#!/usr/bin/env python3
"""Approve explicitly scoped macOS privacy prompts through Accessibility.

This module never changes a TCC database. An already Accessibility-authorized
process can use it on a SIP-enabled Mac. It recognizes Apple system dialogs,
not arbitrary application windows, and never types credentials.
"""

import ctypes
import dataclasses
import hashlib
import json
import math
import os
from pathlib import Path
import plistlib
import re
import subprocess
import time


class WatchError(RuntimeError):
    pass


# Both executable location and Apple code-signing requirement are checked.
HOSTS = {
    '/System/Library/CoreServices/UserNotificationCenter.app/Contents/MacOS/UserNotificationCenter': 'com.apple.UserNotificationCenter',
    '/System/Library/CoreServices/CoreServicesUIAgent.app/Contents/MacOS/CoreServicesUIAgent': 'com.apple.coreservices.uiagent',
    '/System/Library/CoreServices/NotificationCenter.app/Contents/MacOS/NotificationCenter': 'com.apple.notificationcenterui',
}
SERVICE_ALIASES = {
    'Camera': 'camera', 'Microphone': 'microphone', 'AddressBook': 'contacts',
    'ContactsFull': 'contacts', 'ContactsLimited': 'contacts', 'Calendar': 'calendar',
    'Reminders': 'reminders', 'Photos': 'photos', 'PhotosAdd': 'photos-add',
    'BluetoothAlways': 'bluetooth', 'SpeechRecognition': 'speech-recognition',
    'ScreenCapture': 'screen-recording', 'AudioCapture': 'audio-capture',
    'AppleEvents': 'automation', 'SystemPolicyDesktopFolder': 'desktop',
    'SystemPolicyDocumentsFolder': 'documents', 'SystemPolicyDownloadsFolder': 'downloads',
    'SystemPolicyNetworkVolumes': 'network-volumes',
    'SystemPolicyRemovableVolumes': 'removable-volumes',
    'SystemPolicyAppData': 'app-data', 'SystemPolicyAppDataDetailed': 'app-data-detailed',
    'SystemPolicyDeveloperFiles': 'developer-files', 'SystemPolicyAppBundles': 'app-bundles',
    'FileProviderDomain': 'file-provider-domain', 'FileProviderPresence': 'file-provider-presence',
    'MediaLibrary': 'media-library', 'Motion': 'motion', 'Willow': 'homekit',
    'FocusStatus': 'focus-status', 'GameCenterFriends': 'game-center-friends',
    'Location': 'location', 'WebBrowserPublicKeyCredential': 'web-browser-passkeys',
    'Accessibility': 'accessibility', 'ListenEvent': 'input-monitoring',
}
DENY_BUTTONS = {"Don't Allow", 'Deny', 'Cancel', 'Not Now', 'No', 'Stop Allowing'}
BASE_ALLOW = {'Allow', 'OK'}
MAX_PRESS_ATTEMPTS = 3
ALLOW_BUTTONS = {
    'photos': BASE_ALLOW | {'Allow Full Access', 'Allow All Photos'},
    'contacts': BASE_ALLOW | {'Allow Full Access', 'Allow Access'},
    'calendar': BASE_ALLOW | {'Allow Full Access'},
    'screen-recording': BASE_ALLOW | {'Continue to Allow', 'Allow for One Month',
                                     'Allow Screen Recording', 'Allow Recording'},
    'audio-capture': BASE_ALLOW | {'Continue to Allow', 'Allow for One Month'},
    'location': BASE_ALLOW | {'Allow Once', 'Allow While Using the App'},
}


def normalized(value):
    return ' '.join(str(value).translate(str.maketrans({'“': '"', '”': '"',
                                                     '’': "'", '‘': "'"})).split())


@dataclasses.dataclass(frozen=True)
class Identity:
    client: str
    client_type: int
    path: str
    names: tuple

    @property
    def key(self):
        return self.client_type, self.client


@dataclasses.dataclass(frozen=True)
class Host:
    pid: int
    uid: int
    executable: str
    bundle_id: str
    verified: bool = False


@dataclasses.dataclass(frozen=True)
class Button:
    title: str
    enabled: bool = True
    pressable: bool = True
    token: int = dataclasses.field(default=0, repr=False, compare=False)


@dataclasses.dataclass
class Prompt:
    host: Host
    texts: tuple
    buttons: tuple
    has_text_input: bool = False
    truncated: bool = False
    window: int = dataclasses.field(default=0, repr=False)
    refs: tuple = dataclasses.field(default=(), repr=False)

    @property
    def fingerprint(self):
        value = [dataclasses.asdict(self.host), sorted(set(self.texts)),
                 [(b.title, b.enabled, b.pressable) for b in self.buttons],
                 self.has_text_input, self.truncated]
        return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()[:24]


@dataclasses.dataclass(frozen=True)
class Template:
    service: str
    text: str

    def match(self, text):
        # A quoted first placeholder always names the requesting application.
        value = normalized(self.text)
        if '"%@"' not in value:
            return None
        before, after = value.split('"%@"', 1)
        pattern = re.escape(before) + r'"(?P<requester>[^"\r\n]+)"'
        # Remaining placeholders are receivers/domain names in Apple text.
        pattern += re.escape(after).replace(re.escape('%@'), r'[^"\r\n]+')
        return re.fullmatch(pattern, normalized(text))


def load_templates():
    """Read exact English templates from the installed, Apple-owned framework."""
    templates = set()
    source = Path('/System/Library/PrivateFrameworks/TCC.framework/Versions/A/Resources/Localizable.loctable')
    try:
        table = plistlib.loads(source.read_bytes())['en']
        for key, text in table.items():
            if not key.startswith(('REQUEST_ACCESS_SERVICE_', 'REQUEST_ACCESS_UPGRADE_')):
                continue
            service = re.search(r'kTCCService([A-Za-z]+)', key)
            if service and service[1] in SERVICE_ALIASES and isinstance(text, str):
                templates.add(Template(SERVICE_ALIASES[service[1]], text))
    except (OSError, KeyError, ValueError, plistlib.InvalidFileException):
        pass
    fallback = {
        'camera': ['"%@" would like to access the camera.', 'Allow "%@" to access your camera?'],
        'microphone': ['"%@" would like to access the microphone.', 'Allow "%@" to access your microphone?'],
        'contacts': ['"%@" would like to access your contacts.'],
        'calendar': ['"%@" would like to access your calendars.'],
        'reminders': ['"%@" would like to access your reminders.'],
        'photos': ['"%@" would like to access your photos.'],
        'screen-recording': [
            '"%@" would like to capture the contents of the system display.',
            '"%@" would like to record this computer\'s screen and audio.',
            '"%@" can access this computer\'s screen and audio. Do you want to continue to allow access?',
        ],
        'accessibility': ['"%@" would like to control this computer using accessibility features.'],
        'input-monitoring': ['"%@" would like to monitor input from your keyboard even while using other apps.'],
        'local-network': ['"%@" would like to find and connect to devices on your local network.'],
    }
    for service, values in fallback.items():
        templates.update(Template(service, value) for value in values)
    return tuple(sorted(templates, key=lambda t: (t.service, t.text)))


def identity_from_target(target):
    path = Path(target.path)
    names = {path.name, path.stem} if path.suffix == '.app' else {path.name}
    if target.client_type == 0:
        try:
            info = plistlib.loads((path / 'Contents/Info.plist').read_bytes())
            if info.get('CFBundleIdentifier') != target.client:
                raise WatchError(f'Target bundle identity changed: {path}')
            for key in ('CFBundleDisplayName', 'CFBundleName', 'CFBundleExecutable'):
                if isinstance(info.get(key), str):
                    names.add(info[key])
        except (OSError, ValueError, plistlib.InvalidFileException) as e:
            raise WatchError(f'Cannot read target bundle metadata: {path}: {e}') from e
    names = tuple(sorted({normalized(n) for n in names if n and len(n) <= 128}))
    if not names:
        raise WatchError(f'Target has no usable display name: {target.client}')
    return Identity(target.client, target.client_type, str(path.resolve()), names)


def classify_prompt(prompt, identities, templates, services=None, ambiguous_names=()):
    """Pure classifier: no GUI or TCC writes; suitable for fixture tests."""
    base = {'prompt_id': prompt.fingerprint, 'host': prompt.host.bundle_id,
            'pid': prompt.host.pid, 'status': 'ignored', 'reason': 'unknown-permission-dialog'}
    if not prompt.host.verified or HOSTS.get(prompt.host.executable) != prompt.host.bundle_id:
        return {**base, 'reason': 'untrusted-host'}
    if prompt.truncated:
        return {**base, 'reason': 'incomplete-accessibility-tree'}
    if prompt.has_text_input:
        return {**base, 'reason': 'text-or-password-input'}
    matches = []
    # The permission headline precedes the app-controlled usage description.
    # A usage description must never impersonate another permission request.
    headlines = [text for text in prompt.texts if normalized(text).lower() not in
                 {'alert', 'dialog', 'window'}]
    for text in headlines[:1]:
        for template in templates:
            match = template.match(text)
            if match:
                matches.append((template.service, normalized(match['requester'])))
    matches = set(matches)
    if not matches:
        return base
    if len(matches) != 1:
        return {**base, 'reason': 'ambiguous-permission-text'}
    service, name = next(iter(matches))
    base.update(service=service, requester=name)
    matched = [identity for identity in identities if name in identity.names]
    if not matched:
        return {**base, 'reason': 'target-not-selected'}
    if len(matched) != 1 or name in set(ambiguous_names):
        return {**base, 'reason': 'ambiguous-target-name'}
    base.update(client=matched[0].client, client_type=matched[0].client_type)
    if services is not None and service not in services:
        return {**base, 'reason': 'service-not-selected'}
    if not any(normalized(button.title) in DENY_BUTTONS for button in prompt.buttons):
        return {**base, 'reason': 'missing-denial-button'}
    allowed = ALLOW_BUTTONS.get(service, BASE_ALLOW)
    buttons = [button for button in prompt.buttons if normalized(button.title) in allowed]
    if not buttons:
        reason = 'requires-system-settings' if any(normalized(b.title) in
                 {'Open System Settings', 'Open System Preferences'} for b in prompt.buttons) else 'no-known-approval-button'
        return {**base, 'reason': reason}
    # Prefer full authorization over limited/one-time access when offered.
    full = [b for b in buttons if normalized(b.title) in {'Allow Full Access', 'Allow All Photos'}]
    if full:
        buttons = full
    if len(buttons) != 1:
        return {**base, 'reason': 'ambiguous-approval-button'}
    if not buttons[0].enabled or not buttons[0].pressable:
        return {**base, 'reason': 'approval-button-unavailable'}
    return {**base, 'status': 'ready', 'reason': 'recognized-permission',
            'button': buttons[0].title}


class Accessibility:
    """Minimal, owned-reference CoreFoundation/Accessibility bindings."""

    def __init__(self):
        self.cf = ctypes.CDLL('/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation')
        self.ax = ctypes.CDLL('/System/Library/Frameworks/ApplicationServices.framework/ApplicationServices')
        self.proc = ctypes.CDLL('/usr/lib/libproc.dylib')
        p, integer, index = ctypes.c_void_p, ctypes.c_int, ctypes.c_long
        signatures = {
            'CFRelease': (None, p), 'CFRetain': (p, p), 'CFGetTypeID': (index, p),
            'CFStringGetTypeID': (index,), 'CFArrayGetTypeID': (index,),
            'CFBooleanGetTypeID': (index,), 'CFBooleanGetValue': (ctypes.c_bool, p),
            'CFStringCreateWithCString': (p, p, ctypes.c_char_p, integer),
            'CFStringGetCString': (ctypes.c_bool, p, p, index, integer),
            'CFArrayGetCount': (index, p), 'CFArrayGetValueAtIndex': (p, p, index),
            'AXIsProcessTrusted': (ctypes.c_bool,),
            'AXUIElementCreateApplication': (p, integer),
            'AXUIElementCopyAttributeValue': (integer, p, p, ctypes.POINTER(p)),
            'AXUIElementCopyActionNames': (integer, p, ctypes.POINTER(p)),
            'AXUIElementPerformAction': (integer, p, p),
            'AXUIElementSetMessagingTimeout': (integer, p, ctypes.c_float),
        }
        for name, signature in signatures.items():
            f = getattr(self.cf if name.startswith('CF') else self.ax, name)
            f.restype, f.argtypes = signature[0], list(signature[1:])
        self.proc.proc_pidpath.restype = integer
        self.proc.proc_pidpath.argtypes = [integer, p, ctypes.c_uint32]
        self._checked_bundles = set()
        self._read_failed = False

    def trusted(self):
        return bool(self.ax.AXIsProcessTrusted())

    def _string(self, text):
        return self.cf.CFStringCreateWithCString(None, text.encode(), 0x08000100)

    def _value(self, ref, retain_elements=False):
        kind = self.cf.CFGetTypeID(ref)
        if kind == self.cf.CFStringGetTypeID():
            buffer = ctypes.create_string_buffer(16384)
            if self.cf.CFStringGetCString(ref, buffer, len(buffer), 0x08000100):
                return buffer.value.decode('utf8')
            return None
        if kind == self.cf.CFBooleanGetTypeID():
            return bool(self.cf.CFBooleanGetValue(ref))
        if kind == self.cf.CFArrayGetTypeID():
            values = [self.cf.CFArrayGetValueAtIndex(ref, i)
                      for i in range(min(self.cf.CFArrayGetCount(ref), 2048))]
            if retain_elements:
                return [self.cf.CFRetain(value) for value in values]
            return [self._value(value) for value in values]
        return None

    def attribute(self, element, name, retain_elements=False):
        key = self._string(name)
        value = ctypes.c_void_p()
        try:
            error = self.ax.AXUIElementCopyAttributeValue(element, key, ctypes.byref(value))
            if error == -25211:
                raise WatchError('macOS denied Accessibility API access; enable Accessibility for '
                                 'the responsible terminal/agent or Python executable and restart the watcher.')
            if error in (-25202, -25204):
                self._read_failed = True
            if error or not value:
                return None
            return self._value(value, retain_elements)
        finally:
            self.cf.CFRelease(key)
            if value:
                self.cf.CFRelease(value)

    def actions(self, element):
        value = ctypes.c_void_p()
        try:
            if self.ax.AXUIElementCopyActionNames(element, ctypes.byref(value)) or not value:
                return ()
            return self._value(value) or ()
        finally:
            if value:
                self.cf.CFRelease(value)

    def _pidpath(self, pid):
        buffer = ctypes.create_string_buffer(4096)
        if self.proc.proc_pidpath(pid, buffer, len(buffer)) <= 0:
            return None
        return buffer.value.decode('utf8', 'replace')

    def hosts(self, uid):
        result = subprocess.run(['/bin/ps', '-axo', 'pid=,uid=,comm='],
                                text=True, capture_output=True, check=True, timeout=5)
        hosts = []
        for line in result.stdout.splitlines():
            parts = line.strip().split(None, 2)
            if len(parts) != 3 or int(parts[1]) != uid or parts[2] not in HOSTS:
                continue
            pid, executable = int(parts[0]), parts[2]
            if self._pidpath(pid) != executable:
                continue
            bundle_id = HOSTS[executable]
            bundle = str(Path(executable).parents[2])
            if bundle not in self._checked_bundles:
                result = subprocess.run(['/usr/bin/codesign', '--verify', '-R',
                    '=anchor apple and identifier "' + bundle_id + '"', bundle],
                    capture_output=True, text=True, timeout=10)
                if result.returncode:
                    continue
                self._checked_bundles.add(bundle)
            hosts.append(Host(pid, uid, executable, bundle_id, True))
        return hosts

    def snapshot(self, window, host):
        self._read_failed = False
        refs, texts, buttons = [window], [], []
        has_text_input, truncated = False, False
        def walk(element, depth):
            nonlocal has_text_input, truncated
            if depth > 14 or len(refs) > 1024:
                truncated = True
                return
            role = self.attribute(element, 'AXRole')
            if role in ('AXTextField', 'AXTextArea') or self.attribute(element, 'AXSubrole') == 'AXSecureTextField':
                has_text_input = True
            if role in ('AXWindow', 'AXStaticText', 'AXHeading'):
                for key in ('AXTitle', 'AXDescription', 'AXValue'):
                    value = self.attribute(element, key)
                    if isinstance(value, str) and value.strip():
                        texts.append(normalized(value))
            if role == 'AXButton':
                title = self.attribute(element, 'AXTitle') or self.attribute(element, 'AXDescription') or ''
                if isinstance(title, str):
                    buttons.append(Button(title, self.attribute(element, 'AXEnabled') is True,
                                          'AXPress' in self.actions(element), element))
            children = self.attribute(element, 'AXChildren', True) or ()
            for child in children:
                refs.append(child)
                walk(child, depth + 1)
        try:
            walk(window, 0)
            return Prompt(host, tuple(texts), tuple(buttons), has_text_input,
                          truncated or self._read_failed, window, tuple(refs))
        except BaseException:
            for ref in refs:
                self.cf.CFRelease(ref)
            raise

    def scan(self, uid):
        prompts = []
        try:
            for host in self.hosts(uid):
                application = self.ax.AXUIElementCreateApplication(host.pid)
                try:
                    self.ax.AXUIElementSetMessagingTimeout(application, 0.2)
                    windows = self.attribute(application, 'AXWindows', True) or ()
                    for window in windows:
                        prompts.append(self.snapshot(window, host))
                finally:
                    self.cf.CFRelease(application)
            return prompts
        except BaseException:
            for prompt in prompts:
                self.close(prompt)
            raise

    def close(self, prompt):
        for ref in prompt.refs:
            self.cf.CFRelease(ref)
        prompt.refs = ()

    def press(self, prompt, decision, identities, templates, services, ambiguous_names):
        if self._pidpath(prompt.host.pid) != prompt.host.executable:
            raise WatchError('Permission-dialog host changed before approval.')
        fresh = self.snapshot(self.cf.CFRetain(prompt.window), prompt.host)
        try:
            current = classify_prompt(fresh, identities, templates, services, ambiguous_names)
            if fresh.fingerprint != prompt.fingerprint or current != decision:
                raise WatchError('Permission dialog changed before approval; retrying is required.')
            button = next(b for b in fresh.buttons if b.title == decision['button'])
            action = self._string('AXPress')
            try:
                error = self.ax.AXUIElementPerformAction(button.token, action)
            finally:
                self.cf.CFRelease(action)
            if error:
                raise WatchError(f'Accessibility approval failed (AX error {error}).')
        finally:
            self.close(fresh)


def find_ambiguous_names(identities, user):
    """Reject collisions visible among installed app names and running binaries."""
    selected = {identity.key for identity in identities}
    aliases = {name for identity in identities for name in identity.names}
    owners = {name: set() for name in aliases}
    for identity in identities:
        for name in identity.names:
            owners[name].add(identity.key)
    roots = [Path('/Applications'), Path(user.pw_dir) / 'Applications',
             Path('/System/Applications'), Path('/System/Library/CoreServices')]
    for root in roots:
        for folder, dirs, _ in os.walk(root):
            for name in dirs[:]:
                if not name.endswith('.app'):
                    continue
                dirs.remove(name)
                path = Path(folder) / name
                try:
                    info = plistlib.loads((path / 'Contents/Info.plist').read_bytes())
                    key = 0, info['CFBundleIdentifier']
                    app_names = {path.stem, path.name, *(info.get(k, '') for k in
                                ('CFBundleDisplayName', 'CFBundleName', 'CFBundleExecutable'))}
                    for alias in app_names:
                        if isinstance(alias, str) and normalized(alias) in owners:
                            owners[normalized(alias)].add(key)
                except (OSError, KeyError, ValueError, plistlib.InvalidFileException):
                    continue
    result = subprocess.run(['/bin/ps', '-axo', 'uid=,comm='], capture_output=True,
                            text=True, check=True, timeout=5)
    for line in result.stdout.splitlines():
        fields = line.strip().split(None, 1)
        if len(fields) != 2 or fields[0] != str(user.pw_uid):
            continue
        path = Path(fields[1])
        # Include development bundles launched outside the installed-app roots.
        bundle = next((parent for parent in path.parents if parent.suffix == '.app'), None)
        if bundle:
            try:
                info = plistlib.loads((bundle / 'Contents/Info.plist').read_bytes())
                key = 0, info['CFBundleIdentifier']
                app_names = {bundle.stem, bundle.name, *(info.get(k, '') for k in
                            ('CFBundleDisplayName', 'CFBundleName', 'CFBundleExecutable'))}
                for alias in app_names:
                    if isinstance(alias, str) and normalized(alias) in owners:
                        owners[normalized(alias)].add(key)
            except (OSError, KeyError, ValueError, plistlib.InvalidFileException):
                pass
            continue
        name = normalized(path.name)
        if name in owners:
            owners[name].add((1, str(path.resolve())))
    return {name for name, keys in owners.items() if len(keys) > 1 or not keys <= selected}


def run_watcher(targets, user, *, services=None, dry_run=False, once=False,
                interval=0.5, timeout=60.0, emit=None, backend=None,
                templates=None, ambiguous_names=None):
    """Watch selected user's GUI; return aggregate results and emit each decision.

    ``targets`` are tcc_grant.Target-like objects; ``user`` is pwd.struct_passwd.
    ``services`` is None for all recognized services or an iterable of aliases.
    An emit(dict) callback can render live output. No passwords are accepted.
    """
    if not math.isfinite(interval) or not math.isfinite(timeout) or interval < 0.1 or interval > 60 or timeout < 0:
        raise WatchError('Interval must be finite and 0.1–60 seconds; timeout must be finite and nonnegative.')
    if not targets:
        raise WatchError('Select at least one target for GUI permission approval.')
    console_uid = Path('/dev/console').stat().st_uid
    if console_uid != user.pw_uid:
        raise WatchError('The selected user must own the active GUI console session.')
    identities = tuple(identity_from_target(target) for target in targets)
    backend = backend or Accessibility()
    if not backend.trusted():
        raise WatchError('GUI watching requires existing Accessibility access for this '
                         'Python executable or its responsible terminal/agent app. '
                         'Enable it in System Settings > Privacy & Security > Accessibility, then restart the watcher.')
    templates = tuple(templates) if templates is not None else load_templates()
    refresh_names = ambiguous_names is None
    ambiguous_names = set(ambiguous_names) if ambiguous_names is not None else find_ambiguous_names(identities, user)
    services = set(services) if services is not None else None
    decisions, seen, attempts, failed_prompts = [], {}, {}, set()
    started = time.monotonic()
    summary = {'status': 'completed', 'mode': 'dry-run' if dry_run else 'approve',
               'approved': 0, 'would_approve': 0, 'failed': 0, 'decisions': decisions,
               'targets': [dataclasses.asdict(identity) for identity in identities],
               'ambiguous_names': sorted(ambiguous_names)}
    try:
        while True:
            prompts = backend.scan(user.pw_uid)
            visible = set()
            try:
                if refresh_names and prompts:
                    ambiguous_names = find_ambiguous_names(identities, user)
                    summary['ambiguous_names'] = sorted(ambiguous_names)
                for prompt in prompts:
                    fingerprint = prompt.fingerprint
                    visible.add(fingerprint)
                    previous = seen.get(fingerprint)
                    if previous and previous['status'] == 'approved':
                        continue
                    decision = classify_prompt(prompt, identities, templates, services, ambiguous_names)
                    if decision['status'] == 'ready' and refresh_names:
                        # A process may have launched since this scan began.
                        ambiguous_names = find_ambiguous_names(identities, user)
                        summary['ambiguous_names'] = sorted(ambiguous_names)
                        decision = classify_prompt(prompt, identities, templates, services, ambiguous_names)
                    if dry_run and decision['status'] == 'ready':
                        decision['status'] = 'would-approve'
                    if decision == previous:
                        continue
                    if decision['status'] == 'would-approve':
                        summary['would_approve'] += 1
                    if decision['status'] == 'ready':
                        if attempts.get(fingerprint, 0) >= MAX_PRESS_ATTEMPTS:
                            continue
                        attempts[fingerprint] = attempts.get(fingerprint, 0) + 1
                        try:
                            backend.press(prompt, decision, identities, templates, services, ambiguous_names)
                            decision['status'] = 'approved'
                            decision['reason'] = 'accessibility-press-succeeded'
                            summary['approved'] += 1
                            failed_prompts.discard(fingerprint)
                        except WatchError as e:
                            decision.update(status='failed', reason=str(e))
                            failed_prompts.add(fingerprint)
                    seen[fingerprint] = decision
                    summary['failed'] = len(failed_prompts)
                    decisions.append(decision)
                    if emit:
                        emit(decision)
            finally:
                for prompt in prompts:
                    backend.close(prompt)
            seen = {key: decision for key, decision in seen.items() if key in visible}
            attempts = {key: count for key, count in attempts.items() if key in visible}
            if once or (timeout and time.monotonic() - started >= timeout):
                break
            delay = interval if not timeout else min(interval, max(0, timeout - (time.monotonic() - started)))
            time.sleep(delay)
    except KeyboardInterrupt:
        summary['status'] = 'interrupted'
    if summary['failed']:
        summary['status'] = 'partial'
    summary['elapsed_seconds'] = round(time.monotonic() - started, 3)
    return summary
