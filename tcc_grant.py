"""Local TCC grants and scoped GUI permission approval for development Macs."""
from __future__ import annotations

import argparse
import contextlib
import ctypes
import dataclasses
import fcntl
import hashlib
import json
import os
from pathlib import Path
import plistlib
import pwd
import re
import sqlite3
import subprocess
import sys
import time
from urllib.parse import quote
import uuid

SYSTEM_DB = Path('/Library/Application Support/com.apple.TCC/TCC.db')
CONTAINERS = Path('/private/var/containers/Data/ProtectedSystem')
STATE = Path('/var/db/tcc-grant')
FRAMEWORK = '/System/Library/PrivateFrameworks/TCC.framework/TCC'
DAEMON = '/System/Library/PrivateFrameworks/TCC.framework/Support/tccd'
KEYS = ('service', 'client', 'client_type', 'indirect_object_identifier')
REQUIRED = set(KEYS) | {'auth_value', 'auth_reason', 'auth_version', 'csreq'}
VERSION = '0.2.0'


class Error(Exception):
    pass


def run(argv, *, check=True, timeout=30):
    p = subprocess.run([str(x) for x in argv], capture_output=True, text=True,
                       timeout=timeout, env={**os.environ, 'LC_ALL': 'C'})
    if check and p.returncode:
        raise Error(f'{argv[0]} failed ({p.returncode}): {p.stderr.strip() or p.stdout.strip()}')
    return p


@dataclasses.dataclass(frozen=True)
class Service:
    alias: str
    name: str
    database: str = 'user'
    receiver: str | None = None
    version: int = 1
    note: str = 'Database grant supported; effective API access has not been verified.'


# Concrete, macOS-applicable categories. Newly discovered symbols are reported,
# never silently promoted to supported writable services.
_CATALOG = [
    ('accessibility', 'Accessibility', 'system'),
    ('input-monitoring', 'ListenEvent', 'system'),
    ('post-event', 'PostEvent', 'system'),
    ('screen-recording', 'ScreenCapture', 'system'),
    ('audio-capture', 'AudioCapture', 'system'),
    ('full-disk-access', 'SystemPolicyAllFiles', 'system'),
    ('developer-tool', 'DeveloperTool', 'system'),
    ('app-bundles', 'SystemPolicyAppBundles', 'system'),
    ('system-admin-files', 'SystemPolicySysAdminFiles', 'system'),
    ('developer-files', 'SystemPolicyDeveloperFiles', 'system'),
    ('camera', 'Camera', 'user'),
    ('microphone', 'Microphone', 'user'),
    ('contacts', 'AddressBook', 'user'),
    ('calendar', 'Calendar', 'user'),
    ('reminders', 'Reminders', 'user'),
    ('photos', 'Photos', 'user'),
    ('photos-add', 'PhotosAdd', 'user'),
    ('bluetooth', 'BluetoothAlways', 'user'),
    ('speech-recognition', 'SpeechRecognition', 'user'),
    ('media-library', 'MediaLibrary', 'user'),
    ('motion', 'Motion', 'user'),
    ('homekit', 'Willow', 'user'),
    ('focus-status', 'FocusStatus', 'user'),
    ('desktop', 'SystemPolicyDesktopFolder', 'user'),
    ('documents', 'SystemPolicyDocumentsFolder', 'user'),
    ('downloads', 'SystemPolicyDownloadsFolder', 'user'),
    ('network-volumes', 'SystemPolicyNetworkVolumes', 'user'),
    ('removable-volumes', 'SystemPolicyRemovableVolumes', 'user'),
    ('app-data', 'SystemPolicyAppData', 'user'),
    ('file-provider-presence', 'FileProviderPresence', 'user'),
    ('pasteboard', 'Pasteboard', 'user'),
    ('siri', 'Siri', 'user'),
    ('siri-access', 'SiriAccess', 'user'),
    ('game-center-friends', 'GameCenterFriends', 'user'),
    ('user-tracking', 'UserTracking', 'user'),
    ('web-browser-passkeys', 'WebBrowserPublicKeyCredential', 'user'),
]
CATALOG = {a: Service(a, 'kTCCService' + n, db) for a, n, db in _CATALOG}
CATALOG.update({
    'automation': Service('automation', 'kTCCServiceAppleEvents', receiver='app'),
    'app-data-detailed': Service('app-data-detailed', 'kTCCServiceSystemPolicyAppDataDetailed', receiver='app'),
    'file-provider-domain': Service('file-provider-domain', 'kTCCServiceFileProviderDomain', receiver='domain'),
})
ALIASES = {'screen-capture': 'screen-recording', 'fda': 'full-disk-access',
           'apple-events': 'automation', 'calendar-full': 'calendar'}
EXCLUSIONS = {
    'kTCCServiceAll': 'Selector for reset operations, not a permission.',
    'kTCCServiceLocation': 'Location Services has separate locationd authorization; not implemented.',
    'kTCCServiceEndpointSecurityClient': 'Also requires an Endpoint Security entitlement; not implemented.',
    'kTCCServiceContactsFull': 'Composition child of Contacts; grant contacts instead.',
    'kTCCServiceContactsLimited': 'Limited access is not an all-access grant; grant contacts instead.',
    'kTCCServiceRemoteDesktop': 'Remote desktop includes additional authorization; not implemented.',
    'kTCCServiceVirtualMachineNetworking': 'Separate network authorization; not implemented.',
}
# Coverage from the included disposable probes on macOS 27.0.1. This describes
# implementation testing, never authorization of an arbitrary requested target.
LIVE_TESTED = {'accessibility', 'input-monitoring', 'screen-recording', 'camera', 'microphone',
               'contacts', 'calendar', 'reminders', 'photos', 'speech-recognition', 'automation',
               'full-disk-access'}


class Mac:
    def __init__(self):
        if sys.platform != 'darwin':
            raise Error('This command requires macOS.')
        self.cf = ctypes.CDLL('/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation')
        self.sec = ctypes.CDLL('/System/Library/Frameworks/Security.framework/Security')
        self.lib = ctypes.CDLL('/usr/lib/libSystem.B.dylib')
        P = ctypes.c_void_p
        self._bind(self.cf, 'CFStringCreateWithCString', P, [P, ctypes.c_char_p, ctypes.c_uint32])
        self._bind(self.cf, 'CFURLCreateFromFileSystemRepresentation', P, [P, ctypes.c_char_p, ctypes.c_long, ctypes.c_bool])
        self._bind(self.cf, 'CFRelease', None, [P])
        self._bind(self.cf, 'CFDictionaryGetValue', P, [P, P])
        self._bind(self.cf, 'CFStringGetCString', ctypes.c_bool, [P, P, ctypes.c_long, ctypes.c_uint32])
        self._bind(self.cf, 'CFDataGetLength', ctypes.c_long, [P])
        self._bind(self.cf, 'CFDataGetBytePtr', P, [P])
        self._bind(self.sec, 'SecRequirementCreateWithString', ctypes.c_int, [P, ctypes.c_uint32, ctypes.POINTER(P)])
        self._bind(self.sec, 'SecRequirementCreateWithData', ctypes.c_int, [P, ctypes.c_uint32, ctypes.POINTER(P)])
        self._bind(self.cf, 'CFDataCreate', P, [P, P, ctypes.c_long])
        self._bind(self.sec, 'SecRequirementCopyData', ctypes.c_int, [P, ctypes.c_uint32, ctypes.POINTER(P)])
        self._bind(self.sec, 'SecStaticCodeCreateWithPath', ctypes.c_int, [P, ctypes.c_uint32, ctypes.POINTER(P)])
        self._bind(self.sec, 'SecCodeCopyDesignatedRequirement', ctypes.c_int, [P, ctypes.c_uint32, ctypes.POINTER(P)])
        self._bind(self.sec, 'SecCodeCopySigningInformation', ctypes.c_int, [P, ctypes.c_uint32, ctypes.POINTER(P)])
        self._bind(self.sec, 'SecStaticCodeCheckValidity', ctypes.c_int, [P, ctypes.c_uint32, P])
        self._bind(self.lib, 'proc_pidpath', ctypes.c_int, [ctypes.c_int, P, ctypes.c_uint32])
        self._bind(self.lib, 'responsibility_get_pid_responsible_for_pid', ctypes.c_int, [ctypes.c_int])

    @staticmethod
    def _bind(lib, name, result, args):
        f = getattr(lib, name)
        f.restype, f.argtypes = result, args

    def requirement(self, target, strict=False):
        req, data, code = ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p()
        url = self.cf.CFURLCreateFromFileSystemRepresentation(None, os.fsencode(target.path),
                                                             len(os.fsencode(target.path)), False)
        try:
            status = self.sec.SecStaticCodeCreateWithPath(url, 0, ctypes.byref(code))
            if status:
                raise Error(f'Cannot inspect code at {target.path}: OSStatus {status}')
            if strict:
                status = self.sec.SecCodeCopyDesignatedRequirement(code, 0, ctypes.byref(req))
            else:
                info = ctypes.c_void_p()
                status = self.sec.SecCodeCopySigningInformation(code, 0, ctypes.byref(info))
                if status:
                    raise Error(f'Cannot inspect signing identity of {target.path}: OSStatus {status}')
                try:
                    key = ctypes.c_void_p.in_dll(self.sec, 'kSecCodeInfoIdentifier')
                    identifier = self.cf.CFDictionaryGetValue(info, key)
                    if not identifier:
                        raise Error(f'Unsigned code has no usable TCC identity: {target.path}')
                    if target.client_type == 0:
                        buffer = ctypes.create_string_buffer(4096)
                        if not self.cf.CFStringGetCString(identifier, buffer, len(buffer), 0x08000100):
                            raise Error(f'Cannot read signing identifier: {target.path}')
                        if buffer.value.decode() != target.client:
                            raise Error(f'Bundle identifier differs from signing identifier: {target.path}')
                finally:
                    if info.value:
                        self.cf.CFRelease(info)
                text = 'identifier ' + json.dumps(target.client) if target.client_type == 0 else 'true'
                cftext = self.cf.CFStringCreateWithCString(None, text.encode(), 0x08000100)
                try:
                    status = self.sec.SecRequirementCreateWithString(cftext, 0, ctypes.byref(req))
                finally:
                    self.cf.CFRelease(cftext)
            if status:
                raise Error(f'Cannot create code requirement for {target.path}: OSStatus {status}')
            # Default mode checks signing identity, avoiding trust evaluation that
            # can depend on certificate revocation caches. Strict mode validates
            # the designated requirement without hashing all app resources.
            if strict:
                status = self.sec.SecStaticCodeCheckValidity(code, 6, req)
                if status:
                    raise Error(f'Code requirement does not match {target.path}: OSStatus {status}')
            status = self.sec.SecRequirementCopyData(req, 0, ctypes.byref(data))
            if status:
                raise Error(f'Cannot serialize code requirement: OSStatus {status}')
            return ctypes.string_at(self.cf.CFDataGetBytePtr(data), self.cf.CFDataGetLength(data))
        finally:
            for value in (data, req, code):
                if value.value:
                    self.cf.CFRelease(value)
            if url:
                self.cf.CFRelease(url)

    def pidpath(self, pid):
        b = ctypes.create_string_buffer(4096)
        if self.lib.proc_pidpath(pid, b, len(b)) <= 0:
            raise Error(f'PID {pid} has exited or cannot be inspected.')
        return Path(os.fsdecode(b.value))

    def matches(self, target, requirement):
        if not requirement:
            return None
        code, req = ctypes.c_void_p(), ctypes.c_void_p()
        raw = ctypes.create_string_buffer(requirement)
        data = self.cf.CFDataCreate(None, raw, len(requirement))
        path = os.fsencode(target.path)
        url = self.cf.CFURLCreateFromFileSystemRepresentation(None, path, len(path), False)
        try:
            if self.sec.SecRequirementCreateWithData(data, 0, ctypes.byref(req)):
                return False
            if self.sec.SecStaticCodeCreateWithPath(url, 0, ctypes.byref(code)):
                return False
            status = self.sec.SecStaticCodeCheckValidity(code, 6, req)
            if status == 0:
                return True
            # Trust/certificate failures do not prove an identifier/code-hash
            # mismatch. Keep the target's effective authorization unverified.
            return False if status in (-67050, -67062, -67030) else None
        finally:
            for value in (req, code):
                if value.value:
                    self.cf.CFRelease(value)
            self.cf.CFRelease(data)
            self.cf.CFRelease(url)

    def responsible(self, pid):
        result = self.lib.responsibility_get_pid_responsible_for_pid(pid)
        if result <= 0:
            raise Error(f'Cannot determine the responsible process for PID {pid}.')
        return result


@dataclasses.dataclass(frozen=True)
class Target:
    client: str
    client_type: int
    path: str
    source: str = 'explicit'


def target_from_path(path, source='explicit', executable=False):
    p = Path(path).expanduser().resolve(strict=True)
    if not executable:
        for candidate in (p, *p.parents):
            info = candidate / 'Contents/Info.plist'
            if candidate.suffix == '.app' and info.is_file():
                with info.open('rb') as f:
                    bundle_id = plistlib.load(f).get('CFBundleIdentifier')
                if not bundle_id:
                    raise Error(f'No CFBundleIdentifier in {info}')
                return Target(bundle_id, 0, str(candidate), source)
    if not p.is_file() or not os.access(p, os.X_OK):
        raise Error(f'Not an executable file or app bundle: {p}')
    return Target(str(p), 1, str(p), source)


def installed_apps(home, roots=None):
    if roots is None:
        roots = [Path('/Applications'), Path(home) / 'Applications',
                 Path('/System/Applications'), Path('/System/Library/CoreServices')]
    apps = {}
    warnings = []
    for root in roots:
        if not root.is_dir():
            continue
        def onerror(e):
            warnings.append(str(e))
        for folder, dirs, _ in os.walk(root, onerror=onerror):
            # Enumerate top-level launchable apps, not nested private helper bundles.
            for name in sorted(dirs[:]):
                if not name.endswith('.app'):
                    continue
                dirs.remove(name)
                if not (Path(folder) / name / 'Contents/Info.plist').is_file():
                    continue
                try:
                    t = target_from_path(Path(folder) / name, 'installed receiver')
                    apps.setdefault(t.client, t)
                except (Error, OSError, plistlib.InvalidFileException) as e:
                    warnings.append(str(e))
    return apps, warnings


def find_bundle(bundle_id, home):
    apps, _ = installed_apps(home)
    if bundle_id in apps:
        return apps[bundle_id]
    # Spotlight is a fallback for development bundles outside /Applications.
    if not re.fullmatch(r'[A-Za-z0-9_.-]+', bundle_id):
        raise Error('Invalid bundle identifier.')
    p = run(['/usr/bin/mdfind', f'kMDItemCFBundleIdentifier == "{bundle_id}"'], check=False)
    matches = []
    for line in p.stdout.splitlines():
        try:
            t = target_from_path(line)
            if t.client == bundle_id:
                matches.append(t)
        except (Error, OSError):
            pass
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        raise Error(f'Multiple apps match {bundle_id}; specify --app: ' + ', '.join(t.path for t in matches))
    raise Error(f'Cannot locate installed bundle {bundle_id}; specify its app path.')


def choose_user(name=None):
    if not name:
        sudo_user = os.environ.get('SUDO_USER')
        if sudo_user and sudo_user != 'root':
            name = sudo_user
        elif os.getuid() != 0:
            name = pwd.getpwuid(os.getuid()).pw_name
        else:
            uid = Path('/dev/console').stat().st_uid
            if uid:
                name = pwd.getpwuid(uid).pw_name
    if not name:
        raise Error('Cannot identify a user; specify --user USER.')
    try:
        user = pwd.getpwnam(name)
    except KeyError:
        raise Error(f'Unknown user: {name}') from None
    if user.pw_uid == 0:
        raise Error('Select a non-root user with --user.')
    return user


def discover_databases(user):
    candidates = set()
    ps = run(['/bin/ps', '-axo', 'uid=,pid=,comm=']).stdout
    for line in ps.splitlines():
        fields = line.strip().split(None, 2)
        if len(fields) == 3 and fields[0] == str(user.pw_uid) and fields[2] == DAEMON:
            files = run(['/usr/sbin/lsof', '-n', '-a', '-p', fields[1], '-Fn'], check=False).stdout
            for entry in files.splitlines():
                if entry.startswith('n/') and entry.endswith('/com.apple.TCC/TCC.db'):
                    candidates.add(Path(entry[1:]).resolve())
    source = 'tccd open files'
    if not candidates:
        source = 'protected container metadata'
        if CONTAINERS.is_dir():
            for container in CONTAINERS.iterdir():
                metadata = container / '.com.apple.containermanagerd.metadata.plist'
                try:
                    with metadata.open('rb') as f:
                        value = plistlib.load(f)
                    if value.get('MCMMetadataIdentifier') != 'com.apple.tccd':
                        continue
                    if value.get('MCMMetadataOwnership', {}).get('uid') != user.pw_uid:
                        continue
                    path = container / 'Data/Library/Application Support/com.apple.TCC/TCC.db'
                    if path.is_file():
                        candidates.add(path.resolve())
                except (OSError, plistlib.InvalidFileException):
                    continue
    if not candidates:
        source = 'traditional user path'
        p = Path(user.pw_dir) / 'Library/Application Support/com.apple.TCC/TCC.db'
        if p.is_file():
            candidates.add(p.resolve())
    if len(candidates) != 1:
        raise Error(f'Expected one active TCC database for {user.pw_name}; found {len(candidates)}. '
                    'Run doctor with sudo; no database was created.')
    user_db = candidates.pop()
    if user_db.stat().st_uid != user.pw_uid:
        raise Error(f'User database ownership mismatch: {user_db}')
    if not SYSTEM_DB.is_file() or SYSTEM_DB.stat().st_uid != 0:
        raise Error(f'System database missing or not root-owned: {SYSTEM_DB}')
    return {'system': SYSTEM_DB.resolve(), 'user': user_db}, source


def connect(path, readonly=False):
    c = sqlite3.connect('file:' + quote(str(path), safe='/') + ('?mode=ro' if readonly else '?mode=rw'),
                        uri=True, timeout=10, isolation_level=None)
    c.row_factory = sqlite3.Row
    c.execute('PRAGMA busy_timeout=10000')
    c.execute('PRAGMA foreign_keys=ON')
    return c


def schema(c):
    columns = {r['name']: dict(r) for r in c.execute('PRAGMA table_info(access)')}
    if not REQUIRED <= columns.keys():
        raise Error('Unsupported TCC schema: missing ' + ', '.join(sorted(REQUIRED - columns.keys())))
    primary = tuple(r['name'] for r in sorted(columns.values(), key=lambda r: r['pk']) if r['pk'])
    if primary != KEYS:
        raise Error(f'Unsupported access primary key: {primary}')
    for name, col in columns.items():
        if name not in REQUIRED and col['notnull'] and col['dflt_value'] is None and name != 'last_modified':
            raise Error(f'Unsupported required column: {name}')
    return columns


def read_row(c, key, table='access'):
    if table not in ('access', 'managed_overrides', 'expired'):
        raise Error('Invalid table.')
    key_columns = KEYS if table != 'expired' else KEYS[:3]
    if not c.execute('SELECT 1 FROM sqlite_master WHERE name=? AND type=?', (table, 'table')).fetchone():
        return None
    row = c.execute(f'SELECT * FROM {table} WHERE ' + ' AND '.join(f'"{k}"=?' for k in key_columns),
                    tuple(key[k] for k in key_columns)).fetchone()
    return dict(row) if row else None


def encode(value):
    if isinstance(value, bytes):
        return {'$bytes': value.hex()}
    if isinstance(value, dict):
        return {k: encode(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [encode(v) for v in value]
    return value


def decode(value):
    if isinstance(value, dict):
        if set(value) == {'$bytes'}:
            return bytes.fromhex(value['$bytes'])
        return {k: decode(v) for k, v in value.items()}
    if isinstance(value, list):
        return [decode(v) for v in value]
    return value


def atomic_json(path, value):
    temporary = path.with_suffix('.tmp')
    with temporary.open('w') as f:
        json.dump(encode(value), f, indent=2, sort_keys=True)
        f.write('\n')
        f.flush()
        os.fsync(f.fileno())
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)
    fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


@contextlib.contextmanager
def state_lock(state=STATE):
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    s = state.lstat()
    if not state.is_dir() or state.is_symlink() or s.st_uid != os.geteuid() or s.st_mode & 0o077:
        raise Error(f'State directory must be private and owned by the current user: {state}')
    fd = os.open(state / 'lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        deadline = time.monotonic() + 30
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise Error('Another tcc-grant operation holds the lock.')
                time.sleep(0.1)
        yield
    finally:
        os.close(fd)


def write_row(c, row):
    # Column names come exclusively from a validated schema/record, never a CLI argument.
    available = schema(c)
    if not set(row) <= available.keys():
        raise Error('Journal contains columns absent from the current schema.')
    columns = list(row)
    names = ','.join('"' + n + '"' for n in columns)
    updates = ','.join(f'"{n}"=excluded."{n}"' for n in columns if n not in KEYS)
    c.execute(f'INSERT INTO access ({names}) VALUES ({",".join("?" for _ in columns)}) '
              f'ON CONFLICT ({",".join(KEYS)}) DO UPDATE SET {updates}', tuple(row[n] for n in columns))


def restore_row(c, key, before):
    if before is None:
        c.execute('DELETE FROM access WHERE ' + ' AND '.join(f'{k}=?' for k in KEYS),
                  tuple(key[k] for k in KEYS))
    else:
        write_row(c, before)


def grant_row(c, spec):
    columns = schema(c)
    key = {k: spec[k] for k in KEYS}
    before = read_row(c, key)
    if before and before.get('policy_id') is not None:
        raise Error(f'Managed policy owns grant for {key}; management policies were not changed.')
    managed = read_row(c, key, 'managed_overrides')
    if managed:
        raise Error(f'Managed override exists for {key}; management policies were not changed.')
    fields = {**key, 'auth_value': 2, 'auth_reason': 4, 'auth_version': spec['auth_version'],
              'csreq': spec['csreq'], 'policy_id': None,
              'indirect_object_identifier_type': spec.get('indirect_object_identifier_type'),
              'indirect_object_code_identity': spec.get('indirect_object_code_identity'),
              'flags': 0, 'pid': None, 'pid_version': None, 'boot_uuid': 'UNUSED',
              'one_time_reprompt_eligible': 0, 'reminder_count': 0}
    fields = {k: v for k, v in fields.items() if k in columns}
    # User-consent and this tool's grant are both acceptable reasons. Do not rewrite
    # equivalent grants merely to update a timestamp or overwrite their provenance.
    equivalent = {k: v for k, v in fields.items() if k not in ('auth_reason', 'reminder_count', 'one_time_reprompt_eligible')}
    if before and all(before.get(k) == v for k, v in equivalent.items()):
        return None
    now = int(time.time())
    for name in ('last_modified', 'last_reminded'):
        if name in columns:
            fields[name] = now
    row = {**(before or {}), **fields}
    write_row(c, row)
    return {'key': key, 'before': before, 'after': read_row(c, key)}


def transact(databases, specs, state=STATE, fault=None):
    """Back up, journal before-images, commit; compensate any partial commit."""
    with state_lock(state):
        # Unfinished operations require explicit recovery, not a silent overwrite.
        for manifest in state.glob('*/change.json'):
            record = json.loads(manifest.read_text())
            if record.get('status') in ('prepared', 'rollback_failed', 'undo_prepared', 'api_pending'):
                raise Error(f'Unfinished operation {manifest.parent.name}; run undo for that ID first.')
        change_id = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime()) + '-' + uuid.uuid4().hex[:8]
        folder = state / change_id
        folder.mkdir(mode=0o700)
        connections = {}
        commit_attempts = []
        record = {'id': change_id, 'status': 'preparing', 'created': int(time.time()),
                  'databases': {k: str(v) for k, v in databases.items()}, 'changes': []}
        manifest = folder / 'change.json'
        try:
            for name, path in sorted(databases.items()):
                c = connect(path)
                connections[name] = c
                schema(c)
                backup = folder / (name + '.sqlite3')
                with sqlite3.connect(backup) as dest:
                    c.backup(dest)
                os.chmod(backup, 0o600)
                with backup.open('rb') as f:
                    os.fsync(f.fileno())
            # Both databases are locked before any row is modified.
            for c in connections.values():
                c.execute('BEGIN IMMEDIATE')
            for name, rows in specs.items():
                for spec in rows:
                    change = grant_row(connections[name], spec)
                    if change:
                        record['changes'].append({'database': name, **change})
            record['status'] = 'prepared'
            atomic_json(manifest, record)
            for name, c in connections.items():
                # Record the attempt before SQLite can commit and deliver a
                # pending interrupt. Recovery checks the actual before/after image.
                commit_attempts.append(name)
                c.commit()
                if fault:
                    fault(name)
            record['status'] = 'applied'
            atomic_json(manifest, record)
            return record
        except BaseException as e:
            for c in connections.values():
                if c.in_transaction:
                    c.rollback()
            failures = []
            for name in commit_attempts:
                c = connections[name]
                try:
                    c.execute('BEGIN IMMEDIATE')
                    for change in reversed(record['changes']):
                        if change['database'] == name:
                            current = read_row(c, change['key'])
                            if current == change['before']:
                                continue
                            if current != change['after']:
                                raise Error('A concurrent writer changed an applied row.')
                            restore_row(c, change['key'], change['before'])
                    c.commit()
                except Exception as rollback_error:
                    c.rollback()
                    failures.append(str(rollback_error))
            record.update(status='rollback_failed' if failures else 'rolled_back', error=str(e),
                          rollback_errors=failures)
            atomic_json(manifest, record)
            raise Error(f'Grant failed; {record["status"]}. Change ID: {change_id}. {e}') from e
        finally:
            for c in connections.values():
                c.close()


def undo(change_id, state=STATE):
    if not re.fullmatch(r'\d{8}T\d{6}Z-[0-9a-f]{8}', change_id):
        raise Error('Invalid change ID.')
    with state_lock(state):
        manifest = state / change_id / 'change.json'
        if not manifest.is_file():
            raise Error(f'Unknown change ID: {change_id}')
        record = decode(json.loads(manifest.read_text()))
        if record['status'] in ('undone', 'rolled_back'):
            return record
        connections = {}
        committed = []
        pending = []
        try:
            for name, path in sorted(record['databases'].items()):
                connections[name] = connect(Path(path))
                schema(connections[name])
            for c in connections.values():
                c.execute('BEGIN IMMEDIATE')
            # Older versions could leave an unconfirmed write in their journal.
            if record.get('pending'):
                pending_write = record['pending']
                if read_row(connections[pending_write['database']], pending_write['key']) != pending_write['before']:
                    raise Error('Unconfirmed daemon write in pending journal; review backup and current row before recovery.')
                record['pending'] = None
            for change in record['changes']:
                current = read_row(connections[change['database']], change['key'])
                if current == change['before']:
                    continue
                if current != change['after']:
                    raise Error(f'Undo conflict for {change["key"]}; no rows were restored.')
                pending.append(change)
            record['status'] = 'undo_prepared'
            atomic_json(manifest, record)
            for change in reversed(pending):
                restore_row(connections[change['database']], change['key'], change['before'])
            for name, c in connections.items():
                c.commit()
                committed.append(name)
            record['status'] = 'undone'
            atomic_json(manifest, record)
            return record
        except BaseException:
            for c in connections.values():
                if c.in_transaction:
                    c.rollback()
            # Partial undos can be resumed: before/after images distinguish each row.
            if committed:
                record['status'] = 'undo_prepared'
                atomic_json(manifest, record)
            raise
        finally:
            for c in connections.values():
                c.close()


def discover_services():
    names = set()
    # dyld_info reads the shared cache even when the dylib has no standalone file.
    p = run(['/usr/bin/xcrun', 'dyld_info', '-exports', FRAMEWORK], check=False)
    names.update(re.findall(r'\b_kTCCService[A-Za-z0-9_]+', p.stdout))
    names = {n[1:] for n in names}
    p = run(['/usr/bin/strings', DAEMON], check=False)
    names.update(re.findall(r'^kTCCService[A-Za-z0-9_]+$', p.stdout, re.M))
    if not names:
        raise Error('Could not discover local TCC services; Xcode command line tools are required.')
    return names


def service_listing():
    names = discover_services()
    known = {s.name: s for s in CATALOG.values()}
    rows = []
    for name in sorted(names):
        s = known.get(name)
        row = {'name': name, 'alias': s.alias if s else None,
               'support': 'database-grant' if s else 'unsupported',
               'verification': 'unverified',
               'note': s.note if s else EXCLUSIONS.get(name, 'No implemented grant semantics for this category.')}
        if s:
            row.update(database=s.database, receiver=s.receiver, auth_version=s.version)
            row['implementation_verification'] = 'api-tested-on-macos-27.0.1' if s.alias in LIVE_TESTED else 'unverified'
        rows.append(row)
    rows.extend([
        {'name': 'local-network', 'alias': None, 'support': 'unsupported', 'verification': 'unverified',
         'note': 'Separate network privacy subsystem, not a TCC access-table service.'}
    ])
    return rows


def selected_services(args):
    available = discover_services()
    if args.all:
        return [s for s in CATALOG.values() if s.name in available]
    result = []
    names = {s.name: s for s in CATALOG.values()}
    names.update({s.name.removeprefix('kTCCService'): s for s in CATALOG.values()})
    for raw in args.service.split(','):
        raw = raw.strip()
        s = CATALOG.get(ALIASES.get(raw, raw)) or names.get(raw)
        if not s:
            raise Error(f'Unsupported service: {raw}. Run services for supported names and limitations.')
        if s.name not in available:
            raise Error(f'{s.name} is absent from this macOS build.')
        if s not in result:
            result.append(s)
    return result


def resolve_targets(args, user, mac):
    warnings = []
    process = None
    if args.app:
        targets = [target_from_path(args.app)]
    elif args.executable:
        targets = [target_from_path(args.executable, executable=True)]
    elif args.bundle_id:
        targets = [find_bundle(args.bundle_id, user.pw_dir)]
    else:
        pid = args.pid
        if pid <= 0:
            raise Error('PID must be positive.')
        path = mac.pidpath(pid)
        owner = run(['/bin/ps', '-p', str(pid), '-o', 'uid=']).stdout.strip()
        if owner != str(user.pw_uid):
            raise Error(f'PID {pid} does not belong to selected user {user.pw_name}.')
        responsible_pid = mac.responsible(pid)
        responsible_path = mac.pidpath(responsible_pid)
        process = {'pid': pid, 'path': str(path), 'responsible_pid': responsible_pid,
                   'responsible_path': str(responsible_path)}
        targets = [target_from_path(path, 'requested PID')]
        targets.append(target_from_path(responsible_path, 'responsibility API'))
        # Newer sshd divides the launcher/session. TCC logs explicitly identify the
        # canonical responsible_path as sshd-keygen-wrapper on this configuration.
        logs = run(['/usr/bin/log', 'show', '--last', '5m', '--style', 'compact',
                    '--predicate', 'subsystem == "com.apple.TCC" AND eventMessage CONTAINS "AUTHREQ_ATTRIBUTION"'],
                   check=False, timeout=20).stdout
        for line in logs.splitlines():
            blocks = re.findall(r'responsible=\{TCCDProcess: ([^}]+)\}', line)
            for block in blocks:
                matches = re.search(r'\bpid=(\d+)', block)
                rpath = re.search(r'responsible_path=([^,}]+)', block)
                if matches and rpath and int(matches[1]) in (pid, responsible_pid):
                    targets.append(target_from_path(rpath[1], 'TCC attribution log'))
        if responsible_path.name in ('sshd-session', 'sshd', 'sshd-keygen-wrapper'):
            wrapper = Path('/usr/libexec/sshd-keygen-wrapper')
            if wrapper.is_file():
                targets.append(target_from_path(wrapper, 'macOS SSH TCC attribution compatibility'))
                warnings.append('SSH requests may be attributed to sshd-keygen-wrapper; its identity is included.')
        if mac.pidpath(pid) != path or mac.responsible(pid) != responsible_pid:
            raise Error('Process identity changed while resolving the target; retry.')
    unique = {(t.client, t.client_type): t for t in targets}
    return list(unique.values()), warnings, process


def receiver_targets(args, user):
    targets = []
    warnings = []
    for value in args.receiver or []:
        targets.append(target_from_path(value, 'explicit receiver') if '/' in value
                       else find_bundle(value, user.pw_dir))
    if args.all and not args.receiver:
        apps, warnings = installed_apps(user.pw_dir)
        targets = list(apps.values())
    return list({(t.client, t.client_type): t for t in targets}.values()), warnings


def make_specs(targets, services, receivers, domains, mac, strict=False, existing_domains=()):
    specs = {'system': [], 'user': []}
    warnings = []
    requirements = {(t.client, t.client_type): mac.requirement(t, strict) for t in targets}
    receiver_requirements = {}
    for t in receivers:
        try:
            receiver_requirements[(t.client, t.client_type)] = mac.requirement(t, strict)
        except Error as e:
            warnings.append(f'Receiver skipped: {t.path}: {e}')
    domains = sorted(set(domains) | set(existing_domains))
    missing = []
    for s in services:
        objects = [(None, 'UNUSED', None)]
        if s.receiver == 'app':
            objects = [(t.client_type, t.client, receiver_requirements[(t.client, t.client_type)])
                       for t in receivers if (t.client, t.client_type) in receiver_requirements]
        elif s.receiver == 'domain':
            objects = [(3, d, None) for d in domains]
        if not objects:
            missing.append({'service': s.alias, 'status': 'missing-receiver',
                            'detail': 'Supply --receiver or --domain.'})
        for t in targets:
            for typ, identifier, req in objects:
                specs[s.database].append({'service': s.name, 'client': t.client,
                    'client_type': t.client_type, 'auth_version': s.version,
                    'csreq': requirements[(t.client, t.client_type)],
                    'indirect_object_identifier': identifier,
                    'indirect_object_identifier_type': typ,
                    'indirect_object_code_identity': req})
    return specs, warnings, missing


def refresh(uid, databases):
    results = []
    for name in databases:
        service = 'system/com.apple.tccd.system' if name == 'system' else f'gui/{uid}/com.apple.tccd'
        try:
            exists = run(['/bin/launchctl', 'print', service], check=False)
            if exists.returncode:
                results.append({'service': service, 'status': 'failed', 'detail': 'Launchd service not available.'})
                continue
            p = run(['/bin/launchctl', 'kickstart', '-k', service], check=False)
            results.append({'service': service, 'status': 'refreshed' if p.returncode == 0 else 'failed',
                            'detail': p.stderr.strip()})
        except (Error, OSError, subprocess.TimeoutExpired) as e:
            # Grants and undos are already saved. Preserve their results and
            # attempt the remaining services even if launchctl cannot run.
            results.append({'service': service, 'status': 'failed', 'detail': str(e)})
    return results


def require_root():
    if os.geteuid() != 0:
        raise Error('This operation requires sudo; rerun the command with sudo.')


def check_environment():
    version = run(['/usr/bin/sw_vers', '-productVersion']).stdout.strip()
    sip = run(['/usr/bin/csrutil', 'status']).stdout.strip()
    if not re.search(r'status:\s*disabled', sip, re.I):
        raise Error('SIP must be disabled for direct grants. This tool does not change SIP.')
    if version.split('.')[0] != '27':
        raise Error(f'macOS {version} has not been validated; this release supports macOS 27 only.')
    return version, sip


def inspect_status(databases, targets, mac):
    result = []
    for name, path in databases.items():
        with contextlib.closing(connect(path, True)) as c:
            schema(c)
            for t in targets:
                rows = c.execute('SELECT * FROM access WHERE client=? AND client_type=?',
                                 (t.client, t.client_type)).fetchall()
                for row in rows:
                    r = dict(row)
                    matches = mac.matches(t, r['csreq'])
                    managed = read_row(c, r, 'managed_overrides')
                    allowed = r['auth_value'] == 2 and matches is not False
                    result.append({'database': name, 'client': t.client, 'client_type': t.client_type,
                                   'service': r['service'], 'receiver': r['indirect_object_identifier'],
                                   'auth_value': r['auth_value'], 'auth_reason': r['auth_reason'],
                                   'auth_version': r['auth_version'],
                                   'status': 'signature-mismatch' if matches is False else
                                             ('database-allowed' if allowed else 'database-denied-or-limited'),
                                   'verification': 'unverified', 'flags': r.get('flags'),
                                   'code_requirement_matches': matches,
                                   'managed_override': bool(managed), 'policy_id': r.get('policy_id'),
                                   'last_modified': r.get('last_modified'),
                                   'requirement_sha256': hashlib.sha256(r['csreq']).hexdigest() if r['csreq'] else None})
    return result


def existing_domains(databases):
    with contextlib.closing(connect(databases['user'], True)) as c:
        return [r[0] for r in c.execute('SELECT DISTINCT indirect_object_identifier FROM access '
                                       'WHERE service=? AND indirect_object_identifier_type=3',
                                       ('kTCCServiceFileProviderDomain',))]


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--version', action='version', version=VERSION)
    commands = p.add_subparsers(dest='command', required=True)
    def common(name, target=False):
        q = commands.add_parser(name)
        q.add_argument('--json', action='store_true', help='Machine-readable output; diagnostic messages go to stderr.')
        q.add_argument('--user', help='Selected macOS user; defaults to SUDO_USER or console/current user.')
        if target:
            selector = q.add_mutually_exclusive_group(required=True)
            selector.add_argument('--app', help='App bundle path.')
            selector.add_argument('--executable', help='Standalone executable path.')
            selector.add_argument('--bundle-id', help='Installed app bundle identifier.')
            selector.add_argument('--pid', type=int, help='Running process and its responsible launcher.')
        return q
    grant = common('grant', True)
    selection = grant.add_mutually_exclusive_group(required=True)
    selection.add_argument('--all', action='store_true', help='All implemented categories; installed apps are automation receivers.')
    selection.add_argument('--service', help='Comma-separated aliases or kTCCService names.')
    grant.add_argument('--receiver', action='append', help='Receiver bundle ID or app path; repeat for multiple receivers.')
    grant.add_argument('--domain', action='append', default=[], help='File Provider domain identifier; repeat as needed.')
    grant.add_argument('--strict-signature', action='store_true', help='Bind grants to designated code requirements.')
    grant.add_argument('--dry-run', action='store_true', help='Resolve identities and planned writes without changes.')
    common('status', True)
    common('services')
    common('doctor')
    q = common('undo')
    q.add_argument('change_id')
    q = common('changes')
    watch = common('watch',True)
    watch_selection = watch.add_mutually_exclusive_group()
    watch_selection.add_argument('--service',help='Comma-separated permission aliases; defaults to every recognized prompt.')
    watch_selection.add_argument('--all',action='store_true',help='Every recognized permission prompt for the selected target (default).')
    watch.add_argument('--dry-run',action='store_true',help='Report recognized approval buttons without clicking.')
    watch.add_argument('--once',action='store_true',help='Inspect the currently visible dialogs once.')
    watch.add_argument('--interval',type=float,default=0.5,help='Polling interval in seconds (default 0.5).')
    watch.add_argument('--timeout',type=float,default=60,help='Stop after this many seconds; 0 watches until interrupted.')
    return p


def emit(result, as_json):
    if as_json:
        print(json.dumps(encode(result), indent=2, sort_keys=True))
        return
    if isinstance(result, list):
        for r in result:
            if 'support' in r:
                print(f'{(r.get("alias") or "-"):27} {r["support"]:15} {r["name"]}')
            elif 'status' in r:
                print(f'{r.get("id", r.get("client", ""))} {r["status"]} {r.get("service", "")} {r.get("receiver", "")}')
        return
    for t in result.get('targets', []):
        source = '; ' + t['source'] if t.get('source') else ''
        print(f'Target: {t["client"]} (type {t["client_type"]}{source})')
    if result.get('change_id'):
        print(f'Change ID: {result["change_id"]}')
    print(result.get('summary', json.dumps(encode(result), indent=2)))
    for r in result.get('services', []):
        print(f'  {r["service"]}: {r["status"]} ({r.get("rows", 0)} rows)')
    for r in result.get('refresh', []):
        print(f'  {r["service"]}: {r["status"]} {r["detail"]}')
    for w in result.get('warnings', []):
        print('Note: ' + w)


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        mac = Mac()
        if args.command == 'services':
            emit(service_listing(), args.json)
            return 0
        if args.command == 'changes':
            require_root()
            results = []
            if STATE.exists():
                for path in sorted(STATE.glob('*/change.json')):
                    r = json.loads(path.read_text())
                    results.append({'id': r['id'], 'status': r['status'], 'created': r['created'],
                                    'rows': len(r['changes'])})
            emit(results, args.json)
            return 0
        user = choose_user(args.user)
        if args.command == 'watch':
            import gui_permissions as watcher
            targets,warnings,process = resolve_targets(args,user,mac)
            services = None
            if args.service is not None:
                known = set(watcher.SERVICE_ALIASES.values()) | {'local-network','location'}
                services = set()
                for raw in args.service.split(','):
                    raw = raw.strip()
                    service = CATALOG.get(ALIASES.get(raw,raw))
                    alias = service.alias if service else watcher.SERVICE_ALIASES.get(raw.removeprefix('kTCCService'),raw)
                    if alias not in known: raise Error(f'Unsupported GUI prompt service: {raw}')
                    services.add(alias)
            def event(decision):
                if args.json: return
                print(f'{decision["status"]}: {decision.get("requester",decision["host"])} '
                      f'{decision.get("service","")} ({decision["reason"]})',flush=True)
            result = watcher.run_watcher(targets,user,services=services,dry_run=args.dry_run,
                                         once=args.once,interval=args.interval,timeout=args.timeout,emit=event)
            result.update(warnings=warnings,process=process,
                          summary=f'GUI watcher: {result["approved"]} approved; {result["would_approve"]} would approve; '
                                  f'{result["failed"]} failed. AX press success does not verify target API access.')
            emit(result,args.json)
            return int(result['status'] == 'partial')
        if args.command == 'undo':
            require_root()
            if not re.fullmatch(r'\d{8}T\d{6}Z-[0-9a-f]{8}',args.change_id): raise Error('Invalid change ID.')
            manifest = STATE / args.change_id / 'change.json'
            if not manifest.is_file(): raise Error(f'Unknown change ID: {args.change_id}')
            check_environment()
            record = undo(args.change_id)
            # Use the owner of the recorded user database, not the caller's user.
            uid = Path(record['databases']['user']).stat().st_uid if 'user' in record['databases'] else user.pw_uid
            refreshed = refresh(uid, record['databases'])
            result = {'summary': f'Change {record["id"]}: {record["status"]}', 'refresh': refreshed}
            emit(result, args.json)
            return int(any(r['status'] == 'failed' for r in refreshed))
        databases, source = discover_databases(user)
        if args.command == 'doctor':
            version = run(['/usr/bin/sw_vers', '-productVersion']).stdout.strip()
            sip = run(['/usr/bin/csrutil', 'status']).stdout.strip()
            checks = {}
            for name, path in databases.items():
                with contextlib.closing(connect(path, True)) as c:
                    columns = schema(c)
                    checks[name] = {'path': str(path), 'columns': list(columns),
                                    'journal_mode': c.execute('PRAGMA journal_mode').fetchone()[0],
                                    'integrity': c.execute('PRAGMA quick_check').fetchone()[0]}
            result = {'macos': version, 'sip': sip, 'user': user.pw_name, 'uid': user.pw_uid,
                      'user_database_source': source, 'databases': checks,
                      'state_directory': str(STATE), 'supported_os': version.split('.')[0] == '27',
                      'summary': f'macOS {version}; {sip}; user {user.pw_name}; database source: {source}'}
            if not args.json:
                for name, details in checks.items():
                    print(f'{name}: {details["path"]} (integrity: {details["integrity"]})')
            emit(result, args.json)
            return int(any(v['integrity'] != 'ok' for v in checks.values()))
        targets, warnings, process = resolve_targets(args, user, mac)
        if args.command == 'status':
            result = {'targets': [dataclasses.asdict(t) for t in targets], 'process': process,
                      'grants': inspect_status(databases, targets, mac), 'warnings': warnings,
                      'summary': 'Saved database grants; effective API authorization is unverified.'}
            emit(result, args.json)
            if not args.json:
                emit(result['grants'], False)
            return 0
        version, _ = check_environment()
        if not args.dry_run:
            require_root()
        services = selected_services(args)
        receivers, receiver_warnings = receiver_targets(args, user)
        specs, spec_warnings, missing = make_specs(targets, services, receivers, args.domain,
                                                  mac, args.strict_signature,
                                                  existing_domains(databases) if args.all else ())
        warnings += receiver_warnings + spec_warnings
        if missing and not args.all:
            raise Error('Missing receiver information: ' + ', '.join(r['service'] for r in missing))
        result = {'targets': [dataclasses.asdict(t) for t in targets], 'process': process,
                  'user': user.pw_name, 'macos': version, 'databases': {k: str(v) for k, v in databases.items()},
                  'services': [], 'warnings': warnings, 'missing': missing,
                  'identity_mode': 'strict-signature' if args.strict_signature else 'rebuild-persistent'}
        for s in services:
            count = sum(r['service'] == s.name for r in specs[s.database])
            result['services'].append({'service': s.alias, 'rows': count,
                                       'status': ('planned' if args.dry_run else 'database-allowed') if count else 'missing-receiver',
                                       'verification': 'unverified'})
        if args.all:
            result['unsupported'] = [r for r in service_listing() if r['support'] == 'unsupported']
            warnings.append(f'{len(result["unsupported"])} discovered categories have no supported grant semantics; '
                            'see services --json for details. --all covers implemented categories.')
        if args.dry_run:
            result.update(summary=f'Dry run: {sum(map(len, specs.values()))} planned rows; no state changed.',
                          planned_rows=specs)
            emit(result, args.json)
            return int(bool(missing or spec_warnings or receiver_warnings))
        # Recheck that PID targets still identify the same executable/launcher before writing.
        if process and (str(mac.pidpath(process['pid'])) != process['path'] or
                        mac.responsible(process['pid']) != process['responsible_pid']):
            raise Error('PID identity changed before writing; retry.')
        active_databases = {k: v for k, v in databases.items() if specs[k]}
        active_specs = {k: v for k, v in specs.items() if v}
        if not active_specs:
            raise Error('No grants can be written for this selection.')
        record = transact(active_databases, active_specs)
        # The grant journal already contains sufficient undo information.
        result['change_id'] = record['id']
        refreshed = refresh(user.pw_uid, active_databases) if record['changes'] else []
        result.update(refresh=refreshed, changed_rows=len(record['changes']),
                      summary=f'{len(record["changes"])} rows changed. Database grants saved; '
                              'relaunch the target '
                              'if its permission state is cached. Effective API authorization is unverified.')
        emit(result, args.json)
        return int(bool(missing or spec_warnings or receiver_warnings or any(r['status'] == 'failed' for r in refreshed)))
    except (Error, OSError, sqlite3.Error, subprocess.TimeoutExpired, plistlib.InvalidFileException) as e:
        if args.json:
            print(json.dumps({'error': str(e)}))
        else:
            print('tcc_grant.py: ' + str(e), file=sys.stderr)
        return 1
    except Exception as e:
        if type(e).__name__ != 'WatchError': raise
        if args.json: print(json.dumps({'error':str(e)}))
        else: print('tcc_grant.py: ' + str(e),file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
