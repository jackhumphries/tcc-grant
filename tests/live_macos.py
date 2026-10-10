#!/usr/bin/python3
"""Opt-in live tests. Temporarily grants permissions to disposable probes, then undoes them."""
import json
import os
from pathlib import Path
import plistlib
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / 'tcc_grant.py'
BUILD = ROOT / '.build' / ('live-' + uuid.uuid4().hex[:8])
APP = BUILD / 'PermissionProbe.app'
BUNDLE = 'dev.tcc-grant.test.' + uuid.uuid4().hex[:12]
SERVICES = 'screen-recording,accessibility,input-monitoring,camera,microphone,contacts,calendar,reminders,photos,speech-recognition,automation,full-disk-access'
FRAMEWORKS = ('AppKit', 'AVFoundation', 'Contacts', 'EventKit', 'Photos', 'Speech', 'IOKit', 'ScreenCaptureKit')


def command(argv, **kwargs):
    p = subprocess.run([str(a) for a in argv], text=True, capture_output=True, timeout=60, **kwargs)
    if p.returncode:
        raise RuntimeError(f'Command failed ({p.returncode}): {argv}\n{p.stdout}\n{p.stderr}')
    return p.stdout


def run_script(*args, root=True, changes=None):
    prefix = ['sudo', '-n'] if root else []
    argv = [str(a) for a in prefix + ['/usr/bin/python3', TOOL, *args, '--json']]
    p = subprocess.run(argv, text=True, capture_output=True, timeout=60)
    try:
        result = json.loads(p.stdout)
    except json.JSONDecodeError:
        if not p.returncode:
            raise
        result = {}
    # A partial grant can save permissions and still return a failure exit code.
    # Register its journal before raising so the finally block also restores it.
    if changes is not None and result.get('change_id'):
        changes.append(result['change_id'])
    if p.returncode:
        raise RuntimeError(f'Command failed ({p.returncode}): {argv}\n{p.stdout}\n{p.stderr}')
    return result


def build(version='A', standalone=False):
    source = (ROOT / 'probes/PermissionProbe.swift').read_text().replace('"rebuild": "A"', f'"rebuild": "{version}"')
    source_path = BUILD / (version + '.swift')
    source_path.write_text(source)
    binary = BUILD / 'CLIProbe' if standalone else APP / 'Contents/MacOS/PermissionProbe'
    binary.parent.mkdir(parents=True, exist_ok=True)
    command(['xcrun', 'swiftc', '-parse-as-library', source_path, '-o', binary,
             *[arg for framework in FRAMEWORKS for arg in ('-framework', framework)]])
    if not standalone:
        info = {'CFBundleIdentifier': BUNDLE, 'CFBundleName': 'TCC Grant Live Probe',
                'CFBundleExecutable': 'PermissionProbe', 'CFBundlePackageType': 'APPL', 'LSUIElement': True}
        for key in ('NSCameraUsageDescription', 'NSMicrophoneUsageDescription', 'NSContactsUsageDescription',
                    'NSCalendarsFullAccessUsageDescription', 'NSCalendarsUsageDescription',
                    'NSRemindersFullAccessUsageDescription', 'NSRemindersUsageDescription',
                    'NSPhotoLibraryUsageDescription', 'NSSpeechRecognitionUsageDescription', 'NSAppleEventsUsageDescription'):
            info[key] = 'Verify permissions for this disposable development probe.'
        (APP / 'Contents/Info.plist').write_bytes(plistlib.dumps(info))
    command(['codesign', '--force', '--sign', '-', '--identifier', BUNDLE if not standalone else BUNDLE + '.cli',
             binary if standalone else APP])
    return binary


def probe(name, capture=False):
    output = BUILD / (name + '.json')
    args = ['--output', output, '--receiver', 'com.apple.finder']
    if capture:
        args += ['--capture']
    command(['open', '-n', '-W', APP, '--args', *args])
    return json.loads(output.read_text())


def assert_allowed(result):
    for name in ('screen-recording', 'accessibility', 'input-monitoring'):
        assert result[name] is True, (name, result)
    for name in ('camera', 'microphone', 'contacts', 'calendar', 'reminders', 'photos', 'speech-recognition'):
        assert result[name] == 3, (name, result)
    assert result['automation'] == 0, result
    assert result['full-disk-access-preflight'] == 0, result
    assert result['capture'] == {'width': 400, 'height': 300}, result


def main():
    if sys.platform != 'darwin' or os.geteuid() == 0:
        raise RuntimeError('Run as the logged-in macOS user, with sudo credentials available.')
    command(['sudo', '-n', 'true'])
    BUILD.mkdir(parents=True)
    changes = []
    report = {'build': str(BUILD), 'bundle': BUNDLE}
    held = None
    def restore_last():
        run_script('undo', changes[-1])
        changes.pop()
    try:
        build()
        report['baseline'] = probe('baseline')
        assert report['baseline']['screen-recording'] is False
        dry = run_script('grant', '--app', APP, '--service', SERVICES, '--receiver', 'com.apple.finder', '--dry-run', root=False)
        assert 'change_id' not in dry and dry['planned_rows']
        report['persistent_grant'] = run_script('grant', '--app', APP, '--service', SERVICES, '--receiver', 'com.apple.finder', changes=changes)
        report['allowed'] = probe('allowed', True)
        assert_allowed(report['allowed'])
        build('B')
        report['rebuilt'] = probe('rebuilt', True)
        assert report['rebuilt']['rebuild'] == 'B'
        assert_allowed(report['rebuilt'])
        report['idempotent'] = run_script('grant', '--app', APP, '--service', SERVICES, '--receiver', 'com.apple.finder', changes=changes)
        assert report['idempotent']['changed_rows'] == 0
        restore_last()
        restore_last()
        report['restored'] = probe('restored')
        assert report['restored']['screen-recording'] is False

        report['strict_grant'] = run_script('grant', '--app', APP, '--service', 'screen-recording', '--strict-signature', changes=changes)
        assert probe('strict-allowed')['screen-recording'] is True
        build('C')
        report['strict_status'] = run_script('status', '--app', APP)
        rows = [r for r in report['strict_status']['grants'] if r['service'] == 'kTCCServiceScreenCapture']
        assert rows and rows[0]['status'] == 'signature-mismatch'
        # Restore without launching mismatched code: avoids macOS replacing the
        # journaled grant with a new denial, which correctly causes an undo conflict.
        restore_last()

        binary = build('D', True)
        held = subprocess.Popen([str(binary), '--output', str(BUILD / 'pid-baseline.json'), '--hold', '300'])
        report['pid_grant'] = run_script('grant', '--pid', str(held.pid), '--service', SERVICES, '--receiver', 'com.apple.finder', changes=changes)
        report['pid_allowed'] = json.loads(command([binary, '--capture', '--receiver', 'com.apple.finder']))
        assert_allowed(report['pid_allowed'])
        stale = held.pid
        held.terminate()
        held.wait(timeout=10)
        held = None
        stale_result = subprocess.run(['sudo', '-n', '/usr/bin/python3', str(TOOL), 'status', '--pid', str(stale), '--json'],
                                      capture_output=True, text=True, timeout=30)
        assert stale_result.returncode != 0 and 'error' in json.loads(stale_result.stdout)
        report['stale_pid'] = json.loads(stale_result.stdout)
        restore_last()
        report['result'] = 'passed'
    finally:
        if held:
            held.terminate()
            held.wait(timeout=10)
        errors = []
        for change_id in reversed(changes):
            try:
                run_script('undo', change_id)
            except Exception as e:
                errors.append({'change_id': change_id, 'error': str(e)})
        if not errors:
            try:
                command(['sudo', '-n', '/usr/bin/python3', ROOT / 'tests/cleanup_probe.py',
                         '--bundle', BUNDLE, '--executable', BUILD / 'CLIProbe'])
            except Exception as e:
                errors.append({'probe_cleanup': str(e)})
        report['cleanup_errors'] = errors
        (BUILD / 'report.json').write_text(json.dumps(report, indent=2))
        if errors:
            raise RuntimeError(f'Cleanup needs attention: {errors}')
    print(f'Live tests passed. Report: {BUILD / "report.json"}')


if __name__ == '__main__':
    main()
