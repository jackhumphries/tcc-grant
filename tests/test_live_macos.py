import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


MODULE = Path(__file__).with_name('live_macos.py')
spec = importlib.util.spec_from_file_location('live_macos', MODULE)
live = importlib.util.module_from_spec(spec)
spec.loader.exec_module(live)


class LiveRunnerTests(unittest.TestCase):
    def test_partial_grant_is_registered_before_failure_is_raised(self):
        change_id = '20260101T000000Z-1234abcd'
        result = subprocess.CompletedProcess([], 1, stdout=json.dumps({'change_id': change_id}), stderr='')
        changes = []
        with patch.object(live.subprocess, 'run', return_value=result):
            with self.assertRaisesRegex(RuntimeError, 'Command failed'):
                live.run_script('grant', '--pid', '123', changes=changes)
        self.assertEqual(changes, [change_id])

    def test_successful_grant_is_registered_once_and_dry_run_is_not_registered(self):
        change_id = '20260101T000000Z-1234abcd'
        results = [subprocess.CompletedProcess([], 0, stdout=json.dumps(value), stderr='')
                   for value in ({'change_id': change_id}, {'planned_rows': []})]
        changes = []
        with patch.object(live.subprocess, 'run', side_effect=results):
            self.assertEqual(live.run_script('grant', changes=changes)['change_id'], change_id)
            live.run_script('grant', '--dry-run', root=False, changes=changes)
        self.assertEqual(changes, [change_id])

    def test_non_json_command_failure_preserves_diagnostics(self):
        result = subprocess.CompletedProcess([], 1, stdout='', stderr='sudo: a password is required')
        with patch.object(live.subprocess, 'run', return_value=result):
            with self.assertRaisesRegex(RuntimeError, 'sudo: a password is required'):
                live.run_script('grant', changes=[])

    def test_live_runner_undoes_partial_pid_grant_in_finally(self):
        grants, undos = [], []

        def run(argv, **kwargs):
            value, code = {}, 0
            if 'grant' in argv:
                if '--dry-run' in argv:
                    value = {'planned_rows': {'system': [{}]}}
                else:
                    change_id = f'20260101T000000Z-{len(grants) + 1:08x}'
                    grants.append(change_id)
                    value = {'change_id': change_id, 'changed_rows': 0}
                    code = int('--pid' in argv)
            elif 'undo' in argv:
                undos.append(argv[argv.index('undo') + 1])
            elif 'status' in argv:
                value = {'grants': [{'service': 'kTCCServiceScreenCapture', 'status': 'signature-mismatch'}]}
            return subprocess.CompletedProcess(argv, code, stdout=json.dumps(value), stderr='')

        def probe(name, capture=False):
            return {'screen-recording': name not in ('baseline', 'restored'), 'rebuild': 'B'}

        held = SimpleNamespace(pid=123, terminate=Mock(), wait=Mock())
        with tempfile.TemporaryDirectory() as tmp:
            build = Path(tmp) / 'live-test'
            with patch.object(live, 'BUILD', build), \
                 patch.object(live, 'APP', build / 'Probe.app'), \
                 patch.object(live.sys, 'platform', 'darwin'), \
                 patch.object(live.os, 'geteuid', return_value=502), \
                 patch.object(live, 'build', return_value=build / 'CLIProbe'), \
                 patch.object(live, 'probe', side_effect=probe), \
                 patch.object(live, 'assert_allowed'), \
                 patch.object(live.subprocess, 'Popen', return_value=held), \
                 patch.object(live.subprocess, 'run', side_effect=run):
                with self.assertRaisesRegex(RuntimeError, 'Command failed'):
                    live.main()
            self.assertEqual(len(grants), 4)
            self.assertEqual(undos, [grants[1], grants[0], grants[2], grants[3]])
            self.assertEqual(json.loads((build / 'report.json').read_text())['cleanup_errors'], [])
            held.terminate.assert_called_once()
            held.wait.assert_called_once()


if __name__ == '__main__':
    unittest.main()
