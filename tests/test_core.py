import importlib.util
import contextlib
import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

MODULE = Path(__file__).resolve().parents[1] / 'tcc_grant.py'
spec = importlib.util.spec_from_file_location('tcc_grant', MODULE)
t = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = t
spec.loader.exec_module(t)

SCHEMA = '''
CREATE TABLE access (
 service TEXT NOT NULL, client TEXT NOT NULL, client_type INTEGER NOT NULL,
 auth_value INTEGER NOT NULL, auth_reason INTEGER NOT NULL, auth_version INTEGER NOT NULL,
 csreq BLOB, policy_id INTEGER, indirect_object_identifier_type INTEGER,
 indirect_object_identifier TEXT NOT NULL DEFAULT 'UNUSED', indirect_object_code_identity BLOB,
 flags INTEGER, last_modified INTEGER NOT NULL DEFAULT 0,
 pid INTEGER, pid_version INTEGER, boot_uuid TEXT NOT NULL DEFAULT 'UNUSED',
 last_reminded INTEGER NOT NULL DEFAULT 0, one_time_reprompt_eligible INTEGER,
 reminder_count INTEGER NOT NULL DEFAULT 0,
 PRIMARY KEY(service,client,client_type,indirect_object_identifier));
CREATE TABLE managed_overrides (
 service TEXT, client TEXT, client_type INTEGER, indirect_object_identifier TEXT, auth_value INTEGER);
'''


class CoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.dbs = {n: self.root / (n + " ' quoted.db") for n in ('system', 'user')}
        self.state = self.root / 'state'
        for path in self.dbs.values():
            with sqlite3.connect(path) as c:
                c.executescript(SCHEMA)
        self.row = dict(service='kTCCServiceScreenCapture', client='/test/a "quoted" tool',
                        client_type=1, auth_version=1, csreq=b'\x00\x01',
                        indirect_object_identifier='UNUSED', indirect_object_identifier_type=None,
                        indirect_object_code_identity=None)

    def tearDown(self):
        self.tmp.cleanup()

    def current(self, database='system', row=None):
        c = t.connect(self.dbs[database], True)
        try:
            return t.read_row(c, row or self.row)
        finally:
            c.close()

    def test_atomic_grant_backup_idempotence_and_undo(self):
        r = t.transact(self.dbs, {'system': [self.row], 'user': [self.row]}, self.state)
        self.assertEqual(len(r['changes']), 2)
        self.assertEqual(self.current()['auth_value'], 2)
        self.assertEqual(self.current('user')['csreq'], b'\x00\x01')
        self.assertEqual(os.stat(self.state / r['id'] / 'system.sqlite3').st_mode & 0o777, 0o600)
        with sqlite3.connect(self.state / r['id'] / 'system.sqlite3') as c:
            self.assertEqual(c.execute('SELECT count(*) FROM access').fetchone()[0], 0)
        again = t.transact(self.dbs, {'system': [self.row]}, self.state)
        self.assertEqual(again['changes'], [])
        t.undo(r['id'], self.state)
        self.assertIsNone(self.current())
        self.assertIsNone(self.current('user'))
        self.assertEqual(t.undo(r['id'], self.state)['status'], 'undone')

    def test_partial_commit_failure_is_compensated(self):
        def failure(name):
            if name == 'system':
                raise RuntimeError('injected commit failure')
        with self.assertRaisesRegex(t.Error, 'rolled_back'):
            t.transact(self.dbs, {'system': [self.row], 'user': [self.row]}, self.state, fault=failure)
        self.assertIsNone(self.current())
        self.assertIsNone(self.current('user'))

    def test_interrupt_during_commit_is_compensated(self):
        real_connect = t.connect
        for database in ('system', 'user'):
            for commit_first in (False, True):
                with self.subTest(database=database, commit_first=commit_first):
                    class InterruptedConnection:
                        interrupted = False

                        def __init__(self, connection):
                            self.connection = connection

                        def __getattr__(self, name):
                            return getattr(self.connection, name)

                        def commit(self):
                            if self.interrupted:
                                return self.connection.commit()
                            self.interrupted = True
                            if commit_first:
                                self.connection.commit()
                            raise KeyboardInterrupt('interrupt before commit returns')

                    def connect(path):
                        connection = real_connect(path)
                        return InterruptedConnection(connection) if path == self.dbs[database] else connection

                    with patch.object(t, 'connect', side_effect=connect):
                        with self.assertRaisesRegex(t.Error, 'rolled_back'):
                            t.transact(self.dbs, {'system': [self.row], 'user': [self.row]}, self.state)
                    self.assertIsNone(self.current())
                    self.assertIsNone(self.current('user'))
                    for manifest in self.state.glob('*/change.json'):
                        self.assertEqual(json.loads(manifest.read_text())['status'], 'rolled_back')

    def test_compensation_preserves_concurrent_edits_and_requires_recovery(self):
        def failure(name):
            if name == 'system':
                with sqlite3.connect(self.dbs[name]) as c:
                    c.execute('UPDATE access SET auth_value=0')
                raise RuntimeError('failure after a concurrent edit')

        with self.assertRaisesRegex(t.Error, 'rollback_failed'):
            t.transact(self.dbs, {'system': [self.row], 'user': [self.row]}, self.state, fault=failure)
        self.assertEqual(self.current()['auth_value'], 0)
        self.assertIsNone(self.current('user'))
        with self.assertRaisesRegex(t.Error, 'Unfinished operation'):
            t.transact(self.dbs, {'system': [self.row]}, self.state)

    def test_refresh_errors_do_not_skip_remaining_services(self):
        ok = subprocess.CompletedProcess([], 0, stdout='', stderr='')
        for phase in ('print', 'kickstart'):
            for error in (subprocess.TimeoutExpired('/bin/launchctl', 30), OSError('launchctl unavailable')):
                with self.subTest(phase=phase, error=type(error).__name__):
                    responses = ([ok] if phase == 'kickstart' else []) + [error, ok, ok]
                    with patch.object(t, 'run', side_effect=responses):
                        results = t.refresh(502, self.dbs)
                    self.assertEqual([r['status'] for r in results], ['failed', 'refreshed'])
                    self.assertEqual(results[0]['detail'], str(error))
                    self.assertEqual(results[1]['service'], 'gui/502/com.apple.tccd')

    def test_grant_reports_saved_change_and_can_be_undone_after_refresh_timeout(self):
        real_transact = t.transact
        output = io.StringIO()
        ok = subprocess.CompletedProcess([], 0, stdout='', stderr='')
        fixtures = {
            'Mac': object(),
            'choose_user': SimpleNamespace(pw_name='test', pw_uid=502, pw_dir=str(self.root)),
            'discover_databases': (self.dbs, 'fixture'),
            'resolve_targets': ([t.Target(self.row['client'], 1, self.row['client'])], [], None),
            'check_environment': ('27.0.1', 'disabled'),
            'require_root': None,
            'selected_services': [t.CATALOG['screen-recording']],
            'receiver_targets': ([], []),
            'make_specs': ({'system': [self.row], 'user': [self.row]}, [], []),
        }
        with contextlib.ExitStack() as stack:
            for name, result in fixtures.items():
                stack.enter_context(patch.object(t, name, return_value=result))
            stack.enter_context(patch.object(t, 'transact', side_effect=lambda dbs, specs: real_transact(dbs, specs, self.state)))
            stack.enter_context(patch.object(t, 'run', side_effect=[subprocess.TimeoutExpired('/bin/launchctl', 30), ok, ok]))
            stack.enter_context(contextlib.redirect_stdout(output))
            code = t.main(['grant', '--executable', self.row['client'], '--service', 'screen-recording', '--json'])
        result = json.loads(output.getvalue())
        self.assertEqual(code, 1)
        self.assertEqual(result['changed_rows'], 2)
        self.assertEqual([r['status'] for r in result['refresh']], ['failed', 'refreshed'])
        self.assertEqual(self.current()['auth_value'], 2)
        self.assertEqual(self.current('user')['auth_value'], 2)
        self.assertEqual(t.undo(result['change_id'], self.state)['status'], 'undone')
        self.assertIsNone(self.current())
        self.assertIsNone(self.current('user'))

    def test_original_denial_and_unrelated_grants_are_restored(self):
        c = t.connect(self.dbs['system'])
        denied = {**self.row, 'auth_value': 0, 'auth_reason': 2, 'last_modified': 123, 'flags': 1}
        t.write_row(c, denied)
        other = {**denied, 'client': '/unrelated', 'auth_value': 2}
        t.write_row(c, other)
        c.close()
        before = self.current()
        r = t.transact(self.dbs, {'system': [self.row]}, self.state)
        t.undo(r['id'], self.state)
        self.assertEqual(self.current(), before)
        self.assertEqual(self.current(row=other)['auth_value'], 2)

    def test_conflicting_undo_changes_nothing(self):
        r = t.transact(self.dbs, {'system': [self.row], 'user': [self.row]}, self.state)
        with sqlite3.connect(self.dbs['user']) as c:
            c.execute('UPDATE access SET auth_value=0')
        with self.assertRaisesRegex(t.Error, 'Undo conflict'):
            t.undo(r['id'], self.state)
        self.assertEqual(self.current()['auth_value'], 2)
        self.assertEqual(self.current('user')['auth_value'], 0)

    def test_managed_override_prevents_any_commit(self):
        with sqlite3.connect(self.dbs['user']) as c:
            c.execute('INSERT INTO managed_overrides VALUES (?,?,?,?,?)',
                      tuple(self.row[k] for k in t.KEYS) + (0,))
        with self.assertRaisesRegex(t.Error, 'Managed override'):
            t.transact(self.dbs, {'system': [self.row], 'user': [self.row]}, self.state)
        self.assertIsNone(self.current())

    def test_schema_change_fails_before_writing(self):
        with sqlite3.connect(self.dbs['user']) as c:
            c.execute('ALTER TABLE access ADD COLUMN surprise TEXT NOT NULL DEFAULT "ok"')
        # Extra defaulted columns are preserved, but a changed key must fail.
        with sqlite3.connect(self.dbs['system']) as c:
            c.execute('DROP TABLE access')
            c.execute('CREATE TABLE access (service TEXT)')
        with self.assertRaisesRegex(t.Error, 'Unsupported TCC schema'):
            t.transact(self.dbs, {'system': [self.row], 'user': [self.row]}, self.state)
        self.assertIsNone(self.current('user'))

    def test_no_database_created_at_missing_path(self):
        path = self.root / 'missing.db'
        with self.assertRaises(sqlite3.OperationalError):
            t.connect(path)
        self.assertFalse(path.exists())

    def test_protected_container_fallback_and_user_ownership(self):
        container = self.root / 'containers' / 'A'
        container.mkdir(parents=True)
        import plistlib
        import pwd
        user = pwd.getpwuid(os.getuid())
        metadata = {'MCMMetadataIdentifier': 'com.apple.tccd',
                    'MCMMetadataOwnership': {'uid': user.pw_uid}}
        (container / '.com.apple.containermanagerd.metadata.plist').write_bytes(plistlib.dumps(metadata))
        db = container / 'Data/Library/Application Support/com.apple.TCC/TCC.db'
        db.parent.mkdir(parents=True)
        db.write_bytes(b'')
        # Root-ownership check of the system DB is separately tested on this Mac.
        with patch.object(t, 'CONTAINERS', container.parent), patch.object(t, 'SYSTEM_DB', Path('/Library/Application Support/com.apple.TCC/TCC.db')):
            with patch.object(t, 'run', return_value=type('R', (), {'stdout': ''})()):
                result, source = t.discover_databases(user)
        self.assertEqual(result['user'], db.resolve())
        self.assertEqual(source, 'protected container metadata')

    def test_installed_apps_deduplicate_bundles_and_skip_nested_helpers(self):
        import plistlib
        app = self.root / 'Applications' / 'Sample.app'
        (app / 'Contents').mkdir(parents=True)
        (app / 'Contents/Info.plist').write_bytes(plistlib.dumps({'CFBundleIdentifier': 'test.example'}))
        target = t.target_from_path(app)
        self.assertEqual(target.client, 'test.example')
        self.assertEqual(target.client_type, 0)
        duplicate = self.root / 'Applications' / 'Other.app'
        (duplicate / 'Contents').mkdir(parents=True)
        (duplicate / 'Contents/Info.plist').write_bytes(plistlib.dumps({'CFBundleIdentifier': 'test.example'}))
        nested = app / 'Contents/Helpers/PrivateHelper.app'
        (nested / 'Contents').mkdir(parents=True)
        (nested / 'Contents/Info.plist').write_bytes(plistlib.dumps({'CFBundleIdentifier': 'test.private'}))
        apps, warnings = t.installed_apps(str(self.root), roots=[self.root / 'Applications'])
        self.assertEqual(list(apps), ['test.example'])
        self.assertEqual(warnings, [])

    def test_missing_automation_receiver_is_explicit(self):
        class FakeMac:
            def requirement(self, *args):
                return b'req'
        target = t.Target('test.example', 0, '/test/Example.app')
        specs, warnings, missing = t.make_specs([target], [t.CATALOG['automation']], [], [], FakeMac())
        self.assertFalse(specs['user'])
        self.assertEqual(missing[0]['status'], 'missing-receiver')

    def test_file_provider_domains_use_type_three(self):
        class FakeMac:
            def requirement(self, *args):
                return b'req'
        target = t.Target('/test/tool', 1, '/test/tool')
        specs, _, missing = t.make_specs([target], [t.CATALOG['file-provider-domain']], [], ['test/domain'], FakeMac())
        self.assertFalse(missing)
        self.assertEqual(specs['user'][0]['indirect_object_identifier_type'], 3)

    def test_blob_encoding_roundtrip(self):
        original = {'a': [b'\x00\xff', {'x': None}]}
        self.assertEqual(t.decode(json.loads(json.dumps(t.encode(original)))), original)

    def test_concurrent_grants_serialize(self):
        from concurrent.futures import ThreadPoolExecutor
        other = {**self.row, 'client': '/test/second'}
        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(t.transact, self.dbs, {'system': [self.row]}, self.state)
            second = pool.submit(t.transact, self.dbs, {'system': [other]}, self.state)
            a, b = first.result(), second.result()
        self.assertNotEqual(a['id'], b['id'])
        self.assertEqual(self.current()['auth_value'], 2)
        self.assertEqual(self.current(row=other)['auth_value'], 2)

    def test_unfinished_journal_blocks_new_grants(self):
        r = t.transact(self.dbs, {'system': [self.row]}, self.state)
        path = self.state / r['id'] / 'change.json'
        record = json.loads(path.read_text())
        record['status'] = 'prepared'
        path.write_text(json.dumps(record))
        with self.assertRaisesRegex(t.Error, 'Unfinished operation'):
            t.transact(self.dbs, {'system': [self.row]}, self.state)
        t.undo(r['id'], self.state)
        self.assertIsNone(self.current())

    def test_legacy_backend_journals_can_be_undone(self):
        for backend in ('api', 'entitled'):
            with self.subTest(backend=backend):
                r = t.transact(self.dbs, {'system': [self.row]}, self.state)
                path = self.state / r['id'] / 'change.json'
                record = json.loads(path.read_text())
                record.update(backend=backend, pending=None)
                path.write_text(json.dumps(record))
                t.undo(r['id'], self.state)
                self.assertIsNone(self.current())

    def test_legacy_unconfirmed_write_still_blocks_recovery_and_grants(self):
        r = t.transact(self.dbs, {'system': [self.row]}, self.state)
        path = self.state / r['id'] / 'change.json'
        record = json.loads(path.read_text())
        record.update(status='api_pending', backend='api', pending={
            'database': 'system', 'key': {k: self.row[k] for k in t.KEYS}, 'before': None})
        path.write_text(json.dumps(record))
        with self.assertRaisesRegex(t.Error, 'Unconfirmed daemon write'):
            t.undo(r['id'], self.state)
        with self.assertRaisesRegex(t.Error, 'Unfinished operation'):
            t.transact(self.dbs, {'system': [self.row]}, self.state)
        self.assertEqual(self.current()['auth_value'], 2)

    def test_all_39_categories_are_available_for_direct_grants(self):
        args = t.parser().parse_args(['grant', '--executable', '/test/tool', '--all'])
        with patch.object(t, 'discover_services', return_value={s.name for s in t.CATALOG.values()}):
            self.assertEqual(len(t.selected_services(args)), 39)

    def test_direct_grants_require_fully_disabled_sip(self):
        for sip in ('enabled', 'unknown (Custom Configuration)'):
            with self.subTest(sip=sip), patch.object(t, 'run', side_effect=[
                    type('R', (), {'stdout': '27.0.1'})(),
                    type('R', (), {'stdout': f'System Integrity Protection status: {sip}.'})()]):
                with self.assertRaisesRegex(t.Error, 'SIP must be disabled'):
                    t.check_environment()


if __name__ == '__main__':
    unittest.main()
