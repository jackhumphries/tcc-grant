import importlib.util
from pathlib import Path
import pwd
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch


MODULE = Path(__file__).resolve().parents[1] / 'gui_permissions.py'
spec = importlib.util.spec_from_file_location('gui_permissions', MODULE)
gui = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = gui
spec.loader.exec_module(gui)


class ClassifierTests(unittest.TestCase):
    def setUp(self):
        executable, bundle_id = next(iter(gui.HOSTS.items()))
        self.host = gui.Host(200, 502, executable, bundle_id, True)
        self.identity = gui.Identity('test.probe', 0, '/test/Probe.app', ('Probe',))
        self.templates = (gui.Template('microphone', 'Allow “%@” to access your microphone?'),)

    def prompt(self, text='Allow “Probe” to access your microphone?', titles=('Don’t Allow', 'Allow'), **kw):
        return gui.Prompt(self.host, (text,), tuple(gui.Button(t) for t in titles), **kw)

    def classify(self, prompt=None, **kw):
        return gui.classify_prompt(prompt or self.prompt(), (self.identity,), self.templates, **kw)

    def test_current_apple_template_and_exact_button(self):
        decision = self.classify()
        self.assertEqual(decision['status'], 'ready')
        self.assertEqual(decision['client'], 'test.probe')
        self.assertEqual(decision['button'], 'Allow')

    def test_custom_purpose_string_cannot_select_a_target(self):
        prompt = self.prompt('Allow “Other App” to access your microphone?')
        prompt.texts += ('Probe needs the microphone for development.',)
        self.assertEqual(self.classify(prompt)['reason'], 'target-not-selected')

    def test_usage_description_cannot_impersonate_a_permission_headline(self):
        prompt = self.prompt('“Other App” would like to administer your computer.')
        prompt.texts += ('Allow “Probe” to access your microphone?',)
        self.assertEqual(self.classify(prompt)['reason'], 'unknown-permission-dialog')

    def test_untrusted_application_cannot_emulate_system_prompt(self):
        prompt = self.prompt()
        prompt.host = gui.Host(200, 502, '/tmp/UserNotificationCenter', self.host.bundle_id, True)
        self.assertEqual(self.classify(prompt)['reason'], 'untrusted-host')
        prompt.host = gui.dataclasses.replace(self.host, verified=False)
        self.assertEqual(self.classify(prompt)['reason'], 'untrusted-host')

    def test_target_name_must_be_exact_and_unambiguous(self):
        self.assertEqual(self.classify(self.prompt('Allow “Probe Helper” to access your microphone?'))['reason'],
                         'target-not-selected')
        self.assertEqual(self.classify(ambiguous_names={'Probe'})['reason'], 'ambiguous-target-name')
        duplicate = gui.Identity('other.probe', 0, '/other/Probe.app', ('Probe',))
        self.assertEqual(gui.classify_prompt(self.prompt(), (self.identity, duplicate), self.templates)['reason'],
                         'ambiguous-target-name')

    def test_service_filter_does_not_approve_unselected_category(self):
        self.assertEqual(self.classify(services={'camera'})['reason'], 'service-not-selected')

    def test_password_and_incomplete_tree_are_refused(self):
        self.assertEqual(self.classify(self.prompt(has_text_input=True))['reason'], 'text-or-password-input')
        self.assertEqual(self.classify(self.prompt(truncated=True))['reason'], 'incomplete-accessibility-tree')

    def test_unknown_approval_button_and_absent_denial_are_refused(self):
        self.assertEqual(self.classify(self.prompt(titles=('Don’t Allow', 'Approve Everything')))['reason'],
                         'no-known-approval-button')
        self.assertEqual(self.classify(self.prompt(titles=('Allow',)))['reason'], 'missing-denial-button')

    def test_settings_prompt_reported_without_clicking(self):
        self.assertEqual(self.classify(self.prompt(titles=('Deny', 'Open System Settings')))['reason'],
                         'requires-system-settings')

    def test_disabled_and_duplicate_approval_buttons_are_refused(self):
        prompt = self.prompt()
        prompt.buttons = (gui.Button('Don’t Allow'), gui.Button('Allow', enabled=False))
        self.assertEqual(self.classify(prompt)['reason'], 'approval-button-unavailable')
        self.assertEqual(self.classify(self.prompt(titles=('Don’t Allow', 'Allow', 'OK')))['reason'],
                         'ambiguous-approval-button')

    def test_full_photo_access_is_preferred(self):
        template = gui.Template('photos', 'Allow “%@” to access your photo library?')
        prompt = self.prompt('Allow “Probe” to access your photo library?',
                             ('Don’t Allow', 'Select Photos', 'Allow Full Access'))
        decision = gui.classify_prompt(prompt, (self.identity,), (template,))
        self.assertEqual(decision['button'], 'Allow Full Access')

    def test_administration_prompt_is_not_a_supported_template(self):
        templates = gui.load_templates()
        prompt = self.prompt('“Probe” would like to administer your computer. Administration can include '
                             'modifying passwords, networking, and system settings.')
        self.assertEqual(gui.classify_prompt(prompt, (self.identity,), templates)['reason'], 'unknown-permission-dialog')

    def test_automation_receiver_is_part_of_apple_template(self):
        template = gui.Template('automation', '“%@” wants access to control “%@”. Allowing control will '
                                'provide access to documents and data in “%@”, and to perform actions within that app.')
        text = '“Probe” wants access to control “Finder”. Allowing control will provide access to documents and '
        text += 'data in “Finder”, and to perform actions within that app.'
        decision = gui.classify_prompt(self.prompt(text), (self.identity,), (template,))
        self.assertEqual(decision['status'], 'ready')
        self.assertEqual(decision['service'], 'automation')


class WatcherTests(unittest.TestCase):
    def setUp(self):
        self.user = pwd.getpwuid(Path('/dev/console').stat().st_uid)
        self.target = SimpleNamespace(client='/tmp/probe', client_type=1, path='/tmp/probe')
        executable, bundle_id = next(iter(gui.HOSTS.items()))
        self.host = gui.Host(200, self.user.pw_uid, executable, bundle_id, True)
        self.prompt = gui.Prompt(self.host, ('Allow “probe” to access your microphone?',),
                                 (gui.Button('Don’t Allow'), gui.Button('Allow')))
        self.templates = (gui.Template('microphone', 'Allow “%@” to access your microphone?'),)

    def backend(self, trusted=True, fail=False):
        outer = self
        class Backend:
            presses = 0
            closes = 0
            def trusted(self):
                return trusted
            def scan(self, uid):
                return [outer.prompt]
            def press(self, *args):
                self.presses += 1
                if fail:
                    raise gui.WatchError('injected stale dialog')
            def close(self, prompt):
                self.closes += 1
        return Backend()

    def run_once(self, backend, **kw):
        return gui.run_watcher([self.target], self.user, once=True, backend=backend,
                               templates=self.templates, ambiguous_names=(), **kw)

    def test_dry_run_emits_decision_without_any_click(self):
        backend, emitted = self.backend(), []
        result = self.run_once(backend, dry_run=True, emit=emitted.append)
        self.assertEqual(backend.presses, 0)
        self.assertEqual(backend.closes, 1)
        self.assertEqual(result['would_approve'], 1)
        self.assertEqual(emitted[0]['status'], 'would-approve')

    def test_real_mode_calls_only_approved_candidate(self):
        backend = self.backend()
        result = self.run_once(backend)
        self.assertEqual(backend.presses, 1)
        self.assertEqual(result['approved'], 1)
        self.assertEqual(result['decisions'][0]['status'], 'approved')

    def test_failed_action_is_reported_and_reference_closed(self):
        backend = self.backend(fail=True)
        result = self.run_once(backend)
        self.assertEqual(result['failed'], 1)
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(backend.closes, 1)

    def run_scans(self, backend, count=5, **kw):
        # Advance time without sleeping or depending on scheduler timing.
        elapsed = [0.0]

        def sleep(delay):
            elapsed[0] += delay

        with patch.object(gui.time, 'monotonic', side_effect=lambda: elapsed[0]), \
             patch.object(gui.time, 'sleep', side_effect=sleep):
            return gui.run_watcher([self.target], self.user, backend=backend,
                                   templates=self.templates, interval=0.1,
                                   timeout=(count - 1) * 0.1, **kw)

    def test_transient_press_failure_is_retried_and_resolved(self):
        backend = self.backend()
        original_press = backend.press

        def press(*args):
            original_press(*args)
            if backend.presses == 1:
                raise gui.WatchError('transient AX error')

        backend.press = press
        result = self.run_scans(backend, ambiguous_names=())
        self.assertEqual(backend.presses, 2)
        self.assertEqual(result['approved'], 1)
        self.assertEqual(result['failed'], 0)
        self.assertEqual(result['status'], 'completed')
        self.assertEqual([d['status'] for d in result['decisions']], ['failed', 'approved'])
        self.assertGreaterEqual(backend.closes, 5)

    def test_persistent_press_failure_has_a_bounded_retry_budget(self):
        backend = self.backend(fail=True)
        result = self.run_scans(backend, count=6, ambiguous_names=())
        self.assertEqual(backend.presses, 3)
        self.assertEqual(result['approved'], 0)
        self.assertEqual(result['failed'], 1)
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(len(result['decisions']), 3)
        self.assertGreaterEqual(backend.closes, 6)

    def test_new_collision_after_startup_prevents_approval(self):
        backend = self.backend()
        with patch.object(gui, 'find_ambiguous_names', side_effect=[set(), {'probe'}]):
            result = gui.run_watcher([self.target], self.user, once=True, backend=backend,
                                     templates=self.templates)
        self.assertEqual(backend.presses, 0)
        self.assertEqual(result['ambiguous_names'], ['probe'])
        self.assertEqual(result['decisions'][0]['reason'], 'ambiguous-target-name')
        self.assertEqual(backend.closes, 1)

    def test_collision_is_rechecked_immediately_before_approval(self):
        backend = self.backend()
        with patch.object(gui, 'find_ambiguous_names', side_effect=[set(), set(), {'probe'}]):
            result = gui.run_watcher([self.target], self.user, once=True, backend=backend,
                                     templates=self.templates)
        self.assertEqual(backend.presses, 0)
        self.assertEqual(result['decisions'][0]['reason'], 'ambiguous-target-name')

    def test_unchanged_dialog_is_reconsidered_when_collision_disappears(self):
        backend = self.backend()
        with patch.object(gui, 'find_ambiguous_names', side_effect=[{'probe'}, {'probe'}, set(), set(), set()]):
            result = self.run_scans(backend, count=3)
        self.assertEqual(backend.presses, 1)
        self.assertEqual(result['approved'], 1)
        self.assertEqual(result['ambiguous_names'], [])
        self.assertEqual([d['status'] for d in result['decisions']], ['ignored', 'approved'])

    def test_accessibility_trust_is_required_even_for_dry_run(self):
        with self.assertRaisesRegex(gui.WatchError, 'existing Accessibility access'):
            self.run_once(self.backend(trusted=False), dry_run=True)

    def test_ignored_dialog_is_never_clicked(self):
        self.prompt.texts = ('Allow “unselected” to access your microphone?',)
        backend = self.backend()
        result = self.run_once(backend)
        self.assertEqual(backend.presses, 0)
        self.assertEqual(result['decisions'][0]['reason'], 'target-not-selected')

    def test_nonfinite_polling_and_timeout_values_are_rejected(self):
        for option in ({'interval': float('nan')}, {'interval': float('inf')},
                       {'timeout': float('nan')}, {'timeout': float('inf')}):
            with self.subTest(option=option), self.assertRaisesRegex(gui.WatchError, 'finite'):
                self.run_once(self.backend(), **option)


if __name__ == '__main__':
    unittest.main()
