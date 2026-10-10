# GUI permission watcher

The script's `watch` mode recognizes permission dialogs in the active user's
GUI session and presses their affirmative buttons for an explicitly selected
app, executable, or resolved PID identity. It uses the macOS Accessibility API
directly, without screenshots, OCR, AppleScript, or additional Python packages.
This route can work with SIP enabled because the approval goes through Apple's
normal dialog. It requires existing Accessibility access for the Python
executable or its responsible terminal/agent app; sudo does not provide that
access.

```bash
python3 tcc_grant.py watch --app /Applications/YourAgent.app --all --timeout 300
python3 tcc_grant.py watch --pid 12345 --service microphone,camera --dry-run --once --json
```

`--once` scans the visible dialogs once. Continuous watching polls at the selected
interval until the timeout, or until interrupted. A timeout of zero means to
watch until interrupted. Dry runs inspect and report without pressing a button.

The scanner accepts only the expected system executable paths for
UserNotificationCenter, CoreServicesUIAgent, and NotificationCenter, and verifies
their Apple signatures and bundle identifiers. It matches exact English privacy
request headlines from the locally installed TCC framework, supplemented by
specific older and screen-recording renewal wording. App-controlled usage
descriptions cannot select a target or service.

The target name must exactly match the selected app's bundle metadata, app
filename, or executable name. Duplicate names discovered among installed apps
and running processes are refused. The classifier requires a known denial
button and one available, service-appropriate affirmative button. Full photo
and calendar access is preferred when offered. Each button press rereads the
dialog and refuses a changed dialog. Name collisions are refreshed while dialogs
are visible and immediately before approval. The watcher makes at most three
approval attempts while the same dialog remains visible. Text/password-entry
dialogs, administrative authorization dialogs, unknown text or buttons, and
incomplete Accessibility trees are left alone.

Structured results distinguish `approved`, `would-approve`, `ignored`, and
`failed`, including the service, selected client, host process, button, and
reason when known. `approved` means that Accessibility successfully pressed the
button; the requesting app still determines whether its permission API succeeds.
Every decision can also be emitted immediately for live command-line output.

## Limits

- Accessibility access must already be available. The watcher cannot approve its
  own initial Accessibility bootstrap from an untrusted process.
- Only the active console user's GUI is supported. A locked session or a dialog
  unavailable through Accessibility cannot be operated.
- Dialogs offering only **Open System Settings** are reported as
  `requires-system-settings`. The watcher does not change Settings toggles.
- English headlines and the configured affirmative-button labels are supported.
  Unknown localization, future wording, or a different Accessibility layout is
  reported without clicking.
- GUI headlines expose app names rather than code signatures. Collision checking
  is conservative, but this watcher is intended for a development machine with
  trusted apps, not as an app-identity security boundary against malicious apps.
- The watcher does not create permission requests, grant unseen permissions,
  supply administrator passwords, or write a TCC database. GUI approvals are not
  recorded in the script's `undo` journal.

## Integration API

```python
from gui_permissions import WatchError, run_watcher

result = run_watcher(
    targets,                 # Iterable of tcc_grant.Target-like objects.
    user,                    # pwd.struct_passwd for the active console user.
    services=None,           # None for all recognized services; otherwise aliases.
    dry_run=False,
    once=False,
    interval=0.5,
    timeout=60.0,
    emit=print_decision,      # Optional callback receiving one dict per decision.
)
```

The return dictionary includes `status`, `mode`, `approved`, `would_approve`,
`failed`, `decisions`, resolved display-name `targets`, `ambiguous_names`, and
`elapsed_seconds`. Initialization failures raise `WatchError`. Interrupted
watching returns the decisions already completed and `status: interrupted`.
`failed` counts dialogs whose failed presses were not resolved by a successful
retry; individual failed attempts remain in `decisions`. Unresolved failures
produce `status: partial`; callers should return nonzero for that status.
The module accepts no credentials.

## Validation on this Mac

Nineteen fixtures cover selected target/service matching, unknown and disabled
buttons, full-photo selection, duplicate names, Apple-host verification,
password/dialog refusal, app-controlled text impersonation, dry runs, callback
output, and failed/stale actions. A disposable signed app then requested real
microphone access: dry-run selected the correct UserNotificationCenter prompt,
the watcher pressed **Allow**, and `AVCaptureDevice.requestAccess` returned
`true`. The probe's unique permission row was removed, the user database passed
its integrity check, and the user `tccd` service was refreshed. This live test
was performed on the current SIP-disabled Mac; SIP-enabled compatibility follows
the normal Accessibility interaction model and has not been live-tested here.

Apple's APIs used by the implementation are
[AXIsProcessTrusted](https://developer.apple.com/documentation/applicationservices/1460720-axisprocesstrusted),
[AXUIElementCopyAttributeValue](https://developer.apple.com/documentation/applicationservices/1462085-axuielementcopyattributevalue),
and [AXUIElementPerformAction](https://developer.apple.com/documentation/applicationservices/1462091-axuielementperformaction).
