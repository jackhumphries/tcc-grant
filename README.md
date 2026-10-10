# tcc-grant

When developing macOS software with AI agents, the agents often need various
permissions granted such as screen recording permissions. The agents cannot make
forward progress until I manually approve these permissions. The only way to do
so is via the GUI, even when the agent has sudo access on a Mac with SIP
disabled. Apple's built-in command line tool, `tccutil`, only permits reading
permissions rather than modifying them.

This project provides a script for managing macOS permissions via the command
line. AI agents (among other use cases) can use this script to grant themselves
permissions at will. While this can help accelerate development, use this at
your own risk. I personally only use this on a Mac dedicated to development with
no personal information on it.

**When SIP is disabled**, the script can be run entirely from the command line
with no setup needed, though the script must be invoked with `sudo`. **When SIP
is enabled**, you need to first grant Accessibility permission _once_ to Python
and/or the terminal/agent running the script, and after that point, the script
can modify permissions without further intervention. The script does not need
`sudo` access in this case.

This project was implemented with `codex` and builds on top of `tcc-grant` from
the [screenpipe](https://github.com/screenpipe/screenpipe/tree/main/scripts/tcc-grant)
project. See below for the AI-generated description of this project, including
instructions on how to use it.

------------

Manage macOS privacy permissions (TCC) with a Python script on a development Mac.

- **When SIP is disabled:** grant permissions directly, with backups and undo.
- **When SIP is enabled:** use `watch` to click Allow on visible permission prompts.
  The app running the watcher must already have Accessibility access.

Tested on macOS 27.0.1 (26A434).

## Run the script

Requires an Apple silicon Mac, Python 3, and Xcode command line tools. No pip
packages or installation are needed. Keep `tcc_grant.py` and `gui_permissions.py`
together and run these commands from the repository folder:

```bash
python3 tcc_grant.py --help
csrutil status
```

Follow the section matching your SIP status. Replace example paths and PIDs
with your own. To run from another folder, use the full path to `tcc_grant.py`.

## Use with SIP disabled

Check the setup, preview a grant, then apply it:

```bash
sudo python3 tcc_grant.py doctor
sudo python3 tcc_grant.py grant --app /Applications/YourApp.app --all --dry-run
sudo python3 tcc_grant.py grant --app /Applications/YourApp.app --all
sudo python3 tcc_grant.py status --app /Applications/YourApp.app
```

To choose permissions or a different target:

```bash
sudo python3 tcc_grant.py grant --executable /absolute/path/to/helper --service screen-recording,accessibility,input-monitoring
sudo python3 tcc_grant.py grant --pid 12345 --service microphone,camera
sudo python3 tcc_grant.py grant --bundle-id com.googlecode.iterm2 --service full-disk-access
sudo python3 tcc_grant.py grant --app /Applications/YourApp.app --service automation --receiver com.apple.finder
```

`--pid` also includes the target's launcher, such as Terminal, iTerm, or SSH.
Grants to that launcher can affect its other processes. Use `--executable` to
select only the named executable.

`--all` grants every supported category, including automation and app-data access
to installed apps. File Provider access needs `--domain ID`, or domains already
recorded in TCC when using `--all`. Missing receivers or domains are reported.
Rerun the grant for newly installed apps.

## Use with SIP enabled

Direct grants do not work with fully enabled SIP. Use the prompt watcher:

1. Open **System Settings > Privacy & Security > Accessibility**. Enable access
   for the app running the command, usually Terminal or iTerm. If macOS uses
   the Python executable or an agent app instead, enable access for that.
2. In the active, unlocked desktop session, start the watcher without sudo:

   ```bash
   python3 tcc_grant.py watch --app /Applications/YourApp.app --all --timeout 300
   ```

3. Open the target app and use a feature that asks for permission. The watcher
   clicks Allow on recognized prompts for that app during the next five minutes.

If Accessibility access is still missing, enable it and restart the watcher.
Sudo does not provide this permission. To preview clicks for a visible prompt:

```bash
python3 tcc_grant.py watch --app /Applications/YourApp.app --service microphone,camera --dry-run --once
```

Use `--timeout 0` to watch until Ctrl+C. Only recognized English prompts are
supported. The watcher does not make the app request permissions. If a dialog
only offers **Open System Settings**, change the permission there yourself.
Unknown or password dialogs are left alone. Watcher approvals cannot be undone
with this tool. See [GUI_WATCHER.md](GUI_WATCHER.md) for details.

## Check and undo direct grants

```bash
python3 tcc_grant.py services --json
sudo python3 tcc_grant.py changes
sudo python3 tcc_grant.py undo CHANGE_ID
```

Each grant prints a change ID. Backups and change records live in
`/var/db/tcc-grant`. Undo restores only affected entries and stops if another
tool changed them. Interrupted grants or undos must be recovered with `undo`
before new grants can run.

Add `--json` for structured output or `--user USER` to select another account.
Under sudo, the default is the user who ran sudo.

## Limits and tests

- Default grants survive rebuilds at the same path or bundle ID by relaxing
  signature checks. Use `--strict-signature` to bind grants to the target's
  signing identity. Targets must have a usable code signature.
- Direct grants do not cover Location Services or local-network permissions,
  supply missing app entitlements or privacy descriptions, or remove sandbox limits.
- A saved grant does not prove the app can use it. It may need to restart or
  request access through a different identity.
- Exit codes: `0` means success, `1` means failure or a partial result, and `2`
  means invalid syntax. Partial grants may still save permissions; check the output.

```bash
python3 -m unittest discover -s tests -v
# Live tests temporarily change permissions for test apps and their launchers.
# Run as the logged-in user with sudo credentials available.
python3 tests/live_macos.py
```
