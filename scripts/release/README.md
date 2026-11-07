# Gorse

Gorse finds the credentials on your computer and shows what each one could
reach if the laptop were stolen or the AI agent on it went rogue. It runs on
your own machine, reads only, never prints a secret and sends nothing anywhere.

## The apps

**Mac app (`Gorse-macOS.dmg`).** Open the disk image, drag Gorse onto
the Applications folder beside it, and open Gorse from Applications. (The
zip holds the same app; opened from Downloads it offers to move itself.) It runs the check as soon as the
window appears and shows every credential on this Mac, where it is and what
it reaches; Save Report writes the same thing as a page you can keep.

**Windows app.** Run `Gorse-Setup.exe` and click through: it installs for
your user account, adds Gorse to the Start menu and opens it. If you have
the zip instead, Extract All and double-click `Gorse.exe`, keeping
`gorse-cli.exe` next to it: that is the checker it runs. The Windows build
is not yet code-signed, so SmartScreen may warn the first time; compare the
SHA-256 published next to the download before choosing "Run anyway".

## The command-line tool

**macOS.** This is a command-line tool, not an app: nothing goes in
Applications. Double-click the zip you downloaded; macOS puts a folder of the
same name in Downloads with a file called `gorse` inside. Then open
Terminal and run:

    sudo mkdir -p /usr/local/bin
    sudo mv ~/Downloads/gorse-macos-*/gorse /usr/local/bin/
    gorse version

If the folder has a different name, type `sudo mv ` in Terminal, drag the
`gorse` file from the folder into the Terminal window, type a space and
`/usr/local/bin/`, and press Return.

The macOS binary is signed with our Apple Developer ID and notarized, so macOS
opens it without a warning. If macOS still says the developer cannot be
verified, do not override the warning: that means the file is not the one we
published. Email support instead.

**Windows.** Right-click the zip and choose Extract All. Move `gorse.exe` to
a folder such as `C:\Program Files\Gorse\`, then add that folder to your
PATH (search for "Environment Variables" in Start). Open a new terminal and run
`gorse version`. The Windows build is not yet code-signed, so SmartScreen may
warn the first time; compare the file's SHA-256 with the `SHA256SUMS` file in
this zip before choosing "Run anyway".

**Linux.** In a terminal:

    unzip gorse-linux-x86_64.zip
    sudo mkdir -p /usr/local/bin
    sudo mv gorse /usr/local/bin/
    gorse version

Every zip contains a `SHA256SUMS` file. You can check it against the release
page at https://www.gorse.is/download.

## First commands

    gorse exposure        # what a stolen laptop would give away
    gorse exposure --html exposure.html   # the same, as a page for your browser
    gorse scan --deep     # find exposed secrets in your files
    gorse status          # what Gorse can see on this computer

`gorse exposure` lists the credentials and signed-in sessions on this
machine and shows what an attacker could reach with them, including multi-step
paths to production systems, signing services and wallets. Run
`gorse exposure --init` to describe your own production systems and signers,
and the report connects the dots between them.

`gorse scan --deep` reads the files in Desktop, Documents, Downloads and
Pictures for API keys, passwords, private keys, seed phrases and sensitivity
labels, including the text inside screenshots. Add `--all-dirs` for the whole
home folder (Pro). Detection runs inside Gorse: its own rules plus a
converted copy of the open-source Gitleaks rule set (MIT licence, credited in
LICENSE-THIRD-PARTY) run in one pass, and nothing is downloaded.

## What the check sees, and what it does not

Gorse reads the credential files, agent configs and signed-in sessions it
recognises (cloud CLIs, Kubernetes, GitHub, SSH, package registries, CI tokens,
signing keys, wallets), works out what each one opens, and chains them
together to find indirect paths to production and to funds.

- It is a snapshot of the machine at the moment you run it, not monitoring.
- Without Verify, what a credential reaches is inferred from its type and
  your infrastructure map, and the report says so. Verify (Pro) asks each
  provider directly, read-only.
- A secret stored somewhere Gorse does not recognise as a credential
  location is not reported.
- It does not block anything, change anything on the machine, or send
  anything anywhere.

## Free, Pro and Team

- **Free:** everything in this download, including the full exposure report
  and the secret scan. It does not expire.
- **Pro:** adds `gorse exposure --verify`, which confirms with each provider
  what your credentials can really do, the stamped report you can hand to a
  boss, auditor or insurer, and the full scan (`gorse scan --deep
  --all-dirs`, the whole home folder). One computer.
- **Team:** Pro for every laptop, plus one company view of what each laptop
  holds and when it was last checked.

Prices and sign-up: https://www.gorse.is/pricing

## Preview: a guard for AI coding agents

This download also contains a guard that checks each command an AI coding
agent is about to run and refuses the ones that would send credentials off the
computer, read credential files into the conversation, destroy data, add
persistent access or switch the guard off. It is a preview: off until you turn
it on, not yet part of the supported product, and it can refuse a command you
meant to run. Turn it on with `gorse hook claude-code` or `gorse hook
gemini`, and off with `gorse uninstall`. Details are at
https://www.gorse.is/resources.

## Privacy

Scanning and the exposure report run on your computer and send nothing to us.
Verify talks directly to your own providers, only when you run it. Team
reports and optional support uploads contain fingerprints and metadata, never
the secret values themselves. Buying, activating and renewing a licence uses
the network. The apps, and `gorse version` and `gorse status` when run
in a terminal, ask gorse.is once a day whether a newer version exists; that
request carries only the version number. Set `GORSE_NO_UPDATE_CHECK=1` to
stop it. The exposure check and the scans never use the network.

## Licence

The LICENSE file beside this one is the end user licence agreement; using the
software means accepting it. LICENSE-THIRD-PARTY lists the open-source
components it is built with. Purchases, renewals and refunds are covered by
the Terms of Service at https://www.gorse.is/terms, and personal data by
the privacy policy at https://www.gorse.is/privacy.

## Support

Email support@gorse.is or visit https://www.gorse.is/support.

Gorse by QKey Co.
