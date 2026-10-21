# emudhra-guard

[English](README.md) | [한국어](README.ko.md)

A supplementary tool for inspecting and explicitly distrusting 23 eMudhra/emSign certificates on macOS and Windows. It is intended for environments where updates are difficult to apply or an explicit local block is required. It uses built-in operating system tools and requires no additional runtime or network access during execution.

## Update first

**Prefer vendor updates that address this incident before applying manual blocks.** Update the operating system, browser, CA bundle, or runtime that the application actually uses for TLS certificate verification. Confirm that the installed version includes the fix, and restart or redeploy the application if needed to load the updated trust data.

If those updates already reject the compromised certificates, additional manual distrust is not required for protection against this incident. Updating one CA bundle only protects applications that use that bundle; it does not update every trust store on the device.

Use this tool as a fallback when updates cannot be applied promptly, or when your environment requires explicit local distrust. It checks the manual block configuration, not whether vendor mitigations are installed. A `NOT_CONFIGURED` result therefore does not mean the application is vulnerable.

## Local blocking

The default action only inspects the local configuration. Servers can resend intermediate certificates, and root store updates can restore deleted certificates. To keep them blocked, the tool uses macOS `deny` settings or the Windows `Disallowed` store.

## Certificates and supported environments

The tool uses a fixed list verified on **2026-10-21**:

- Seven emSign roots: `Root CA G1/C1`, `ECC Root CA G3/C3`, `Root TLS CA G1/G3`, and `Root CS CA G3`.
- Eight intermediates associated with the incident, plus eight cross-signed certificates using the same keys.
- Certificates are matched by the SHA-256 fingerprint of their DER encoding. Both scripts also pin the SHA-256 checksum of the certificate data file.

The seven roots are part of this tool's blocking scope; this does not mean that all seven root private keys were compromised. The fixed list does not automatically discover new certificates or replace up-to-date revocation information.

| Operating system | Mechanism | Applies to |
| --- | --- | --- |
| macOS | Records `deny` in the default keychain and user trust settings, or in the System keychain and administrator trust settings. | Apps that use OS trust settings, Safari, and Chrome, Edge, and Chromium-based browsers that use local certificates. |
| Windows | Adds certificates to the `CurrentUser` or `LocalMachine` `Disallowed` store. | Apps that use the Windows trust store, Chrome, and Edge. |

The tool does not modify Firefox/NSS, Java trust stores, separate Python CA bundles, or certificate stores inside containers. Browsers configured to ignore local OS certificates require separate configuration. Restart browsers after blocking certificates. System scope does not audit explicit overrides made by other users or management policies.

## macOS

Uses Bash, `security`, `openssl`, and `plutil`, as provided by macOS.

```bash
git clone https://github.com/Reasonably/emudhra-guard.git "$HOME/workspace/emudhra-guard"

# Inspect the current account. Running without arguments also only inspects.
bash "$HOME/workspace/emudhra-guard/macos.sh" check

# Block for the current account. macOS may request authentication.
bash "$HOME/workspace/emudhra-guard/macos.sh" block

# Inspect system scope.
bash "$HOME/workspace/emudhra-guard/macos.sh" check --system

# Apply system-wide settings with administrator privileges.
sudo bash "$HOME/workspace/emudhra-guard/macos.sh" block --system
```

Backups are saved under `~/Library/Application Support/emudhra-guard/backups/` for user scope, or `/var/root/Library/Application Support/emudhra-guard/backups/` for system scope. The command prints the exact backup path.

```bash
# Replace BACKUP_DIRECTORY with the actual absolute path printed by the command.
bash "$HOME/workspace/emudhra-guard/macos.sh" restore /absolute/path/to/BACKUP_DIRECTORY

# Restore a system-scope backup.
sudo bash "$HOME/workspace/emudhra-guard/macos.sh" restore /var/root/Library/Application\ Support/emudhra-guard/backups/BACKUP_DIRECTORY
```

Restore reverts only the trust entries changed by that run. It preserves later changes to unrelated certificates and stops if a target certificate's trust settings have been edited separately. Public certificate copies added to the keychain remain; only their trust settings are restored.

## Windows

Requires Windows PowerShell 5.1 or later. Keep the `data` directory next to `windows.ps1` when cloning the repository or extracting the release ZIP.

```powershell
git clone https://github.com/Reasonably/emudhra-guard.git "$HOME\emudhra-guard"

# Inspect the current account.
& "$HOME\emudhra-guard\windows.ps1" -Action Check

# Block for the current account.
& "$HOME\emudhra-guard\windows.ps1" -Action Block

# Inspect machine scope.
& "$HOME\emudhra-guard\windows.ps1" -Action Check -Scope LocalMachine

# Run this command in an administrator PowerShell session.
& "$HOME\emudhra-guard\windows.ps1" -Action Block -Scope LocalMachine

# Use the actual backup file path printed by the command.
& "$HOME\emudhra-guard\windows.ps1" -Action Restore -BackupPath 'C:\absolute\path\to\backup.json'
```

If execution policy blocks the script, follow your organization's approval process. The tool does not change execution policy.

Backups are saved under `%LOCALAPPDATA%\emudhra-guard\backups` for user scope, or `%ProgramData%\emudhra-guard\backups` for machine scope. Restore uses the scope recorded in the backup and removes only the block entries added by that run. Pre-existing block entries are preserved.

## Results and recovery

- `DENY`: An explicit block exists in the selected scope. On macOS, the tool also checks for the local public certificate copy that browsers read.
- `DENY_WITHOUT_LOCAL_COPY`: macOS has a deny setting, but the selected keychain has no certificate copy. Run `block` to add it.
- `NOT_CONFIGURED`: No explicit block was found in the scope being inspected. The browser's own revocation list or other protections may already block the certificate; this status is not a vulnerability verdict.
- Exit code `0` means that all 23 certificates were explicitly blocked when inspected, or that the requested action completed. Exit code `2` means that inspection found entries without the required configuration. Exit code `1` indicates an error.

A backup is saved before changes are applied. Cancelled authentication or a failed operation is reported as a failure; use the printed backup path to restore settings. Avoid changing the same certificates with another tool at the same time. On macOS, the tool also checks for changes to the full trust settings immediately before importing, but the check and OS update are not protected by an atomic lock.

Restoring settings can return certificates to their default trust state. Blocking also affects legitimate websites and code signatures within the selected scope, so restore only when needed. Local backups may contain host or keychain information; do not publish them.

## Sources and verification

- [Mozilla incident report](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449)
- [Official emSign certificate repository](https://repository.emsign.com/)
- [Published cross-signed certificates](https://github.com/Fluepke/emudrahahahahaha)
- [Chromium's handling of OS trust settings](https://chromium.googlesource.com/chromium/src/+/main/net/data/ssl/chrome_root_store/faq.md)
- [Microsoft X509Store documentation](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509store)

Individual fingerprints and sources are listed in [data/provenance.json](data/provenance.json). No private keys are included.

Checks cover certificate fingerprints, read-only inspection, repeated execution, preservation of existing settings, selective restore, and rejection of tampered input. macOS tests use the OS's offline plist generation tools and a simulated store. Windows tests use a temporary user certificate store. Automated tests do not modify the real trust stores.

## License

The code is licensed under [MIT](LICENSE). Sources and fingerprints for the certificate data are recorded in the provenance list. Release ZIPs contain only code and public certificate data.
