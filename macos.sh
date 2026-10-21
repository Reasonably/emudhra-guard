#!/bin/bash
# SPDX-License-Identifier: MIT
set -euo pipefail
export LC_ALL=C
umask 077

DATA_SHA256=55BC7E540EA13BF8614F473E4E6A475C990F596EFD3E8820B4E6CD52A8D759BA
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA="$SCRIPT_DIR/data/certificates.tsv"

fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
security_cmd() { /usr/bin/security "$@"; }
settings_cmd() {
    local command="$1"; shift
    if [[ "$SCOPE" == system ]]; then security_cmd "$command" -d "$@"; else security_cmd "$command" "$@"; fi
}
digest() { /usr/bin/openssl dgst "-$1" "$2" | /usr/bin/awk '{print toupper($NF)}'; }
rows() { /usr/bin/tail -n +2 "$DATA"; }

load_certificates() {
    [[ "$(digest sha256 "$DATA")" == "$DATA_SHA256" ]] || fail 'Certificate data checksum mismatch.'
    local sha256 sha1 name encoded count=0
    while IFS=$'\t' read -r sha256 sha1 name encoded; do
        [[ "$sha256" =~ ^[A-F0-9]{64}$ && "$sha1" =~ ^[A-F0-9]{40}$ ]] || fail 'Invalid fingerprint.'
        printf '%s' "$encoded" | /usr/bin/base64 -D > "$WORK/$sha256.der"
        [[ "$(digest sha256 "$WORK/$sha256.der")" == "$sha256" ]] || fail "SHA-256 mismatch: $name"
        [[ "$(digest sha1 "$WORK/$sha256.der")" == "$sha1" ]] || fail "SHA-1 mismatch: $name"
        /usr/bin/openssl x509 -inform DER -in "$WORK/$sha256.der" -out "$WORK/$sha256.pem"
        count=$((count + 1))
    done < <(rows)
    [[ "$count" == 23 ]] || fail 'Expected 23 certificates.'
}

export_settings() {
    local destination="$1"
    if ! settings_cmd trust-settings-export "$destination" > "$WORK/export.log" 2>&1; then
        if /usr/bin/grep -Eq 'No Trust Settings were found|errSecNoTrustSettings|\(-25263\)' "$WORK/export.log"; then
            printf '%s\n' '<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>trustVersion</key><integer>1</integer><key>trustList</key><dict/></dict></plist>' > "$destination"
        else
            /bin/cat "$WORK/export.log" >&2
            fail 'Cannot read trust settings; no changes made.'
        fi
    fi
    /usr/bin/plutil -lint "$destination" > /dev/null
}

is_denied() {
    local settings
    settings="$(/usr/bin/plutil -extract "trustList.$2.trustSettings" json -o - "$1" 2>/dev/null)" || return 1
    [[ "$(printf '%s' "$settings" | /usr/bin/tr -d '[:space:]')" == '[{"kSecTrustSettingsResult":3}]' ]]
}

inventory() {
    local result=0
    security_cmd find-certificate -a -Z "$KEYCHAIN" > "$WORK/inventory.txt" 2> "$WORK/inventory.log" || result=$?
    if [[ "$result" != 0 && "$result" != 44 ]]; then
        /bin/cat "$WORK/inventory.log" >&2
        fail 'Cannot read the target keychain.'
    fi
}

has_certificate() {
    /usr/bin/grep -Fqx "SHA-256 hash: $1" "$WORK/inventory.txt"
}

check() {
    export_settings "$WORK/check.plist"
    inventory
    local sha256 sha1 name encoded status count=0
    printf 'Scope: %s | Keychain: %s\n' "$SCOPE" "$KEYCHAIN"
    while IFS=$'\t' read -r sha256 sha1 name encoded; do
        status=NOT_CONFIGURED
        if is_denied "$WORK/check.plist" "$sha1"; then
            status=DENY_WITHOUT_LOCAL_COPY
            if has_certificate "$sha256"; then status=DENY; count=$((count + 1)); fi
        fi
        printf '%-25s %s\n' "$status" "$name"
    done < <(rows)
    printf 'Explicit local blocks: %s/23. NOT_CONFIGURED is not a vulnerability verdict.\n' "$count"
    [[ "$count" == 23 ]] || return 2
}

unchanged_since() {
    export_settings "$WORK/latest.plist"
    # Abort on any difference rather than overwrite concurrent trust changes.
    /usr/bin/cmp -s "$1" "$WORK/latest.plist" || fail 'Trust settings changed during this run. Rerun after other certificate changes finish.'
}

block() {
    export_settings "$WORK/before.plist"
    inventory
    local sha256 sha1 name encoded backup
    local missing=()
    : > "$WORK/changed-sha1.txt"
    while IFS=$'\t' read -r sha256 sha1 name encoded; do
        if ! is_denied "$WORK/before.plist" "$sha1"; then printf '%s\n' "$sha1" >> "$WORK/changed-sha1.txt"; fi
        if ! has_certificate "$sha256"; then missing+=("$WORK/$sha256.pem"); fi
    done < <(rows)
    if [[ ! -s "$WORK/changed-sha1.txt" && "${#missing[@]}" == 0 ]]; then
        printf 'Already blocked. No changes made.\n'
        return
    fi
    /bin/mkdir -p "$STATE_HOME/Library/Application Support/emudhra-guard/backups"
    backup="$(/usr/bin/mktemp -d "$STATE_HOME/Library/Application Support/emudhra-guard/backups/$(/bin/date +%Y%m%d-%H%M%S).XXXXXX")"
    /bin/cp "$WORK/before.plist" "$backup/trust-before.plist"
    /bin/cp "$WORK/changed-sha1.txt" "$backup/changed-sha1.txt"
    printf '%s\n' "$SCOPE" > "$backup/scope.txt"
    printf '%s\n' "$KEYCHAIN" > "$backup/keychain.txt"
    printf '%s\n' "$DATA_SHA256" > "$backup/data-sha256.txt"
    printf 'Backup: %s\n' "$backup"
    /bin/cp "$WORK/before.plist" "$WORK/planned.plist"
    while IFS=$'\t' read -r sha256 sha1 name encoded; do
        if /usr/bin/grep -Fqx "$sha1" "$WORK/changed-sha1.txt"; then
            security_cmd add-trusted-cert -r deny -i "$WORK/planned.plist" -o "$WORK/planned-next.plist" "$WORK/$sha256.pem" > /dev/null || fail 'Could not prepare trust settings.'
            /bin/mv "$WORK/planned-next.plist" "$WORK/planned.plist"
        fi
    done < <(rows)
    if [[ "${#missing[@]}" != 0 ]]; then security_cmd add-certificates -k "$KEYCHAIN" "${missing[@]}" || fail 'Could not add certificate copies; use the printed backup for recovery.'; fi
    unchanged_since "$WORK/before.plist"
    if [[ -s "$WORK/changed-sha1.txt" ]]; then
        settings_cmd trust-settings-import "$WORK/planned.plist" || fail 'Trust import failed or was cancelled; use the printed backup for recovery.'
    fi
    check || fail 'Block verification failed; use the printed backup for recovery.'
    printf 'Restart browsers to refresh cached trust decisions.\n'
}

same_entry() {
    local first=0 second=0
    /usr/bin/plutil -extract "trustList.$3" xml1 -o "$WORK/first-entry.plist" "$1" 2>/dev/null || first=$?
    /usr/bin/plutil -extract "trustList.$3" xml1 -o "$WORK/second-entry.plist" "$2" 2>/dev/null || second=$?
    if [[ "$first" != 0 && "$second" != 0 ]]; then return 0; fi
    [[ "$first" == 0 && "$second" == 0 ]] && /usr/bin/cmp -s "$WORK/first-entry.plist" "$WORK/second-entry.plist"
}

restore() {
    local backup="$1" sha1 entry count=0
    [[ "$(/bin/cat "$backup/data-sha256.txt")" == "$DATA_SHA256" ]] || fail 'Backup belongs to a different certificate list.'
    [[ "$(/bin/cat "$backup/keychain.txt")" == "$KEYCHAIN" ]] || fail 'Backup keychain differs from this account.'
    /usr/bin/plutil -lint "$backup/trust-before.plist" > /dev/null
    export_settings "$WORK/before-restore.plist"
    /bin/cp "$WORK/before-restore.plist" "$WORK/restored.plist"
    while IFS= read -r sha1; do
        rows | /usr/bin/awk -F '\t' '{print $2}' | /usr/bin/grep -Fqx "$sha1" || fail 'Backup contains an unknown certificate.'
        if same_entry "$backup/trust-before.plist" "$WORK/before-restore.plist" "$sha1"; then continue; fi
        is_denied "$WORK/before-restore.plist" "$sha1" || fail 'A target was changed after blocking. Refusing to overwrite its newer settings.'
        if /usr/bin/plutil -extract "trustList.$sha1" xml1 -o "$WORK/original-entry.plist" "$backup/trust-before.plist" 2>/dev/null; then
            entry="$(/bin/cat "$WORK/original-entry.plist")"
            /usr/bin/plutil -replace "trustList.$sha1" -xml "$entry" "$WORK/restored.plist"
        else
            /usr/bin/plutil -remove "trustList.$sha1" "$WORK/restored.plist"
        fi
        count=$((count + 1))
    done < "$backup/changed-sha1.txt"
    if [[ "$count" == 0 ]]; then printf 'Already restored. No changes made.\n'; return; fi
    unchanged_since "$WORK/before-restore.plist"
    settings_cmd trust-settings-import "$WORK/restored.plist" || fail 'Restore failed or was cancelled.'
    export_settings "$WORK/after-restore.plist"
    while IFS= read -r sha1; do
        same_entry "$backup/trust-before.plist" "$WORK/after-restore.plist" "$sha1" || fail 'Restore verification failed.'
    done < "$backup/changed-sha1.txt"
    printf 'Restored %s trust entries; unrelated settings and public certificate copies were retained.\n' "$count"
}

main() {
    local action="${1:-check}" backup=''
    SCOPE=user
    if [[ "$action" == --help || "$action" == -h ]]; then
        printf 'Usage: bash macos.sh [check|block] [--system]\n       bash macos.sh restore BACKUP_DIRECTORY\n'
        return
    fi
    case "$action" in
        check|block)
            [[ "$#" -le 2 ]] || fail 'Too many arguments.'
            if [[ "$#" == 2 ]]; then [[ "$2" == --system ]] || fail 'Unknown option.'; SCOPE=system; fi ;;
        restore)
            [[ "$#" == 2 && -d "$2" ]] || fail 'Provide a backup directory.'
            backup="$2"; SCOPE="$(/bin/cat "$backup/scope.txt")" ;;
        *) fail 'Expected check, block, or restore.' ;;
    esac
    [[ "$(/usr/bin/uname -s)" == Darwin ]] || fail 'This script requires macOS.'
    [[ "$SCOPE" == user || "$SCOPE" == system ]] || fail 'Invalid scope.'
    STATE_HOME="$HOME"
    if [[ "$SCOPE" == system ]]; then
        KEYCHAIN=/Library/Keychains/System.keychain
        if [[ "$action" != check && "$EUID" != 0 ]]; then fail 'System changes require sudo.'; fi
        if [[ "$EUID" == 0 ]]; then STATE_HOME=/var/root; fi
    else
        [[ "$EUID" != 0 ]] || fail 'Do not use sudo for current-user scope; use --system.'
        KEYCHAIN="$(security_cmd default-keychain -d user | /usr/bin/sed 's/^[[:space:]]*"//;s/"[[:space:]]*$//')"
        [[ -f "$KEYCHAIN" ]] || fail 'No readable default keychain.'
    fi
    /bin/mkdir -p "$STATE_HOME/Library/Caches/emudhra-guard"
    WORK="$(/usr/bin/mktemp -d "$STATE_HOME/Library/Caches/emudhra-guard/run.XXXXXX")"
    trap '/bin/rm -rf -- "$WORK"' EXIT
    load_certificates
    case "$action" in check) check ;; block) block ;; restore) restore "$backup" ;; esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then main "$@"; fi
