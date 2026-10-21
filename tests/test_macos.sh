#!/bin/bash
# Exercises native offline plist generation with a simulated writable keychain.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/macos.sh"
TEST_PARENT="$HOME/Library/Caches/emudhra-guard-tests"
/bin/mkdir -p "$TEST_PARENT"
WORK="$(/usr/bin/mktemp -d "$TEST_PARENT/test.XXXXXX")"
trap '/bin/rm -rf -- "$WORK"' EXIT
SCOPE=user
DOMAIN=()
KEYCHAIN="$WORK/mock keychain"
STATE_HOME="$WORK/state home"
load_certificates
MOCK_STORE="$WORK/mock-store.plist"
MOCK_INVENTORY="$WORK/mock-inventory.txt"
MOCK_IMPORTS="$WORK/imports.txt"
: > "$MOCK_IMPORTS"
printf '%s\n' '<?xml version="1.0"?><plist version="1.0"><dict><key>trustVersion</key><integer>1</integer><key>trustList</key><dict/></dict></plist>' > "$WORK/empty.plist"
first_sha="$(rows | /usr/bin/awk -F '\t' 'NR==1 {print $1}')"
second_sha="$(rows | /usr/bin/awk -F '\t' 'NR==2 {print $1}')"
second_sha1="$(rows | /usr/bin/awk -F '\t' 'NR==2 {print $2}')"
/usr/bin/security add-trusted-cert -r deny -i "$WORK/empty.plist" -o "$WORK/first.plist" "$WORK/$first_sha.pem" > /dev/null
/usr/bin/security add-trusted-cert -r trustRoot -i "$WORK/first.plist" -o "$WORK/second.plist" "$WORK/$second_sha.pem" > /dev/null
/usr/bin/security add-trusted-cert -r trustRoot -i "$WORK/second.plist" -o "$MOCK_STORE" "$ROOT/tests/unrelated.pem" > /dev/null
/bin/cp "$MOCK_STORE" "$WORK/original.plist"
printf 'SHA-256 hash: %s\n' "$first_sha" > "$MOCK_INVENTORY"

security_cmd() {
    local command="$1"; shift
    case "$command" in
        trust-settings-export) /bin/cp "$MOCK_STORE" "${@: -1}" ;;
        find-certificate) /bin/cat "$MOCK_INVENTORY" ;;
        add-trusted-cert) /usr/bin/security "$command" "$@" ;;
        add-certificates)
            shift 2
            local file sha
            for file in "$@"; do
                sha="$(/usr/bin/openssl x509 -in "$file" -outform DER | /usr/bin/openssl dgst -sha256 | /usr/bin/awk '{print toupper($NF)}')"
                printf 'SHA-256 hash: %s\n' "$sha" >> "$MOCK_INVENTORY"
            done ;;
        trust-settings-import)
            [[ "${MOCK_IMPORT_FAIL:-0}" != 1 ]] || return 1
            printf 'import\n' >> "$MOCK_IMPORTS"
            /bin/cp "${@: -1}" "$MOCK_STORE" ;;
        *) fail "Unexpected mocked command: $command" ;;
    esac
}

status=0
(check > "$WORK/check.log") || status=$?
[[ "$status" == 2 ]] && /usr/bin/cmp -s "$MOCK_STORE" "$WORK/original.plist"
[[ ! -s "$MOCK_IMPORTS" ]]
block > "$WORK/block.log"
backup="$(/usr/bin/sed -n 's/^Backup: //p' "$WORK/block.log")"
[[ -d "$backup" && "$(/usr/bin/wc -l < "$MOCK_IMPORTS" | /usr/bin/tr -d ' ')" == 1 ]]
check > "$WORK/after-check.log"
block > "$WORK/idempotent.log"
[[ "$(/usr/bin/wc -l < "$MOCK_IMPORTS" | /usr/bin/tr -d ' ')" == 1 ]]

# An unrelated trust change made after blocking must survive restore.
/usr/bin/security add-trusted-cert -r deny -i "$MOCK_STORE" -o "$WORK/edited.plist" "$ROOT/tests/unrelated.pem" > /dev/null
/bin/mv "$WORK/edited.plist" "$MOCK_STORE"
unrelated_sha1="$(/usr/bin/openssl x509 -in "$ROOT/tests/unrelated.pem" -outform DER | /usr/bin/openssl dgst -sha1 | /usr/bin/awk '{print toupper($NF)}')"
restore "$backup" > "$WORK/restore.log"
is_denied "$MOCK_STORE" "$unrelated_sha1"
while IFS=$'\t' read -r sha256 sha1 name encoded; do
    same_entry "$WORK/original.plist" "$MOCK_STORE" "$sha1"
done < <(rows)
restore "$backup" > "$WORK/idempotent-restore.log"

# New edits to a target and concurrent trust changes must stop the write.
block > "$WORK/block-again.log"
backup2="$(/usr/bin/sed -n 's/^Backup: //p' "$WORK/block-again.log")"
/usr/bin/security add-trusted-cert -r trustRoot -i "$MOCK_STORE" -o "$WORK/conflict.plist" "$WORK/$second_sha.pem" > /dev/null
/bin/mv "$WORK/conflict.plist" "$MOCK_STORE"
/bin/cp "$MOCK_STORE" "$WORK/conflict-before.plist"
if (restore "$backup2" > "$WORK/conflict.log" 2>&1); then fail 'Restore accepted a newer edit.'; fi
/usr/bin/cmp -s "$MOCK_STORE" "$WORK/conflict-before.plist"
if (unchanged_since "$WORK/original.plist" > /dev/null 2>&1); then fail 'Concurrent modification was ignored.'; fi

# A failed import still leaves a usable backup; no trust changes are reported.
MOCK_IMPORT_FAIL=1
/bin/cp "$WORK/original.plist" "$MOCK_STORE"
if (block > "$WORK/failed.log" 2>&1); then fail 'Import failure was ignored.'; fi
failed_backup="$(/usr/bin/sed -n 's/^Backup: //p' "$WORK/failed.log")"
[[ -f "$failed_backup/trust-before.plist" ]]
/usr/bin/cmp -s "$MOCK_STORE" "$WORK/original.plist"
MOCK_IMPORT_FAIL=0

/bin/cp "$DATA" "$WORK/corrupt.tsv"
printf 'corrupt\n' >> "$WORK/corrupt.tsv"
if (DATA="$WORK/corrupt.tsv"; load_certificates > /dev/null 2>&1); then fail 'Corrupt payload accepted.'; fi
printf 'PASS: read-only check, block, idempotency, selective restore, conflict, partial failure, payload validation.\n'
