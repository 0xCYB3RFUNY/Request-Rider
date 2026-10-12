#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp_dir="$(mktemp -d)"
trap 'rm -rf -- "$tmp_dir"' EXIT

awk '
  /^ensure_camoufox\(\) \{$/ { in_function = 1 }
  in_function { print }
  in_function && /^}$/ { exit }
' "$repo_root/start.sh" >"$tmp_dir/ensure_camoufox.sh"
grep -q '^ensure_camoufox() {$' "$tmp_dir/ensure_camoufox.sh"

source "$tmp_dir/ensure_camoufox.sh"

step() { :; }
info() { :; }
skip() { :; }
ok() { printf '%s\n' "$*"; }
warn() { printf '[WARN] %s\n' "$*" >&2; }
die() {
  printf '[DIE] %s\n' "$*" >&2
  exit 1
}

mkdir -p "$tmp_dir/venv/bin"
cat >"$tmp_dir/venv/bin/python" <<'PY'
#!/usr/bin/env bash
set -eu

printf '%s\n' "$*" >>"$CAMOUFOX_TEST_CALLS"

if [ "${1-}" = '-c' ]; then
  case "${2-}" in
    'import camoufox')
      [ -f "$CAMOUFOX_TEST_STATE/package" ]
      ;;
    *camoufox_path*)
      [ -f "$CAMOUFOX_TEST_STATE/browser" ]
      ;;
    *)
      printf 'Unexpected Python check: %s\n' "${2-}" >&2
      exit 64
      ;;
  esac
elif [ "${1-}" = '-m' ] && [ "${2-}" = 'pip' ]; then
  [ "${CAMOUFOX_TEST_FAIL_PIP:-0}" != 1 ] || exit 20
  touch "$CAMOUFOX_TEST_STATE/package"
elif [ "${1-}" = '-m' ] && [ "${2-}" = 'camoufox' ] && [ "${3-}" = 'sync' ]; then
  [ "${CAMOUFOX_TEST_FAIL_SYNC:-0}" != 1 ] || exit 21
  touch "$CAMOUFOX_TEST_STATE/synced"
elif [ "${1-}" = '-m' ] && [ "${2-}" = 'camoufox' ] && [ "${3-}" = 'fetch' ]; then
  [ "${CAMOUFOX_TEST_FAIL_FETCH:-0}" != 1 ] || exit 22
  [ -f "$CAMOUFOX_TEST_STATE/synced" ] || exit 23
  [ "${CAMOUFOX_TEST_SKIP_BROWSER:-0}" != 1 ] || exit 0
  touch "$CAMOUFOX_TEST_STATE/browser"
else
  printf 'Unexpected Python command: %s\n' "$*" >&2
  exit 64
fi
PY
chmod +x "$tmp_dir/venv/bin/python"

new_state="$tmp_dir/new"
mkdir -p "$new_state"
export WORKER_VENV_DIR="$tmp_dir/venv"
export CAMOUFOX_TEST_STATE="$new_state"
export CAMOUFOX_TEST_CALLS="$new_state/calls"
(ensure_camoufox) >"$new_state/output" 2>&1
grep -Fq -- '-m pip install --quiet --disable-pip-version-check camoufox==0.5.6' "$new_state/calls"
grep -Fq -- '-m camoufox sync' "$new_state/calls"
grep -Fq -- '-m camoufox fetch' "$new_state/calls"
grep -Fq -- 'Camoufox готовий' "$new_state/output"
test -f "$new_state/package"
test -f "$new_state/browser"

existing_state="$tmp_dir/existing"
mkdir -p "$existing_state"
touch "$existing_state/package" "$existing_state/browser"
export CAMOUFOX_TEST_STATE="$existing_state"
export CAMOUFOX_TEST_CALLS="$existing_state/calls"
(ensure_camoufox) >"$existing_state/output" 2>&1
! grep -Fq -- '-m pip install' "$existing_state/calls"
! grep -Fq -- '-m camoufox sync' "$existing_state/calls"
! grep -Fq -- '-m camoufox fetch' "$existing_state/calls"
grep -Fq -- 'Camoufox готовий' "$existing_state/output"

failure_state="$tmp_dir/fetch-failure"
mkdir -p "$failure_state"
touch "$failure_state/package"
export CAMOUFOX_TEST_STATE="$failure_state"
export CAMOUFOX_TEST_CALLS="$failure_state/calls"
export CAMOUFOX_TEST_FAIL_FETCH=1
unset CAMOUFOX_TEST_FAIL_PIP CAMOUFOX_TEST_FAIL_SYNC
(ensure_camoufox) >"$failure_state/output" 2>&1
grep -Fq -- 'не вдалося завантажити браузер Camoufox' "$failure_state/output"
! grep -Fq -- 'Camoufox готовий' "$failure_state/output"

package_failure_state="$tmp_dir/package-failure"
mkdir -p "$package_failure_state"
export CAMOUFOX_TEST_STATE="$package_failure_state"
export CAMOUFOX_TEST_CALLS="$package_failure_state/calls"
export CAMOUFOX_TEST_FAIL_PIP=1
(ensure_camoufox) >"$package_failure_state/output" 2>&1
grep -Fq -- 'пакет Camoufox не встановлено' "$package_failure_state/output"
! grep -Fq -- '-m camoufox sync' "$package_failure_state/calls"

sync_failure_state="$tmp_dir/sync-failure"
mkdir -p "$sync_failure_state"
touch "$sync_failure_state/package"
export CAMOUFOX_TEST_STATE="$sync_failure_state"
export CAMOUFOX_TEST_CALLS="$sync_failure_state/calls"
unset CAMOUFOX_TEST_FAIL_PIP CAMOUFOX_TEST_FAIL_FETCH
export CAMOUFOX_TEST_FAIL_SYNC=1
(ensure_camoufox) >"$sync_failure_state/output" 2>&1
grep -Fq -- 'не вдалося синхронізувати версії Camoufox' "$sync_failure_state/output"
! grep -Fq -- '-m camoufox fetch' "$sync_failure_state/calls"

verify_failure_state="$tmp_dir/verification-failure"
mkdir -p "$verify_failure_state"
touch "$verify_failure_state/package"
export CAMOUFOX_TEST_STATE="$verify_failure_state"
export CAMOUFOX_TEST_CALLS="$verify_failure_state/calls"
unset CAMOUFOX_TEST_FAIL_SYNC
export CAMOUFOX_TEST_SKIP_BROWSER=1
(ensure_camoufox) >"$verify_failure_state/output" 2>&1
grep -Fq -- 'fetch завершився без бінарника' "$verify_failure_state/output"
! grep -Fq -- 'Camoufox готовий' "$verify_failure_state/output"

printf '%s\n' 'Camoufox startup installation tests passed'
