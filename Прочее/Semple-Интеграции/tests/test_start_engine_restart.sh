#!/usr/bin/env bash
#
# Цільова перевірка двох речей, які start.sh робив неправильно:
#
#   1. `ensure_engine` перебудовував бінарник тільки після раннього
#      виходу по `/health`, тож на живому стенді перебудова була
#      недосяжна: єдиний спосіб її отримати — вбити рушій.
#   2. Перезапустити один сервіс було неможливо: `--restart` гасив
#      увесь стенд.
#
# Тест працює на витягнутих із start.sh функціях і підставних командах,
# тому він нічого не зупиняє і нічого не збирає.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp_dir="$(mktemp -d)"
trap 'rm -rf -- "$tmp_dir"' EXIT

# ───────────────────────────── Витягнути функції ─────────────────────────────

# Дужки в ERE — метасимволи, тому `()` у шаблоні не збігся б як літерали.
# Звіряємося точним початком рядка через index(), а не через ~.
extract() { # extract <ім'я> <файл-призначення>
  awk -v want="$1() {" '
    index($0, want) == 1 { inside = 1 }
    inside { print }
    inside && /^}$/ { exit }
  ' "$repo_root/start.sh" >"$2"
}

extract build_engine_binary "$tmp_dir/build.sh"
extract engine_running_but_stale "$tmp_dir/stale.sh"
extract ensure_engine "$tmp_dir/ensure.sh"
extract restart_engine "$tmp_dir/restart.sh"
# `state_record` береться справжня, а не підстава: assertion у кінці
# перевіряє, що перезапущений engine потрапив у файл стану, і підстава
# довела б лише те, що її викликав сам тест.
extract state_record "$tmp_dir/state_record.sh"

for f in build stale ensure restart state_record; do
  if [ ! -s "$tmp_dir/$f.sh" ]; then
    printf 'FAIL: не знайдено функцію у start.sh (%s)\n' "$f" >&2
    exit 1
  fi
done

step() { :; }
info() { printf '%s\n' "$*"; }
ok()   { printf '%s\n' "$*"; }
skip() { printf '%s\n' "$*"; }
warn() { printf '[WARN] %s\n' "$*" >&2; }
die()  { printf '[DIE] %s\n' "$*" >&2; exit 1; }

# Підставні `/proc`-читалки: реальний рушій тест не має права чіпати.
_proc_starttime() { printf '%s' "${TEST_STARTTIME:-}"; }
_proc_cmdline()    { printf 'engine'; }
_stop_signal()     { printf 'TERM'; }
http_ok()          { [ "${TEST_HEALTHY:-0}" = '1' ]; }
wait_for()         { return 0; }

STARTED_PIDS=()
STARTED_NAMES=()
# `register_pid` — справжня функція start.sh: її тіло і є «зареєструвати
# і запам'ятати». Підстава тут переписала б саму себе й довела б нічого
# про запис у файл стану.
register_pid() {
  STARTED_PIDS+=("$1")
  STARTED_NAMES+=("$2")
  state_record "$2" "$1"
}
_stop_tree() {
  printf '%s\n' "$1" >>"$TEST_STOPPED"
  return 0
}

export TEST_STOPPED="$tmp_dir/stopped"
: >"$TEST_STOPPED"

# Функції з start.sh у THIS оболонці: окремий тест-допоміжник перевіряє
# їх ізольовано, тут нам потрібні й змінні, які вони міняють.
# shellcheck source=/dev/null
. "$tmp_dir/build.sh"
# shellcheck source=/dev/null
. "$tmp_dir/stale.sh"
# shellcheck source=/dev/null
. "$tmp_dir/ensure.sh"
# shellcheck source=/dev/null
. "$tmp_dir/restart.sh"
# shellcheck source=/dev/null
. "$tmp_dir/state_record.sh"

# Каталог-подібник із двома «вихідниками» і керованим бінарником.
ENGINE_DIR="$tmp_dir/engine"
BIN_DIR="$tmp_dir/bin"
ENGINE_BINARY="$BIN_DIR/engine"
ENGINE_URL="http://127.0.0.1:59999"
ENGINE_PORT=59999
PROXY_PORT=59998
LOG_DIR="$tmp_dir/logs"
CA_DIR="$tmp_dir/ca"
STATE_FILE="$tmp_dir/stack.state"
mkdir -p "$ENGINE_DIR" "$BIN_DIR" "$LOG_DIR"
: >"$ENGINE_DIR/main.go"

# Складальник engine — підстава: рахуємо виклики й пишемо бінарник.
build_calls="$tmp_dir/build-calls"
: >"$build_calls"
go() {
  printf 'build\n' >>"$build_calls"
  printf '#!/bin/sh\n' >"$ENGINE_BINARY"
  chmod +x "$ENGINE_BINARY"
}

# ─────────────── 1. Порядок: перебудова ДО перевірки `/health` ───────────────
#
# Сценарій відтворює саме виміряний збій: engine живий, бінарник старший за
# вихідники. Очікуємо, що перебудова відбудеться, а оператор отримає
# вказівку на --restart-engine. До правки `build` не викликався взагалі.

printf '#!/bin/sh\n' >"$ENGINE_BINARY"
chmod +x "$ENGINE_BINARY"
# Вихідник новіший за бінарник. Час ставимо явно, а не через `sleep`:
# `-newer` порівнює mtime, і тест не повинен залежати від того, встигли ми
# перервати цикл часу.
touch -d '2020-01-01 00:00:00' "$ENGINE_BINARY"
: >"$ENGINE_DIR/main.go"

TEST_HEALTHY=1 TEST_STARTTIME=4242 ensure_engine

if ! grep -qx build "$build_calls"; then
  printf 'FAIL: engine живий, але перебудова не виконалась — це вихідний дефект\n' >&2
  exit 1
fi

# Повторний виклик із узгодженим бінарником не має перебудовувати нічого.
# Час модифікації ставимо явно: підставний `go` перезаписує бінарник, тож
# його mtime інакше залежав би від того, як довго тривав попередній крок.
: >"$build_calls"
touch -d '2030-01-01 00:00:00' "$ENGINE_BINARY"   # бінарник новіший за джерело
touch -d '2020-01-01 00:00:00' "$ENGINE_DIR/main.go"
TEST_HEALTHY=1 TEST_STARTTIME=4242 ensure_engine >/dev/null
if grep -qx build "$build_calls"; then
  printf 'FAIL: бінарник не застарілий, але перебудова все одно виконалась\n' >&2
  exit 1
fi

# ─────────────── 2. `engine_running_but_stale` розрізняє два стани ───────────────

# engine мертвий → «застарілий» бути не може.
TEST_HEALTHY=0 TEST_STARTTIME=4242 engine_running_but_stale && {
  printf 'FAIL: engine_running_but_stale вважає застарілим те, що не працює\n' >&2
  exit 1
}
# engine живий, джерело старше за бінарник → не застарілий.
TEST_HEALTHY=1 TEST_STARTTIME=4242 engine_running_but_stale && {
  printf 'FAIL: engine_running_but_stale вважає застарілим актуальний код\n' >&2
  exit 1
}
# engine живий, джерело новіше за бінарник → застарілий.
touch -d '2030-01-01 00:00:00' "$ENGINE_DIR/main.go"
touch -d '2020-01-01 00:00:00' "$ENGINE_BINARY"
TEST_HEALTHY=1 TEST_STARTTIME=4242 engine_running_but_stale || {
  printf 'FAIL: engine_running_but_stale не побачив розбіжності, яку сам же й створює\n' >&2
  exit 1
}

# ─────────────── 3. `--restart-engine` гасить лише наш engine ───────────────
#
# Три різні стани: наш живий процес, PID перероблений, запису немає.
# У жодному з них не можна вбити чужий PID — це межа AGENTS.md.

: >"$build_calls"
printf 'engine 777 4242 /bin/engine\n' >"$STATE_FILE"
printf 'engine\n' >"$ENGINE_BINARY"
chmod +x "$ENGINE_BINARY"
# Джерело старше за бінарник: перебудова не потрібна й не повинна
# виконуватись. Час ставимо явно, бо попередній блок лишив його в 2030.
touch -d '2030-01-01 00:00:00' "$ENGINE_BINARY"
touch -d '2020-01-01 00:00:00' "$ENGINE_DIR/main.go"

# Функцію викликаємо в поточній оболонці, а не через `bash -c`: нам
# потрібен результат `register_pid`, тобто змінна STARTED_NAMES.
# Вивід ховаємо в файл, бо блок запуску engine друкує рядки, а тест
# повинен читатись за assertion-ами, а не за журналом.
TEST_STARTTIME=4242 restart_engine >"$tmp_dir/restart-ours.out" 2>&1
cat "$tmp_dir/restart-ours.out"
if ! grep -qx 777 "$TEST_STOPPED"; then
  printf 'FAIL: --restart-engine не зупинив наш engine pid 777 (зупинено: %s)\n' "$(cat "$TEST_STOPPED")" >&2
  exit 1
fi

# Після перезапуску engine має бути записано заново, інакше наступний
# --stop не знатиме, що його гасити. Перевіряємо тут, одразу після
# успішного випадку: далі тест навмисно видаляє файл стану, і assertion
# наприкінці перевіряв би уже порожне місце.
if [ "${#STARTED_NAMES[@]}" -eq 0 ] || [ "${STARTED_NAMES[-1]}" != 'engine' ]; then
  printf 'FAIL: перезапущений engine не зареєстровано — наступний --stop його пропустить\n' >&2
  exit 1
fi
if ! grep -qx engine "$STATE_FILE"; then
  printf 'FAIL: у %s немає рядка engine після перезапуску\n' "$STATE_FILE" >&2
  exit 1
fi

# PID перероблений: starttime не збігається → зупиняти нічого не можна.
: >"$TEST_STOPPED"
printf 'engine 777 1111 /bin/engine\n' >"$STATE_FILE"
# starttime у /proc тепер інший (4242) — PID перероблений.
TEST_STARTTIME=9999 restart_engine >"$tmp_dir/restart-reused.out" 2>&1
if [ -s "$TEST_STOPPED" ]; then
  printf 'FAIL: --restart-engine зупинив PID із переробленим номером\n' >&2
  exit 1
fi
grep -Fq 'перероблено' "$tmp_dir/restart-reused.out"

# Запису про engine немає → нічого не зупиняємо.
: >"$TEST_STOPPED"
rm -f "$STATE_FILE"
TEST_STARTTIME=4242 restart_engine >"$tmp_dir/restart-norecord.out" 2>&1
if [ -s "$TEST_STOPPED" ]; then
  printf 'FAIL: --restart-engine зупинив процес без запису у файлі стану\n' >&2
  exit 1
fi
grep -Fq 'не записаний' "$tmp_dir/restart-norecord.out"

printf '%s\n' 'Engine restart/startup tests passed'