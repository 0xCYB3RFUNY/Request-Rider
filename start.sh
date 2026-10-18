#!/usr/bin/env bash
#
# Request-Rider — єдиний скрипт запуску.
#
# Один файл робить те, що AGENTS.md описує як «Локальний запуск» плюс те,
# чого раніше не існувало: перевіряє кожну залежність і встановлює відсутню,
# піднімає весь стек нативними процесами, і — за `--check` — проганяє блок
# «Команды проверки».
#
#   ./start.sh             встановити чого бракує, підняти весь стек
#   ./start.sh --check     те саме + go test (-race), Django tests, node --check
#   ./start.sh --status    нічого не встановлювати, лише показати стан
#   ./start.sh --stop      зупинити те, що підняли попередні запуски цього скрипта
#   ./start.sh --restart   --stop, потім звичайний запуск
#   ./start.sh --restart-engine
#                         перебудувати engine, якщо вихідники новіші, і
#                         перезапустити ТІЛЬКИ рушій. web, postgres, redis
#                         і browser-worker лишаються ввімкненими.
#
# Навіщо окремий прапорець: зміни в engine не можуть підхопитися, поки
# працює процес зі старого бінарника, а `--restart` гасить увесь стек —
# разом із браузером, відкритими сесіями та довгим сканом. Виміряно
# 2026-10-06: engine жив із 13:53, бінарник зібрано 13:07, 31 вихідник
# новіший, і оператор бачив UI, зібраний до правок.
#
# `--stop` і `--restart` працюють не з пам'ятю процесу, а з файлом стану
# `data/stack.state`: попередній запуск міг завершитися разом із терміналом,
# і тоді ніхто не пам'ятає, які PID-и наші. Запис робиться на старті кожного
# процесу, а `--stop` гасить лише те, що записано **і** що досі має той самий
# starttime — перероблений PID не наш, а чужі процеси не записуються взагалі.
#
# Принцип «є на машині — йдемо до наступного рядка»: кожен крок спершу
# перевіряє, чи вже готово, і лише тоді встановлює. Нічого не ставиться
# двічі, тому повторний запуск нічого не ламає.
#
# Кожна змінна нижче перекривається зовнішнім оточенням, тому скрипт
# працює і на сусідньому стенді, не ламаючи його.

set -Eeuo pipefail

# Права на журнали: лише власник.
#
# Виміряно на цій машині: `umask` = 002, тому кожен журнал, створений перенаправленням
# `>>`, виходив з правами 0664 — тобто читається **будь-ким користувачем на машині**.
# `engine.log` серед них. Для інструмента, чий продукт — доказ, це не «дрібниця
# гігіени», а саме те, через що доказ не належить тому, хто його отримав.
#
# Ставиться до будь-якого створення файлів, бо `umask` діє на момент створення, а не
# постфактум: chmod після старту не допоможе файлу, який уже відкритий іншим процесом.
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Абсолютний шлях до цього файла. `drop_root_privileges` перезапускає
# скрипт після зниження прав, і йому треба знати, який саме файл
# перезапускати. Ім'я з `BASH_SOURCE[0]` тут не годиться: під `sudo
# ./start.sh` воно містить шлях, який не збігається з тим, під яким
# працює вже виконуваний процес, — і перезапуск пішов би не туди.
SELF_PATH="$ROOT_DIR/$(basename "${BASH_SOURCE[0]}")"

# ─────────────────────────── Конфігурація ───────────────────────────

RUN_CHECK=0
RUN_STATUS_ONLY=0
RUN_STOP_ONLY=0
RUN_RESTART=0
RUN_RESTART_ENGINE=0

for arg in "$@"; do
  case "$arg" in
    --check)   RUN_CHECK=1 ;;
    --status)  RUN_STATUS_ONLY=1 ;;
    --stop)    RUN_STOP_ONLY=1 ;;
    --restart) RUN_RESTART=1 ;;
    --restart-engine) RUN_RESTART_ENGINE=1 ;;
    -h|--help)
      # Друкуємо лише шапку-коментар над `set -Eeuo pipefail`, щоб
      # довідка не тягнула за собою весь код.
      sed -n '2,/^set -Eeuo/p' "${BASH_SOURCE[0]}" | sed '$d; s/^# \{0,1\}//'
      exit 0
      ;;
    *)
      printf 'start.sh: невідомий аргумент %s (див. --help)\n' "$arg" >&2
      exit 2
      ;;
  esac
done

# Порти. Типові значення незмінні, але змінні потрібні: :8000/:8081 часто
# зайняті іншим стендом, і тоді весь успішний старт падає на "address
# already in use" замість того, щоб піднятися на вільному порту.
export RUNSERVER_PORT="${RUNSERVER_PORT:-8000}"
export ENGINE_PORT="${ENGINE_PORT:-8081}"
export PROXY_PORT="${PROXY_PORT:-8080}"
export WORKER_PORT="${WORKER_PORT:-8090}"
export POSTGRES_PORT="${POSTGRES_PORT:-55433}"
export REDIS_PORT="${REDIS_PORT:-6379}"
export SOCKS_PORT="${SOCKS_PORT:-9050}"

export ENGINE_URL="${ENGINE_URL:-http://127.0.0.1:$ENGINE_PORT}"
export PASSIVE_PROXY_URL="${PASSIVE_PROXY_URL:-http://127.0.0.1:$PROXY_PORT}"
export BROWSER_WORKER_URL="${BROWSER_WORKER_URL:-http://127.0.0.1:$WORKER_PORT}"

export CA_DIR="${CA_DIR:-$ROOT_DIR/data/ca}"

# Дзеркала Go-модулів, через які крок 02 спробує завантажити залежності.
# Спершу йде те, що налаштовано в машині, далі відомі публічні: так
# сусідній стенд із власним проксі не зачіпається, а стандартний запас
# працює без ручного налаштування. Пробується по черзі, поки не
# спрацює хоч одне; див. пояснення в `ensure_go`.
# Третє дзеркало додане 2026-10-03 за виміром, а не за припущенням: на цій
# машині **кожен** `.zip` з `proxy.golang.org` доходить до редиректа на
# `storage.googleapis.com` і повертає 403 — перевірено і для
# `klauspost/compress@v1.18.2`, і для самого `nuclei/v3@v3.11.1`, тобто це
# не «важкий модуль», а весь zip-шлях проксі.
# `goproxy.cn` не рятує: `dial tcp: lookup goproxy.cn: server misbehaving`.
# `goproxy.io` теж 403. `proxy.golang.com.cn` на ті самі об'єкти віддає 200.
#
# GOSUMDB не змінюється (див. нижче): вміст модулів і далі перевіряється
# контрольними сумами, тож додається дзеркало, а не довіра.
export GOPROXY_MIRRORS="${GOPROXY_MIRRORS:-https://proxy.golang.org,direct https://goproxy.cn,direct https://proxy.golang.com.cn,direct}"

# PostgreSQL — єдина база застосунку. `web/core/settings.py` вимагає
# POSTGRES_HOST (або DATABASE_URL) вже на імпорті настроїв, тому значення
# треба задати до будь-якої команди Django. Пароля немає: локальний кластер
# слухає лише 127.0.0.1 з trust-автентифікацією.
export POSTGRES_HOST="${POSTGRES_HOST:-127.0.0.1}"
export POSTGRES_USER="${POSTGRES_USER:-$(id -un)}"
export POSTGRES_DB="${POSTGRES_DB:-requestrider}"
export POSTGRES_TEST_TEMPLATE="${POSTGRES_TEST_TEMPLATE:-requestrider_utf8_tmpl}"

# SECRET_KEY підписує session-cookie та CSRF-токени. Якщо змінну не задати,
# `web/core/settings.py` згенерує ключ і збереже його в `data/run/secret_key`
# (каталог у .gitignore), тож він переживає перезапуск і не потрапляє в git.
# Задавай RR_SECRET_KEY, якщо ключ тримаєш поза репозиторієм.
# RR_DEBUG лишається 0: з DEBUG=1 будь-який невідомий шлях друкує всю карту
# маршрутів (73 імені, `admin/` включно) у відповіді 404.
export RR_DEBUG="${RR_DEBUG:-0}"

# Redis — єдиний брокер (див. README «Automation / Workflows»).
export CELERY_BROKER_URL="${CELERY_BROKER_URL:-redis://127.0.0.1:$REDIS_PORT/0}"
export ENGINE_BROKER_URL="${ENGINE_BROKER_URL:-$CELERY_BROKER_URL}"

# Права запуску. Визначається тут, а викликається нижче — після
# власного визначення, але ДО першого запису на диск.
#
# Саме до генерації `data/run/broker_key`, бо вона першою пише на диск.
# Якби гвард стояв після неї, то на зламаному стенді (`data/` від root)
# звичайний запуск упав би на `mkdir -p` з `Permission denied`, і
# оператор бачив би помилку системи, а не пояснення скрипта.
# Виміряно 2026-10-11 на цій машині.
run_startup_privilege_guard() {
  drop_root_privileges "$@"
  check_no_root_owned_leftovers
}

# Внутрішніх HTTP-поверхонь (движок :8081, воркер :8090) більше не захищає
# спільний секрет: `RR_INTERNAL_API_KEY` / `X-RequestRider-Internal-Key` видалені
# наскрізь, ключ не генерується і не перевіряється. Причина — виміряний дефект:
# двигун, піднятий до сесії, жив на `/health` (endpoint за проектом без ключа), а
# `ensure_engine()` приймав його за свій і друкував «engine вже працює». Далі
# Django надсилав ключ своєї інсталяції, рушій порівнював його зі своїм
#_boot-time_ значенням і віддавав 403 FORBIDDEN_ORIGIN на кожен внутрішній
# виклик: стек працював наполовину, а рядок стану казав UP.
#
# Мережева межа не змінюється і не видаляється: движок і воркер і далі
# відмовляють binds на не-loopback адресу, а `Host` перевіряється на loopback
# (DNS-rebinding) — це не ключ, це географія процесу.

# Екзекутор графа workflow. Типовим є **процесний** runtime — це те, що
# README називає стандартом для локального запуску, і те, на якому написано
# весь тестовий набір. Тому обидва прапорці за замовчуванням вимкнені.
#
# Це не косметика. З прапорцями `=1` Django-тести йдуть брокерним шляхом,
# де publish відбувається в процесі, а результат приходить в інший
# (`consume_engine_results`), тож вузол отримує
# `EngineTaskDeferred: engine task ... is running outside the graph worker`.
# Виміряно 2026-09-29: 463 тести, 58 errors і 3 failures з прапорцями
# проти тих самих 463, що дають `OK (skipped=1)` без них.
export WORKFLOW_CELERY_ENABLED="${WORKFLOW_CELERY_ENABLED:-0}"
export WORKFLOW_ENGINE_BROKER_ENABLED="${WORKFLOW_ENGINE_BROKER_ENABLED:-0}"

# Брокерний шлях тягне за собою Celery worker і споживача результатів.
# Якщо прапорці вимкнені, ці процеси не піднімаються: worker, який не
# споживає жодного workflow, — це «живий мусор», а не «повністю
# автоматичний запуск».
_broker_path_enabled() {
  case "$(printf '%s' "${WORKFLOW_CELERY_ENABLED}${WORKFLOW_ENGINE_BROKER_ENABLED}" | tr 'A-Z' 'a-z')" in
    *1*|*true*|*yes*|*on*) return 0 ;;
  esac
  return 1
}

WEB_DIR="$ROOT_DIR/web"
WORKER_DIR="$ROOT_DIR/browser-worker"
ENGINE_DIR="$ROOT_DIR/engine"
BIN_DIR="$ROOT_DIR/bin"
# Один шлях до бінарника, а не два рядки з нього: `ensure_engine` і
# `build_engine_binary` мають говорити про той самий файл, інакше
# перевірка «вихідники новіші» дивилася б на один шлях, а запускали б з
# іншого.
ENGINE_BINARY="$BIN_DIR/engine"
VENV_DIR="$WEB_DIR/.venv"
WORKER_VENV_DIR="$WORKER_DIR/.venv"
DATA_DIR="$ROOT_DIR/data"
LOG_DIR="$DATA_DIR/logs"
PGDATA="$DATA_DIR/pg"
REDIS_DIR="$DATA_DIR/redis"

# Файл стану стеку. Тут, а не в data/logs, бо журнали читає людина, а цей
# файл читає скрипт; і не в data/run, бо там unix-сокети PostgreSQL, який
# скрипт створює з chmod 777.
STATE_FILE="$DATA_DIR/stack.state"

# Тримаємо PID'и того, що підняли самі. Те, що вже працювало до нас, не
# чіпаємо ні в trap, ні деінде: чужий стенд — не наша справа.
STARTED_PIDS=()
STARTED_NAMES=()

# ───────────────────────────── Оформлення ───────────────────────────

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  C_DIM=$'\033[2m'; C_OK=$'\033[32m'; C_WARN=$'\033[33m'
  C_ERR=$'\033[31m'; C_STEP=$'\033[36m'; C_OFF=$'\033[0m'
else
  C_DIM=''; C_OK=''; C_WARN=''; C_ERR=''; C_STEP=''; C_OFF=''
fi

STEP_NO=0
step()  { STEP_NO=$((STEP_NO + 1)); printf '\n%s[%02d] %s%s\n' "$C_STEP" "$STEP_NO" "$1" "$C_OFF"; }
info()  { printf '      %s\n' "$1"; }
ok()    { printf '      %s✓%s %s\n' "$C_OK" "$C_OFF" "$1"; }
skip()  { printf '      %s· %s%s\n' "$C_DIM" "$1" "$C_OFF"; }
warn()  { printf '      %s! %s%s\n' "$C_WARN" "$1" "$C_OFF"; }
die()   { printf '\n%s✗ %s%s\n\n' "$C_ERR" "$1" "$C_OFF" >&2; exit 1; }

have_cmd() { command -v "$1" >/dev/null 2>&1; }

# `sudo` тільки коли ми не root. Один раз, щоб не перепитувати на кожному
# кроці: якщо пароль не введено, перший же виклик зупинить скрипт.
SUDO=''
if [ "$(id -u)" -ne 0 ]; then
  if have_cmd sudo; then
    SUDO='sudo'
  else
    die 'Потрібен root або sudo для встановлення системних пакетів.'
  fi
fi

# ────────────────────────── Права запуску: не root ──────────────────────────
#
# `sudo ./start.sh` ламає стенд, і це виміряно 2026-10-11 на цій машині.
# Причина одна: скрипт створює свої артефакти від того, хто його запустив,
# а `sudo` робить цим «хто» root. Виміряні наслідки:
#
#   * `web/.venv` і `browser-worker/.venv` виходять `root:root 0700`, і
#     наступний звичайний запуск не може навіть прочитати
#     `web/.venv/bin/python` — `Permission denied`;
#   * `data/` — те саме, а в ньому кластер PostgreSQL, журнали й файл
#     стану, з яким працює `--stop`;
#   * Firefox з `PLAYWRIGHT_BROWSERS_PATH=$HOME/.cache/ms-playwright`
#     їде в `/root/.cache/ms-playwright`, недоступний звичайному
#     користувачу;
#   * сам Firefox під root не піднімається: `firefox_launch_ok` повертає
#     `TargetClosedError: Target page, context or browser has been
#     closed`. Той самий браузер v1490 і той самий Playwright 1.55.0
#     запускаються без помилки від звичайного користувача на цій самій
#     машині (`LAUNCH_OK`), тож справа не в збірці і не в системних
#     бібліотеках, а в тому, від кого її запущено.
#
# Тому скрипт сам знижує права до того, хто його викликав, і перезапускається
# від нього. Права, потрібні для `apt-get` і для CA в системних коренях, не
# втрачаються: `SUDO` вище працює як і раніше, це вже зроблено.

# Користувач, від імені якого має жити стенд. `SUDO_USER` — той, хто
# викликав `sudo`; коли його немає (root-сесія без sudo), власник
# репозиторію: стенд живе в його каталозі, і жоден інший не є «тим
# користувачем» правильніше.
resolve_stack_user() {
  local candidate="${SUDO_USER:-}"

  if [ -z "$candidate" ] || [ "$candidate" = "$(id -un)" ]; then
    candidate="$(stat -c '%U' "$ROOT_DIR" 2>/dev/null || true)"
  fi

  # Порожньо або root — немає кого понизити до. Перевіряємо, що користувач
  # реально існує: `SUDO_USER` може бути stale, і тоді `setpriv` упав би з
  # `invalid user`, тобто стенд не піднявся б з помилкою в один рядок.
  [ -n "$candidate" ] && [ "$candidate" != "root" ] || return 1
  id -u "$candidate" >/dev/null 2>&1 || return 1

  printf '%s\n' "$candidate"
}

# Права, які залишив на артефактах скрипта попередній запуск від root.
#
# Перелік закритий: тільки ті шляхи, які створює сам скрипт. Усе інше в
# репозиторії — не наша справа («Границя моєї роботи» в AGENTS.md).
#
# Кеш браузерів не `chown`, а переносимо: `/root/.cache/ms-playwright` —
# це 96 MiB, і перекачавання з CDN знову того ж самого браузера займе
# хвилини без жодної користі для оператора. Якщо в користувача вже є
# власний кеш, root-івський просто лишається як є.
reclaim_root_owned_paths() {
  local target="$1"
  local browsers_root="${PLAYWRIGHT_BROWSERS_PATH:-$HOME/.cache/ms-playwright}"
  local target_home path

  target_home="$(getent passwd "$target" 2>/dev/null | cut -d: -f6 || true)"

  if [ -n "$target_home" ] && [ "$browsers_root" != "$target_home/.cache/ms-playwright" ] \
      && [ -d "$browsers_root" ] && [ ! -d "$target_home/.cache/ms-playwright" ]; then
    mkdir -p "$target_home/.cache" 2>/dev/null || true
    if mv "$browsers_root" "$target_home/.cache/ms-playwright" 2>/dev/null; then
      info "кеш браузерів перенесено з $browsers_root у $target_home/.cache/ms-playwright"
    else
      warn "кеш браузерів лишився в $browsers_root — браузер буде завантажено знову"
    fi
  fi

  for path in "$DATA_DIR" "$VENV_DIR" "$WORKER_VENV_DIR" "$BIN_DIR"; do
    [ -e "$path" ] || continue
    [ "$(stat -c '%U' "$path" 2>/dev/null || true)" = "root" ] || continue
    if chown -R "$target" "$path" 2>/dev/null; then
      info "права повернуто до $target: $path"
    else
      warn "не вдалося повернути права на $path — стенд може не піднятися"
    fi
  done
}

# Знизити права й перезапустити скрипт від звичайного користувача.
#
# `exec` — не підсилення: процес замінюється цілком, тому `trap`и,
# змінні й аргументи нижче виконуються вже від потрібного користувача,
# а не від root. Повторного входу в цю функцію не буде: після `setpriv`
# `id -u` уже не нуль.
drop_root_privileges() {
  [ "$(id -u)" -eq 0 ] || return 0

  local target
  if ! target="$(resolve_stack_user)"; then
    die 'запуск від root, але немає звичайного користувача, від якого продовжити.
    Запускайте без sudo: ./start.sh   (sudo всередині скрипт використовує сам)'
  fi

  reclaim_root_owned_paths "$target"

  local target_home
  target_home="$(getent passwd "$target" 2>/dev/null | cut -d: -f6 || true)"
  if [ -z "$target_home" ]; then
    die "не вдалося визначити домашній каталог користувача $target"
  fi

  info "запуск від root — продовжуємо від користувача $target"
  warn 'запускайте без sudo: ./start.sh   (sudo всередині скрипт використовує сам)'

  # `HOME` обовʼязково: інакше `PLAYWRIGHT_BROWSERS_PATH` залишився б
  # у `/root/.cache`, недоступному для $target. Решта оточення зберігається:
  # знижуємо права, а не переписуємо середовище.
  export HOME="$target_home"
  exec setpriv --reuid="$target" --regid="$target" --init-groups -- \
    env HOME="$target_home" \
    "$SELF_PATH" "$@"
}

# Каталоги, які залишилися від попереднього `sudo ./start.sh`.
#
# Гвард вище виправляє їх, але тільки коли сам скрипт запущено від root.
# Після того, як оператор перейде на `./start.sh` без sudo, права вже
# root, і звичайний запуск падає на першому ж `mkdir -p` з невнятним
# `Permission denied` — без жодної підказки, що робити.
#
# Виклик робить `run_startup_privilege_guard` вище — до генерації
# ключа брокера, бо вона першою пише на диск.
check_no_root_owned_leftovers() {
  [ "$(id -u)" -eq 0 ] && return 0

  local path blocked=0
  for path in "$DATA_DIR" "$VENV_DIR" "$WORKER_VENV_DIR" "$BIN_DIR"; do
    [ -e "$path" ] || continue
    [ "$(stat -c '%U' "$path" 2>/dev/null || true)" = "root" ] || continue
    blocked=1
  done

  [ "$blocked" -eq 0 ] && return 0

  die "каталоги стенду належать root — це наслідок попереднього 'sudo ./start.sh'.

    Виправте один раз:
      sudo ./start.sh --status
    Скрипт сам знизить права до $USER і продовжить. Після цього запускайте
    без sudo: ./start.sh"
}

# Виклик — тут, після визначень, але ДО генерації ключа брокера:
# `run_startup_privilege_guard` вище викликає обидві функції, які
# визначені нижче, тому сам виклик мусить стояти після них.
run_startup_privilege_guard "$@"

# Спільний ключ підпису конвертів брокера (Django <-> Go engine).
#
# Навіщо: брокер не має автентифікації — будь-який локальний процес може покласти
# у чергу коректний за формою конверт з чужим task_id, і він буде виконаний
# (задача) або просуне чужий workflow (результат). Підпис HMAC-SHA256 у полі `sig`
# доводить, хто написав конверт. Без ключа обидва боки працюють у режимі
# сумісності (нічого не підписується і не перевіряється) — з гучним попередженням
# у журналі, а не мовчки.
#
# Ключ генерується один раз на інсталяцію і лежить поруч із ключем підпису сесій
# (data/run/, 0600). Зовнішнє значення через оточення має пріоритет — так ключ
# переживає перевстановлення дерева і так його задають у docker-compose.
#
# Блок стоїть після гварда прав: він створює `data/run/`, тобто є
# першим записом у каталозі, який має належати звичайному користувачу.
if [ -z "${RR_ENGINE_BROKER_KEY:-}" ]; then
  _broker_key_file="$ROOT_DIR/data/run/broker_key"
  if [ -f "$_broker_key_file" ]; then
    RR_ENGINE_BROKER_KEY="$(cat "$_broker_key_file" 2>/dev/null)"
  else
    RR_ENGINE_BROKER_KEY="$(python3 -c 'import secrets;print(secrets.token_hex(32))' 2>/dev/null || openssl rand -hex 32 2>/dev/null || "")"
    if [ -n "$RR_ENGINE_BROKER_KEY" ]; then
      mkdir -p "$(dirname "$_broker_key_file")"
      printf '%s' "$RR_ENGINE_BROKER_KEY" >"$_broker_key_file"
      chmod 600 "$_broker_key_file"
    fi
  fi
  export RR_ENGINE_BROKER_KEY
fi

# ────────────────────────── Перевірки стану ─────────────────────────

# Порт зайнятий будь-ким — і нашою попередньою копією, і чужим процесом.
# Різниця не вгадується з порту, тому далі ми перевіряємо health-ендпоїнт.
port_open() { "$1" 2>/dev/null | grep -q .; }

http_ok() { curl -fsS --max-time 3 "$1" >/dev/null 2>&1; }

wait_for() {
  # wait_for <опис> <промпт-команда> [секунд]
  local what="$1" probe="$2" timeout="${3:-60}" waited=0
  while [ "$waited" -lt "$timeout" ]; do
    if eval "$probe" >/dev/null 2>&1; then return 0; fi
    sleep 1
    waited=$((waited + 1))
  done
  return 1
}

register_pid() {
  STARTED_PIDS+=("$1")
  STARTED_NAMES+=("$2")
  # Одночасно записуємо процес у файл стану: `Ctrl+C` гасить його через
  # trap, але термінал може закритися раніше, і тоді наступний запуск
  # не матиме жодного способу дізнатися, що engine — наш.
  state_record "$2" "$1"
}

# ───────────────────────── Файл стану стеку ───────────────────────────
#
# Рядок: `<ім'я> <pid> <starttime> <командний рядок>`.
#
# `starttime` — це те, що робить запис доказом, а не припущенням. PID
# перероблюється: 32768 живих процесів означає, що той самий номер
# щезав значно раніше, ніж помер процес, який ми записали. Порівняння
# з `comm` допомагає, але `comm` у `/proc/pid/stat` обрізається до 15
# символів, тому `python3.12` і `python3.11` дають однаковий рядок.
# `starttime` відрізняється завжди, коли відрізняється процес.

# Поле 22 у /proc/<pid>/stat — starttime. Щоб не зламатися на процесі,
# чиє comm містить пробіли або дужки, спершу відкидаємо префікс до
# останньої `) `, після чого starttime стає двадцятим полем.
_proc_starttime() {
  local stat
  stat="$(cat "/proc/$1/stat" 2>/dev/null)" || return 1
  [ -n "$stat" ] || return 1
  stat="${stat##*) }"
  awk '{ print $20 }' <<<"$stat"
}

_proc_cmdline() {
  tr '\0' ' ' <"/proc/$1/cmdline" 2>/dev/null | sed 's/ *$//'
}

# PID із pid-файлу. PostgreSQL, Redis і Tor демонізуються самі, тому
# `register_pid $!` для них не дає нічого: `$!` — це PID того, хто вже
# вийшов. Перший рядок pid-файлу — це справжній PID демона.
_pidfile_pid() {
  [ -s "$1" ] || return 1
  local pid
  read -r pid <"$1" || return 1
  case "$pid" in
    ''|*[!0-9]*) return 1 ;;
  esac
  printf '%s' "$pid"
}

# state_record <ім'я> <pid> — додати або оновити запис.
state_record() {
  local name="$1" pid="$2" stime cmdline tmp
  stime="$(_proc_starttime "$pid")" || return 0
  cmdline="$(_proc_cmdline "$pid")"

  mkdir -p "$(dirname "$STATE_FILE")"
  tmp="$(mktemp "$STATE_FILE.XXXXXX")" || return 0
  if [ -f "$STATE_FILE" ]; then
    # Перезапис рядка з тим самим іменем, а не додавання: сервіс, який
    # перезапустили, має один запис, інакше `--stop` гасив би PID-и
    # двох поколінь, з яких один уже не наш.
    grep -v "^$name[[:space:]]" "$STATE_FILE" >"$tmp" 2>/dev/null || true
  fi
  # Порядок рядків = порядок появи, тому `--stop` читає файл у зворотному
  # порядку і гасить залежні процеси раніше тих, від яких вони залежать.
  printf '%s %s %s %s\n' "$name" "$pid" "$stime" "$cmdline" >>"$tmp"
  mv -f "$tmp" "$STATE_FILE"
}

# state_forget <ім'я> — запис більше неактуальний (процес зупинено або
# помер сам).
state_forget() {
  [ -f "$STATE_FILE" ] || return 0
  local tmp
  tmp="$(mktemp "$STATE_FILE.XXXXXX")" || return 0
  grep -v "^$1[[:space:]]" "$STATE_FILE" >"$tmp" 2>/dev/null || true
  mv -f "$tmp" "$STATE_FILE"
}

# ───────────────────────────── Крок 0 ───────────────────────────────

print_banner() {
  printf '%s\n' "$C_DIM"
  printf '  Request-Rider · єдиний скрипт запуску\n'
  printf '  %s\n' "$C_OFF"
  printf '    web        http://127.0.0.1:%s\n' "$RUNSERVER_PORT"
  printf '    engine     %s\n' "$ENGINE_URL"
  printf '    proxy      %s\n' "$PASSIVE_PROXY_URL"
  printf '    worker     %s\n' "$BROWSER_WORKER_URL"
  printf '    postgres   %s:%s/%s\n' "$POSTGRES_HOST" "$POSTGRES_PORT" "$POSTGRES_DB"
  printf '    redis      %s\n' "$CELERY_BROKER_URL"
}

print_status() {
  printf '\n%-16s %-24s %s\n' 'СЕРВІС' 'АДРЕСА' 'СТАН'
  printf '%s\n' '--------------------------------------------------------------'

  # Рядок стану читається очима людини, тому він каже саме «живий/мертвий»,
  # а не «процес десь існує». Стан береться з того самого health-ендпоінта,
  # на якому крок запуску чекав готовності, тож таблиця не може
  # розійтися з тим, що скрипт щойно перевірив.
  #
  # _row приймає стан ТРЕТІМ аргументом і перевіряє саме його. Раніше
  # порівнювався другий, тобто адреса, тому будь-який живий сервіс
  # друкувався як DOWN — оператор бачив стек, який сам скрипт щойно
  # перевірив, і не міг йому повірити.
  _row() { # $1=ім'я  $2=адреса  $3=up|down
    if [ "$3" = up ]; then
      printf '%-16s %-24s %sUP%s\n' "$1" "$2" "$C_OK" "$C_OFF"
    else
      printf '%-16s %-24s %sDOWN%s\n' "$1" "$2" "$C_ERR" "$C_OFF"
    fi
  }

  local s
  s=down; http_ok "http://127.0.0.1:$RUNSERVER_PORT/" && s=up
  _row 'web' "127.0.0.1:$RUNSERVER_PORT" "$s"
  s=down; http_ok "$ENGINE_URL/health" && s=up
  _row 'engine' "127.0.0.1:$ENGINE_PORT" "$s"
  s=down; http_ok "$BROWSER_WORKER_URL/health" && s=up
  _row 'browser-worker' "127.0.0.1:$WORKER_PORT" "$s"
  s=down
  # `-d postgres`: іменує базу, яка точно є, щоб проба не іменувала `kali`.
  pg_isready -h 127.0.0.1 -p "$POSTGRES_PORT" -d postgres -q 2>/dev/null && s=up
  _row 'postgres' "127.0.0.1:$POSTGRES_PORT" "$s"
  s=down; redis-cli -p "$REDIS_PORT" ping >/dev/null 2>&1 && s=up
  _row 'redis' "127.0.0.1:$REDIS_PORT" "$s"

  # Що саме зможе зупинити `--stop`. Умова та сама, що й при зупинці:
  # процес знайдено **і** його starttime у /proc досі той самий.
  # Перелік береться з тієї самої функції, що й у `stop_stack`, інакше
  # таблиця могла б казати «контролю немає» про стек, який `--stop` зараз
  # зупинить.
  printf '\n'
  local owned='' name pid stime cmdline now_stime
  while read -r name pid stime cmdline; do
    [ -n "${name:-}" ] || continue
    now_stime="$(_proc_starttime "$pid" 2>/dev/null)" || now_stime=''
    [ -n "$now_stime" ] && [ "$now_stime" = "$stime" ] \
      && owned="$owned $name($pid)"
  done < <(owned_processes)
  if [ -n "$owned" ]; then
    printf '%-16s %-24s %s%s%s\n' 'контроль' "$STATE_FILE" "$C_OK" "$owned" "$C_OFF"
  else
    printf '%-16s %-24s %s%s%s\n' 'контроль' 'немає' "$C_DIM" 'жодного живого процесу' "$C_OFF"
  fi
  printf '\n'
}

# ─────────────────────────── Крок 1: пакети ──────────────────────────
#
# Тільки те, без чого застосунок не стартує. Docker навмисно не
# перевіряється: вибраний нативний режим, compose не бере участі.

ensure_packages() {
  step 'Системні пакети'

  # jq свідомо відсутній: скрипт не парсить JSON через зовнішній інструмент,
  # а ставити пакет, який не використовується, — це рівно той «мертвий
  # інструмент», який AGENTS.md забороняє лишати в репозиторії.
  local wanted=(
    'curl:curl'
    'git:git'
    'go:golang-go'
    'node:nodejs'
    'npm:npm'
    'psql:postgresql-client'
    'redis-cli:redis-tools'
    'redis-server:redis-server'
    'tor:tor'
  )

  local missing=() entry cmd pkg
  for entry in "${wanted[@]}"; do
    cmd="${entry%%:*}"
    pkg="${entry#*:}"
    if have_cmd "$cmd"; then
      skip "$cmd — встановлено"
    else
      missing+=("$pkg")
      info "$cmd — бракує ($pkg)"
    fi
  done

  # Сервер PostgreSQL перевіряється НЕ через `command -v pg_ctl`: на Debian
  # і Kali бінарники сервера живуть у /usr/lib/postgresql/<maj>/bin і не
  # потрапляють у PATH, тоді як пакет встановлено. Перевірка лише через
  # PATH змусила б щоразу ставити вже наявний postgresql.
  if find_pg_bin pg_ctl >/dev/null 2>&1 && find_pg_bin initdb >/dev/null 2>&1; then
    skip "PostgreSQL server — встановлено ($(find_pg_bin pg_ctl | xargs dirname))"
  else
    missing+=('postgresql')
    info 'PostgreSQL server (pg_ctl/initdb) — бракує (postgresql)'
  fi

  # python3 + venv: модуль venv не є окремою командою, тому перевіряється
  # спробою імпорту.
  if ! python3 -c 'import venv' >/dev/null 2>&1; then
    missing+=('python3-venv')
    info 'python3-venv — бракує'
  else
    skip 'python3 + venv — встановлено'
  fi

  if [ "${#missing[@]}" -eq 0 ]; then
    ok 'Усі системні пакети на місці'
    return 0
  fi

  # Пароль root не приймається з неінтерактивного входу, тож кажемо
  # одразу, що робити, замість падати на 'sudo: a password is required'
  # після довгої паузи вже всередині apt.
  if [ -n "$SUDO" ] && ! sudo -n true 2>/dev/null; then
    if [ -t 0 ]; then
      info 'потрібен пароль root — введіть його у запиті sudo'
    else
      printf '      бракує: %s\n' "${missing[*]}" >&2
      printf '      встановіть вручну:\n' >&2
      printf "        sudo apt-get install -y %s\n" "${missing[*]}" >&2
      printf '        sudo ./start.sh\n' >&2
      die 'без root неможливо встановити системні пакети (немає інтерактивного терміналу для пароля)'
    fi
  fi

  info "встановлюємо: ${missing[*]}"
  $SUDO apt-get update -qq
  # -y: скрипт має дійти до кінця сам. Інтерактивного підтвердження тут
  # немає, бо наступний рядок усе одно спирається на цей результат.
  #
  # `DEBIAN_FRONTEND` стоїть ПЕРЕД `$SUDO`, а не після: коли скрипт уже
  # root, `$SUDO` порожній, і в `$SUDO DEBIAN_FRONTEND=... apt-get` парсер
  # вважає `DEBIAN_FRONTEND=...` іменом команди — виходить
  # `command not found` (rc=127) і жоден пакет не ставиться. З перестановкою
  # рядок є перевизначенням змінної і однаково правий для `sudo` та для
  # прямого запуску від root.
  DEBIAN_FRONTEND=noninteractive $SUDO apt-get install -y -qq "${missing[@]}"

  for entry in "${wanted[@]}"; do
    have_cmd "${entry%%:*}" || die "${entry%%:*} не з'явився після встановлення ${entry#*:}"
  done
  find_pg_bin pg_ctl >/dev/null 2>&1 || die "pg_ctl не знайдено після встановлення postgresql"
  python3 -c 'import venv' || die 'python3-venv не імпортується після встановлення'
  ok 'Системні пакети встановлено'
}

# ─────────────────────── Крок 1b: CA у системних коренях ─────────────

ensure_ca_trusted() {
  # Пасивний проксі підписує відповіді власним CA, тому будь-який клієнт, що
  # йде через нього по HTTPS, має довіряти цьому CA. Firefox із Playwright —
  # клієнт, і він не читає `SSL_CERT_FILE`: у нього власне сховище NSS.
  # Виміряно 2026-10-02 без цього кроку: `data/logs/engine.log` містить
  # `Cannot read request from mitm'd client ...: tls: unknown certificate
  # authority`, тобто проксі писав попередження замість трафіку.
  #
  # CA додається, а не замінює системний bundle — інакше зникла б довіра до
  # звичайних публічних HTTPS-цілей, які є основною роботою інструмента.
  step 'CA у системних коренях'

  local crt="$CA_DIR/ca.crt" target='/usr/local/share/ca-certificates/requestrider-engine.crt'
  if [ ! -s "$crt" ]; then
    warn "CA не знайдено за $crt — рушій створить його при першому старті"
    return 0
  fi

  # Порівняння за вмістом, а не за датою: щоб повторний `./start.sh` не писав у
  # /usr/local/share/ca-certificates на кожному запуску й не перезапускав
  # `update-ca-certificates` без потреби.
  if [ -r "$target" ] && cmp -s "$crt" "$target"; then
    skip 'CA движка вже в системних коренях'
    return 0
  fi

  if [ ! -d /usr/local/share/ca-certificates ] || [ ! -w /usr/local/share/ca-certificates ]; then
    # Не падаємо: стенд працює і без цього, а крок лише прибирає попередження
    # в журналі движка. Тому — попередження і точна команда, як в ensure_packages.
    warn 'системні корені недоступні для запису (потрібен root). Встановіть вручну:'
    warn "  sudo cp '$crt' '$target'"
    warn '  sudo update-ca-certificates'
    return 0
  fi

  cp "$crt" "$target" || { warn "не вдалося скопіювати CA у $target"; return 0; }
  if update-ca-certificates >/dev/null 2>&1; then
    ok "CA движка додано в системні корені: $target"
  else
    warn "CA скопійовано, але update-ca-certificates не відпрацював; перевірте вручну: sudo update-ca-certificates"
  fi
}

# ─────────────────────────── Крок 2: Go ─────────────────────────────

ensure_go() {
  step 'Go-інструменти'
  if ! have_cmd go; then die 'go не знайдено після встановлення пакетів'; fi

  local version
  version="$(go env GOVERSION 2>/dev/null || echo unknown)"
  info "go $version"

  # Модулі движка живуть у GOMODCACHE, і перше завантаження триває
  # хвилинами. Качаємо їх тут, до старту, щоб перший запит до engine не
  # чекав на мережу.
  #
  # Ланцюг дзеркал, а не один проксі. Виміряно 2026-09-30 на цій машині,
  # по кожному об'єкту окремо, бо перша версія цього пояснення була
  # неправильною — вона стверджувала, що проксі заблокований за регіоном:
  #
  #   nuclei/v3.11.1.info        200      201 байт
  #   nuclei/v3.11.1.mod         200   21 469 байт
  #   nuclei/v3.11.1.zip         403      193 байт   ← AccessDenied,
  #                                     «not available in your location»
  #   pkg/errors v0.9.1.zip      200   17 866 байт
  #   logrus v1.9.4.zip          200   70 579 байт
  #   rsc.io/quote v1.5.2.zip    200    2 987 байт
  #   nuclei/v3.11.1.zip через goproxy.cn
  #                            200  13 242 544 байт
  #
  # Отже блокування не загальне для проксі: `.info` і `.mod` того самого
  # модуля проходять, а zip ні. Розбіжність збігається з розміром — 12.6 МБ
  # відмовлено, до 70 КБ проходять, — тобто це ліміт сховища, а не вибір
  # модуля. Які саме об'єкти зачепить, заздалегідь не знаємо: один
  # відмовлений zip роняє `go build` усього движка, а ланцюг дзеркал
  # переносить це на «спробуй наступне» замість на «стек не підніметься».
  #
  # GOSUMDB не змінюється. `sum.golang.org` відповідає 200, тобто перевірка
  # контрольних сум доступна, і `GOSUMDB=off` не потрібен: він вимкнув би
  # перевірку сум для модулів, яких ще немає в `go.sum`, тобто послабив би
  # ланцюг постачання заради зручності.
  #
  # GOPROXY_MIRRORS перекривається з оточення, тож сусідній стенд із
  # власним проксі працює без правки цього файлу.
  local mirror
  for mirror in $GOPROXY_MIRRORS; do
    info "завантажуємо Go-модулі через $mirror (кеш: $(go env GOMODCACHE))"
    if ( cd "$ENGINE_DIR" && GOPROXY="$mirror" go mod download all ) \
         >"$LOG_DIR/go-mod.log" 2>&1; then
      ok "Go готовий: модулі завантажено через $mirror"
      return 0
    fi
    warn "$mirror не спрацював; деталі в $LOG_DIR/go-mod.log"
  done
  warn 'жодне дзеркало GOPROXY не спрацювало — збереження engine покаже деталі'
}

# ────────────────────────── Крок 3: venv ─────────────────────────────

# Права на вже наявні журнали, створені до встановлення umask.
#
# `umask 077` вище діє лише на те, що створюється **після** нього. Журнал, який
# залишився від попереднього запуску, може мати старі права. Без цього кроку
# закріплення umask працювало б лише з наступного старту.
harden_service_log_permissions() {
  local hardened=0 file
  for file in "$LOG_DIR"/*.log; do
    [ -f "$file" ] || continue
    if chmod 0600 "$file" 2>/dev/null; then
      hardened=$((hardened + 1))
    fi
  done
  [ "$hardened" -gt 0 ] && info "права 0600 виставлено на $hardened журнал(ів)"
  return 0
}

# Права на секрети в `data/run` — на кожному старті, а не лише при створенні.
#
# `chmod 600` вище стоїть у гілці `else`, тобто виконується тільки коли файлу ще
# немає. Файл, який уже існує, просто читається (`if [ -f … ]; then cat`) і права
# з нього не знімаються — це той самий випадок, що `harden_service_log_permissions`
# лікує для журналів: `umask 077` діє лише на те, що створюється після нього.
#
# Виміряно 2026-10-03 на цьому дереві: `broker_key` мав `0660`, тобто його читала
# і перезаписувала вся група, поки `secret_key` і `compose.env` порядом були
# `0600`. Права прийшли разом із відновленням каталогу. `internal_key` у переліку
# більше немає: ключ видалено, тож файлу не існує.
#
# Перелік файлів явний, а не `chmod -R`, і це не педантизм: у `data/run` живуть
# pid-файли, сокети `.s.PGSQL.*`, а також `torrc` і `stand.route`, які належать
# іншим процесам (`root:docker`). Рекурсивний `chmod` або зламав би стенд, або
# змінив чужі файли — обидва вартості тут гірші за залишені права.
harden_run_secret_permissions() {
  local hardened=0 name file
  for name in broker_key secret_key compose.env; do
    file="$ROOT_DIR/data/run/$name"
    [ -f "$file" ] || continue
    # `chmod` без `-f` падає на файлі, який належить іншому користувачу, а
    # `set -e` перетворив би це на зупинку старту. Права, які не належать
    # цьому процесу, не наш секрет і не наша справа.
    if [ "$(stat -c '%a' "$file" 2>/dev/null)" != "600" ] && chmod 0600 "$file" 2>/dev/null; then
      hardened=$((hardened + 1))
    fi
  done
  [ "$hardened" -gt 0 ] && info "права 0600 виставлено на $hardened секрет(ів) у data/run"
  return 0
}

ensure_web_venv() {
  step 'Python-оточення web'
  mkdir -p "$LOG_DIR"
  local py_sys_ver py_venv_ver
  py_sys_ver="$(python3 -c 'import sys; print(sys.version_info[:2])' 2>/dev/null || true)"
  py_venv_ver="$("$VENV_DIR/bin/python" -c 'import sys; print(sys.version_info[:2])' 2>/dev/null || true)"
  if [ ! -x "$VENV_DIR/bin/python" ] || [ "$py_sys_ver" != "$py_venv_ver" ] || ! "$VENV_DIR/bin/python" -c 'import pip' >/dev/null 2>&1; then
    info 'створюємо venv'
    python3 -m venv --clear "$VENV_DIR" || die 'не вдалося створити web/.venv'
  else
    skip 'web/.venv — вже існує'
  fi

  if "$VENV_DIR/bin/python" -c 'import django, psycopg, celery, redis' >/dev/null 2>&1; then
    skip 'залежності web — вже встановлені'
  else
    info 'встановлюємо web/requirements.txt (Django, psycopg, celery, redis)'
    # A committed lock pins the whole tree to measured versions; the ranges in
    # requirements.txt stay the human-maintained input and the fallback. The hash
    # lock goes first: a fresh install verifies every wheel against digests taken
    # from PyPI metadata, so a substituted file fails loudly instead of running.
    _web_req="$WEB_DIR/requirements.txt"
    _web_hash=""
    [ -f "$WEB_DIR/requirements.lock" ] && _web_req="$WEB_DIR/requirements.lock"
    if [ -f "$WEB_DIR/requirements.hash" ]; then
      _web_req="$WEB_DIR/requirements.hash"
      _web_hash="--require-hashes"
    fi
    "$VENV_DIR/bin/python" -m pip install --quiet --disable-pip-version-check \
      $_web_hash -r "$_web_req" || die 'не вдалося встановити web-залежності'
  fi
  ok "web-оточення готове: $("$VENV_DIR/bin/python" -c 'import django;print("Django",django.get_version())')"
}

# Модулі поза стандартною бібліотекою, які `worker.py` імпортує на
# старті. Читаються з самого `worker.py`, а не задані списком тут: список
# у скрипті застаріває мовчки, а наступна сесія додає модуль — і перевірка
# знову перевіряє не те, що воркер реально робить на старті.
#
# Транзитивні імпорти ловляться самі: модуль, який імпортує інший, тягне
# і його, тож недоступна залежність на три рівні нижче теж роняє перевірку.
# Stdlib виключено — він не може раптом зникнути. Camoufox теж виключено:
# його optional runtime встановлюється окремим кроком після preflight; lazy
# import усередині browser job не потрібен для імпорту воркера.
_worker_required_modules() {
  "$WORKER_VENV_DIR/bin/python" - "$WORKER_DIR/worker.py" <<'PY' 2>/dev/null
import ast
import sys

tree = ast.parse(open(sys.argv[1], encoding="utf-8").read())
names = set()
for node in ast.walk(tree):
    if isinstance(node, ast.Import):
        names.update(alias.name.split(".")[0] for alias in node.names)
    elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
        names.add(node.module.split(".")[0])
optional_modules = {"camoufox"}
# Через кому, а не пробілом: результат вставляється в `import ...`, а
# `import a b` — це SyntaxError. Помилка тут була б непомітною: вона
# ховалася за `2>/dev/null` і виглядала б як «ланцюг імпорту зламаний»,
# тобто крок 04 встановлював би playwright заново й упирався б у die
# навіть з повністю встановленими залежностями.
print(", ".join(sorted(names - set(sys.stdlib_module_names) - optional_modules)))
PY
}

# Чи воркер взагалі імпортується. Без цієї перевірки невдалий імпорт
# виявлявся через 60 секунд очікування health на кроці 11, з одним лише
# шляхом до логу. Виміряно 2026-09-30: відсутня залежність у
# browser-worker давала `browser-worker не піднявся`, а реальна причина —
# `ModuleNotFoundError: No module named 'numpy'` — лежала в
# data/logs/browser-worker.log.
_worker_imports_ok() {
  local mods
  mods="$(_worker_required_modules)"
  [ -n "$mods" ] || return 0
  # `cd "$WORKER_DIR"` обовʼязковий: `anti_detect`, `human_input` —
  # локальні модулі цього каталогу, а `python -c`
  # кладе в `sys.path` поточний каталог. Воркер запускається саме звідти
  # (`cd "$WORKER_DIR"` у `start_browser_worker`), тому й перевірка має
  # бути звідти — інакше вона падає на `No module named 'anti_detect'`
  # при повністю готовому оточенні.
  ( cd "$WORKER_DIR" && "$WORKER_VENV_DIR/bin/python" -c "import $mods" ) >/dev/null 2>&1
}

ensure_worker_venv() {
  step 'Python-оточення browser-worker'
  local py_sys_ver py_venv_ver
  py_sys_ver="$(python3 -c 'import sys; print(sys.version_info[:2])' 2>/dev/null || true)"
  py_venv_ver="$("$WORKER_VENV_DIR/bin/python" -c 'import sys; print(sys.version_info[:2])' 2>/dev/null || true)"
  if [ ! -x "$WORKER_VENV_DIR/bin/python" ] || [ "$py_sys_ver" != "$py_venv_ver" ] || ! "$WORKER_VENV_DIR/bin/python" -c 'import pip' >/dev/null 2>&1; then
    info 'створюємо venv'
    python3 -m venv --clear "$WORKER_VENV_DIR" || die 'не вдалося створити browser-worker/.venv'
  else
    skip 'browser-worker/.venv — вже існує'
  fi

  if ! _worker_imports_ok; then
    info 'встановлюємо browser-worker/requirements.txt (playwright)'
    # Same lock-first rule as the web venv: an exact record when present,
    # the human-maintained ranges otherwise. Hashes first, for the same reason.
    _worker_req="$WORKER_DIR/requirements.txt"
    _worker_hash=""
    [ -f "$WORKER_DIR/requirements.lock" ] && _worker_req="$WORKER_DIR/requirements.lock"
    if [ -f "$WORKER_DIR/requirements.hash" ]; then
      _worker_req="$WORKER_DIR/requirements.hash"
      _worker_hash="--require-hashes"
    fi
    "$WORKER_VENV_DIR/bin/python" -m pip install --quiet --disable-pip-version-check \
      $_worker_hash -r "$_worker_req" || die 'не вдалося встановити playwright'
    # Після встановлення перевіряємо знову і, якщо ланцюг імпорту все ще
    # ламається, друкуємо саму помилку. «Не вдалося встановити» тут було б
    # брехнею: залежність може бути не в requirements.txt.
    if ! _worker_imports_ok; then
      printf '%s\n' "$( cd "$WORKER_DIR" && "$WORKER_VENV_DIR/bin/python" \
        -c "import $(_worker_required_modules)" 2>&1 | tail -3 )" >&2
      die 'browser-worker не імпортується після встановлення залежностей; причина вище'
    fi
  else
    skip "залежності встановлено: $(_worker_required_modules)"
  fi
  ok "browser-worker оточення готове: playwright $("$WORKER_VENV_DIR/bin/python" -c 'import playwright;print(playwright.__version__)' 2>/dev/null || echo '?')"

}


# Системні бібліотеки Firefox для Debian/Kali.
#
# `python -m playwright install-deps firefox` тут не працює: у Playwright немає
# списку залежностей для Kali, тож він підставляє ubuntu-20.04, де назви
# пакетів інші. Виміряно на kali-rolling 2026.3 — три імені не існують узагалі:
#
#   libgdk-pixbuf2.0-0     -> у Kali libgdk-pixbuf-2.0-0
#   ttf-unifont            -> Candidate: (none), у Kali unifont
#   ttf-ubuntu-font-family -> пакет лише Ubuntu, у Debian/Kali fonts-ubuntu
#
# разом з тим Rolling перейшов на time64, тому й решту доводиться брати з
# суфіксом `t64` (`libasound2t64`, `libatk1.0-0t64`, `libcups2t64`, ...), а
# Playwright просить назви до переходу. Разом це дає код 100 і стіну рядків
# `E: Unable to locate package`, тоді як сам Firefox запускається.
#
# Тому список будуємо самі й кожну групу пропускаємо через `apt-cache policy`:
# береться перша назва, що має кандидата, а група без кандидата взагалі не
# ставиться — і про відсутні імена повідомляємо, щоб пропуск був видимий.
install_firefox_system_deps() {
  # Один запис — одна залежність; `|` відділяє назви одного пакета в різних
  # дистрибутивах (t64-варіант Kali проти назви до переходу).
  local groups=(
    'libasound2t64|libasound2'
    'libatk-bridge2.0-0t64|libatk-bridge2.0-0'
    'libatk1.0-0t64|libatk1.0-0'
    'libatspi2.0-0t64|libatspi2.0-0'
    'libcairo-gobject2'
    'libcairo2'
    'libcups2t64|libcups2'
    'libdbus-1-3'
    'libdrm2'
    'libgbm1'
    'libglib2.0-0t64|libglib2.0-0'
    'libgdk-pixbuf-2.0-0|libgdk-pixbuf2.0-0'
    'libnspr4'
    'libnss3'
    'libpango-1.0-0'
    'libx11-6'
    'libxcb1'
    'libxcomposite1'
    'libxdamage1'
    'libxext6'
    'libxfixes3'
    'libxkbcommon0'
    'libxrandr2'
    'fonts-dejavu-core'
    'fonts-liberation'
    'fonts-noto-color-emoji'
    'unifont|ttf-unifont'
    'fonts-ubuntu|ttf-ubuntu-font-family'
  )

  local installable=() missing=() group label pick name candidate
  for group in "${groups[@]}"; do
    label="${group%%|*}"     # канонічне ім'я — те саме, що просив би Playwright
    pick=''
    while [ -n "$group" ]; do
      name="${group%%|*}"
      group="${group#*|}"
      [ "$group" = "$name" ] && group=''   # більше немає '|' — це остання назва
      candidate="$(apt-cache policy "$name" 2>/dev/null | sed -n 's/^  Candidate: //p')"
      if [ -n "$candidate" ] && [ "$candidate" != '(none)' ]; then
        pick="$name"
        break
      fi
    done
    if [ -n "$pick" ]; then
      installable+=("$pick")
    else
      missing+=("$label")
    fi
  done

  [ "${#missing[@]}" -gt 0 ] && skip "у цьому репозиторії немає: ${missing[*]}"

  if [ "${#installable[@]}" -eq 0 ]; then
    warn 'жодного системного пакета не знайдено — пропускаємо встановлення'
    return 1
  fi

  info "встановлюємо системні бібліотеки Firefox (${#installable[@]} пакетів, потрібен root)"

  # Пароль root не приймається з неінтерактивного входу — кажемо одразу, що
  # робити, замість падати на 'sudo: a password is required' усередині apt.
  # Тут не die: браузер уже може бути працездатним, тож це попередження.
  if [ -n "$SUDO" ] && ! sudo -n true 2>/dev/null; then
    if [ -t 0 ]; then
      info 'потрібен пароль root — введіть його у запиті sudo'
    else
      printf '      бракує системних бібліотек:\n' >&2
      printf "        sudo apt-get install -y %s\n" "${installable[*]}" >&2
      return 1
    fi
  fi

  # `DEBIAN_FRONTEND` ставимо ПЕРЕД `$SUDO`, а не після: коли скрипт уже
  # root, `$SUDO` порожній, і в `$SUDO DEBIAN_FRONTEND=... apt-get` парсер
  # вже вважає `DEBIAN_FRONTEND=...` іменем команди — виходить
  # `command not found`. З перестановкою рядок є перевизначенням змінної
  # і однаково правий для `sudo` та для прямого запуску від root.
  DEBIAN_FRONTEND=noninteractive $SUDO apt-get install -y "${installable[@]}"
}

# Запуск Firefox, а не лише наявність бінарника.
#
# `[ -x "$binary" ]` і `INSTALLATION_COMPLETE` доводять тільки те, що файл
# покладено на диск. Рушій при цьому може не стартувати — немає бібліотеки,
# не вдалося створити профіль, sandbox не піднімається, — і тоді помилка
# з'являється пізно, в момент job-у, далеко від місця, де її спричинили.
#
# Повний запуск коштує виміряних ~4-5 с, тож на кожен старт тащити його
# не можна. Натомість кешуємо підпис бінарника (шлях + розмір + mtime) у
# маркер поруч із браузером: доки бінарник не змінився, перевірка вже
# пройшла і повторно не оплачується. Змінили версію — перевіряємо знову.
firefox_launch_ok() {
  local binary="$1"
  # Каталог беремо з тієї ж змінної, яку експортує ensure_playwright_browser,
  # а не з його локальної `browsers_path`: локальна не видима ззовні, і
  # покладання на динамічну область видимості bash тут крихке.
  local browsers="${PLAYWRIGHT_BROWSERS_PATH:-$HOME/.cache/ms-playwright}"
  local marker="$browsers/.rr-firefox-launch-ok"
  local signature output rc
  local timeout_s="${RR_FIREFOX_VERIFY_TIMEOUT:-90}"

  signature="$(stat -c '%n %s %Y' "$binary" 2>/dev/null)" || return 1
  [ -n "$signature" ] || return 1

  if [ -f "$marker" ] && [ "$(cat "$marker" 2>/dev/null)" = "$signature" ]; then
    skip 'Firefox уже перевірявся фактичним запуском (бібліотеки на місці)'
    return 0
  fi

  if ! have_cmd timeout; then
    warn 'немає timeout — перевірку запуску пропускаємо'
    return 0
  fi

  info "перевіряємо фактичний запуск Firefox (виміряно ~5 с, таймаут ${timeout_s}с)"
  output="$(timeout "$timeout_s" "$WORKER_VENV_DIR/bin/python" - 2>&1 <<'RRVERIFY'
from playwright.sync_api import sync_playwright

with sync_playwright() as p:
    browser = p.firefox.launch(headless=True)
    page = browser.new_page()
    page.set_content("<h1>rr</h1>")
    assert page.inner_text("h1") == "rr"
    browser.close()
RRVERIFY
)"
  rc=$?

  if [ "$rc" -eq 0 ]; then
    # Неперезаписний маркер: якщо каталог недоступний на запис, перевірка
    # все одно успішна — просто наступний запуск повторить її.
    printf '%s' "$signature" > "$marker" 2>/dev/null || true
    ok 'Firefox запускається — системні бібліотеки на місці'
    return 0
  fi

  # 124 — таймаут, решта — помилка запуску або самого браузера.
  #
  # Показуємо не весь трейс, а рядок винятку: у виводі Playwright він
  # лежить у самому низу, під 17 рядками `File "..."` і `_generated.py`, і
  # саме він називає причину — `Executable doesn't exist`, відсутню
  # бібліотеку або зруйнований профіль. Без нього лишається «Firefox не
  # запускається», що не сказа оператору нічого. Якщо рядка винятку немає,
  # віддаємо останні рядки — вони ближчі до причини, ніж початок стеку.
  local summary
  if [ "$rc" -eq 124 ]; then
    summary="не встиг запуститися за ${timeout_s}с — це таймаут, а не помилка бібліотеки"
  elif [ -z "$output" ]; then
    summary='браузер завершився без виводу (збіглося з нашим assert або з падінням самого процесу)'
  else
    summary="$(printf '%s\n' "$output" | grep -E '^[^ ].*(Error|Exception):' | head -3)"
    [ -n "$summary" ] || summary="$(printf '%s\n' "$output" | tail -3)"
  fi

  warn "Firefox не запускається (rc=$rc). Причина:"
  printf '%s\n' "$summary" | while IFS= read -r line; do
    [ -n "$line" ] || continue
    printf '        %s\n' "$line"
  done
  warn 'решту застосунку це не зупиняє, але browser-driven Target не працюватиме'
  return 1
}

# Playwright-рушій: бібліотека без браузера не запускається, а помилка
# з'являється лише в момент job-у. Тому перевіряємо сам бінарник, а не
# імпорт пакета.
ensure_playwright_browser() {
  step 'Браузер Playwright (Firefox)'
  local browsers_path="${PLAYWRIGHT_BROWSERS_PATH:-$HOME/.cache/ms-playwright}"
  local binary browser_revision_dir
  export PLAYWRIGHT_BROWSERS_PATH="$browsers_path"

  if ! binary="$("$WORKER_VENV_DIR/bin/python" - 2>&1 <<'PY'
from playwright.sync_api import sync_playwright

with sync_playwright() as playwright:
    print(playwright.firefox.executable_path)
PY
)"; then
    warn "не удалось получить путь Firefox из Playwright: $binary"
    binary=''
  fi

  if [ -n "$binary" ]; then
    browser_revision_dir="$(dirname "$(dirname "$binary")")"
  else
    browser_revision_dir=''
  fi

  if [ -n "$binary" ] && [ -x "$binary" ] \
      && [ -f "$browser_revision_dir/INSTALLATION_COMPLETE" ]; then
    export FIREFOX_EXECUTABLE_PATH="$binary"
    skip "Firefox уже завантажено: $binary"
    # Файл на місці — ще не доказ, що рушій стартує. Перевірка кешована за
    # підписом бінарника, тож повторні запуски її не повторюють.
    firefox_launch_ok "$binary" \
      || warn 'Firefox завантажено, але не запускається — browser-driven Target не працюватиме'
    ok 'Рушій браузера готовий'
    return 0
  fi

  if [ -n "$binary" ]; then
    warn "Firefox отсутствует или установка не завершена: $binary"
  fi

  # have_cmd node перевірено на кроці 1, але playwright-driver ставить
  # власну копію — тож переконуємося перед довгим завантаженням.
  have_cmd node || die 'Node.js потрібен Playwright, але не встановлено'

  # Не `playwright install-deps`: на Kali він бере ubuntu-20.04-список і
  # падає на трьох іменах, яких тут немає. Див. install_firefox_system_deps.
  # Це попередження, а не зупинка: браузер уже може бути працездатним (на
  # машині без цих пакетів Firefox запускається), тож ламаємо запуск лише
  # тоді, коли сам завантажений рушій не з'явився.
  install_firefox_system_deps \
    || warn 'системні бібліотеки Firefox встановлено не повністю — продовжуємо; ламатися буде лише на завантаженні браузера'

  info 'завантажуємо Firefox (після цього кроку — довго)'
  "$WORKER_VENV_DIR/bin/python" -m playwright install firefox \
    || die 'не вдалося завантажити Firefox для Playwright'

  binary="$("$WORKER_VENV_DIR/bin/python" -c \
    'from playwright.sync_api import sync_playwright; p=sync_playwright().start(); print(p.firefox.executable_path); p.stop()')" \
    || die 'не вдалося визначити шлях Firefox Playwright'
  browser_revision_dir="$(dirname "$(dirname "$binary")")"
  [ -x "$binary" ] && [ -f "$browser_revision_dir/INSTALLATION_COMPLETE" ] \
    || die "Firefox завантажено, але очікуваний виконуваний файл або маркер встановлення відсутній: $binary"
  export FIREFOX_EXECUTABLE_PATH="$binary"
  # Щойно завантажений рушій перевіряємо обов'язково: тут ми вже заплатили
  # часом завантаження, 5 с на перевірку не коштують нічого, а зупинка
  # відбувається відразу, поки оператор бачить причину, а не на job-і.
  firefox_launch_ok "$binary" \
    || die 'Firefox завантажено, але не запускається — див. вивід вище'
  ok "Firefox готовий: $FIREFOX_EXECUTABLE_PATH"
}

# Chromium — рушій Playwright для браузерного обходу Target (chromium/chrome/edge).
# Playwright 1.55 очікує ревізію chromium_headless_shell-1187; іноді в
# ~/.cache/ms-playwright лишається лише інша ревізія, і будь-який запуск абінг
# (через `/api/target-browser`) падає на `BrowserType.launch: Executable doesn't
# exist`. Тому тут ми ставимо саме Chromium-білд Playwright, ідемпотентно:
# якщо ревізія вже присутня, нічого не скачуватиметься.
ensure_playwright_chromium() {
  step 'Playwright Chromium (для browser-driven Target)'
  local python_bin="$WORKER_VENV_DIR/bin/python"
  local binary

  binary="$( "$python_bin" -c \
    'from playwright.sync_api import sync_playwright; p=sync_playwright().start(); print(p.chromium.executable_path); p.stop()' \
  2>/dev/null )" || binary=""

  if [ -n "$binary" ] && [ -x "$binary" ]; then
    local browser_revision_dir
    browser_revision_dir="$(dirname "$(dirname "$binary")")"
    if [ -f "$browser_revision_dir/INSTALLATION_COMPLETE" ]; then
      skip "Playwright Chromium уже встановлено: $binary"
      ok "Playwright Chromium готовий: $binary"
      return 0
    fi
  fi

  if [ -z "$binary" ]; then
    warn 'не вдалося визначити шлях Playwright Chromium — ставимо за замовчуванням (chromium)'
  fi

  info 'завантажуємо Chromium для Playwright (після цього кроку — довго)'
  if ! "$python_bin" -m playwright install chromium; then
    warn 'Playwright Chromium не вдалося завантажити автоматично; у браузерному \
Target буде недоступний `chromium` (деталь у data/logs)'
    return 0
  fi

  binary="$( "$python_bin" -c \
    'from playwright.sync_api import sync_playwright; p=sync_playwright().start(); print(p.chromium.executable_path); p.stop()' \
  2>/dev/null )" || binary=""
  if [ -z "$binary" ] || [ ! -x "$binary" ]; then
    warn 'Playwright Chromium встановлено, але виконуваний файл не визначається'
    return 0
  fi
  local browser_revision_dir
  browser_revision_dir="$(dirname "$(dirname "$binary")")"
  [ -f "$browser_revision_dir/INSTALLATION_COMPLETE" ] \
    || warn "Playwright Chromium встановлено, але маркер INSTALLATION_COMPLETE відсутній: $browser_revision_dir"
  ok "Playwright Chromium готовий: $binary"
  return 0
}

# Camoufox — окремий рантайм Target. Під час першого запуску завантаження
# браузера може зайняти кілька хвилин і близько 1.2 ГБ диска; наступні запуски
# пропускають мережеві кроки, якщо бінарник уже встановлено.
ensure_camoufox() {
  step 'Camoufox (антидетект-браузер)'
  local python_bin="$WORKER_VENV_DIR/bin/python"
  local version="${RR_CAMOUFOX_VERSION:-0.5.6}"
  local browser_check='import os, sys; from camoufox.pkgman import camoufox_path; sys.exit(0 if os.path.isfile(os.path.join(str(camoufox_path(download_if_missing=False)), "camoufox")) else 1)'

  if ! "$python_bin" -c 'import camoufox' >/dev/null 2>&1; then
    info 'встановлюємо пакет camoufox'
    "$python_bin" -m pip install --quiet --disable-pip-version-check "camoufox==$version" \
      || {
        warn 'пакет Camoufox не встановлено; решта застосунку запускається без цього runtime'
        return 0
      }
  fi

  if ! "$python_bin" -c 'import camoufox' >/dev/null 2>&1; then
    "$python_bin" -c 'import camoufox' >&2
    warn 'пакет Camoufox недоступний після встановлення; решта застосунку запускається без цього runtime'
    return 0
  fi

  if "$python_bin" -c "$browser_check" >/dev/null 2>&1; then
    skip 'браузер Camoufox уже встановлено'
    ok 'Camoufox готовий'
    return 0
  fi

  info 'синхронізуємо список версій Camoufox'
  if ! "$python_bin" -m camoufox sync; then
    warn 'не вдалося синхронізувати версії Camoufox; решта застосунку запускається без цього runtime'
    return 0
  fi

  info 'завантажуємо браузер Camoufox (може знадобитися близько 1.2 ГБ)'
  if ! "$python_bin" -m camoufox fetch; then
    warn 'не вдалося завантажити браузер Camoufox; решта застосунку запускається без цього runtime'
    return 0
  fi

  if ! "$python_bin" -c "$browser_check" >/dev/null 2>&1; then
    warn 'Camoufox fetch завершився без бінарника браузера; решта застосунку запускається без цього runtime'
    return 0
  fi

  ok 'Camoufox готовий'
}


# ─────────────────────────── Крок 4: nuclei ──────────────────────────

ensure_nuclei() {
  step 'Nuclei (сканер шаблонів)'
  mkdir -p "$BIN_DIR"
  local pinned="${RR_NUCLEI_VERSION:-v3.11.1}"
  local nuclei_bin=''

  if [ -n "${RR_NUCLEI_BINARY:-}" ] && [ -x "${RR_NUCLEI_BINARY}" ]; then
    export RR_NUCLEI_BINARY
    ok "RR_NUCLEI_BINARY з оточення: $RR_NUCLEI_BINARY"
  elif [ -x "$BIN_DIR/nuclei" ]; then
    export RR_NUCLEI_BINARY="$BIN_DIR/nuclei"
    skip "збінарник у репозиторії вже є: $BIN_DIR/nuclei"
  elif have_cmd nuclei; then
    export RR_NUCLEI_BINARY="$(command -v nuclei)"
    ok "системний nuclei: $RR_NUCLEI_BINARY ($("$RR_NUCLEI_BINARY" -version 2>&1 | grep -o 'v[0-9.]*' | head -1))"
  else
    info "збираємо закріплений nuclei $pinned (довго)"
    GOBIN="$BIN_DIR" go install "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@$pinned" \
      || die 'збірка nuclei не вдалася; поставіть nuclei вручну або задайте RR_NUCLEI_BINARY'
    export RR_NUCLEI_BINARY="$BIN_DIR/nuclei"
    ok "nuclei зібрано: $BIN_DIR/nuclei"
  fi

  # Корпус шаблонів називається, а не шукається. Правило оператора 2026-10-06:
  # обираєш папку — і її абсолютний шлях іде в `-t`. Рушій больше нічого не
  # вгадує (2026-10-06 з `templateDirRoots` прибрано `~/.local/`, `~/Desktop/`,
  # `~/Downloads/`, `/usr/share/`, `/opt/`), тому те, що він показує в списку,
  # визначається тут.
  #
  # Змінна саме `RR_NUCLEI_TEMPLATE_DIR` (без множини): рушій читає
  # `engine/pkg/scanner/nuclei_dirsource.go: templateDirRoots`, і до 2026-10-05
  # тут експортувалася `RR_NUCLEI_TEMPLATES_DIR`, яку не читав ніхто — корпус
  # оператора був невидимий, а папка з нього відповідала `template directory
  # "…" was not found`.
  #
  # Тільки `<root>/nuclei-templates`: це те, що оператор тримає в проєкті. Другий
  # корінь не додається — два корпуси з однаковою назвою `http` означали б два
  # рядки в списку, з яких один не запускає те, що на ньому написано.
  if [ -z "${RR_NUCLEI_TEMPLATE_DIR:-}" ] && [ -d "$ROOT_DIR/nuclei-templates" ]; then
    export RR_NUCLEI_TEMPLATE_DIR="$ROOT_DIR/nuclei-templates"
    info "шаблони: $RR_NUCLEI_TEMPLATE_DIR"
  fi
}

# ───────────────────── Крок 4b: httpx ──────────────────────────────────
#
# `bin/` у `.gitignore`, тому бінарник не входить до вихідного дерева.
ensure_httpx() {
  step 'ProjectDiscovery httpx'
  mkdir -p "$BIN_DIR"

  # httpx выполняется как отдельный процесс, потому что `runner` тянет `dit`,
  # `asnmap`, `mapcidr`, `wappalyzergo`, `pdcp` та `internal/db`.
  local httpx_version="${RR_HTTPX_VERSION:-v1.11.0}"
  if [ -x "$BIN_DIR/httpx" ]; then
    skip "httpx уже є: $BIN_DIR/httpx"
  elif have_cmd httpx; then
    ok "системний httpx: $(command -v httpx)"
  else
    info "збираємо httpx $httpx_version (довго)"
    GOBIN="$BIN_DIR" go install "github.com/projectdiscovery/httpx/cmd/httpx@$httpx_version" \
      || die 'збірка httpx не вдалася; поставіть httpx у bin/ вручну або задайте RR_HTTPX_VERSION'
    ok "httpx зібрано: $BIN_DIR/httpx"
  fi
}


# ─────────────────────────── Крок 5: postgres ────────────────────────
#
# Кластер у data/pg, а не системний: порт 55433 не конфліктує з
# системним 5432, а `--check` не ламає те, чим користується інша сесія.

find_pg_bin() {
  local name="$1" dir
  for dir in /usr/lib/postgresql/*/bin /usr/pgsql-*/bin /usr/local/pgsql/bin; do
    [ -x "$dir/$name" ] && { printf '%s' "$dir/$name"; return 0; }
  done
  have_cmd "$name" && { command -v "$name"; return 0; }
  return 1
}

# PostgreSQL відмовляється працювати від root: і initdb, і pg_ctl завершуються
# з «cannot be run as root». Тому визначаємо користувача, від імені якого
# житиме кластер: зазвичай це той, хто запустив скрипт, а якщо через sudo —
# власник репозиторію.
PG_RUNAS_USER=''
resolve_pg_runas() {
  if [ "$(id -u)" -ne 0 ]; then
    PG_RUNAS_USER="$(id -un)"
  elif [ -n "${SUDO_USER:-}" ]; then
    PG_RUNAS_USER="$SUDO_USER"
  else
    PG_RUNAS_USER=postgres
  fi
}

pg_as() {
  if [ "$(id -u)" -eq 0 ] && [ "$(id -un)" != "$PG_RUNAS_USER" ]; then
    if have_cmd runuser; then
      runuser -u "$PG_RUNAS_USER" -- "$@"
    else
      su -s /bin/sh "$PG_RUNAS_USER" -c "$(printf '%q ' "$@")"
    fi
  else
    "$@"
  fi
}

# Власник файлів кластера: якщо скрипт запущено через sudo, каталоги
# створюються від root, а працювати з ними буде SUDO_USER.
pg_own() {
  [ "$(id -u)" -eq 0 ] || return 0
  chown "$PG_RUNAS_USER" "$@" 2>/dev/null || true
}

ensure_postgres() {
  step 'PostgreSQL'
  resolve_pg_runas

  # `-d postgres` називає базу, яка є в будь-якому кластері. Без нього libpq
  # іменує базу за іменем ОС-користувача (`kali`), і сервер пише в лог
  # `FATAL: database "kali" does not exist` — на живому сервері, під час руху.
  # Код повернення pg_isready при цьому лишається 0 (виміряно 2026-09-29 на
  # PostgreSQL 18), тож це не є причиною збою кроку 07: die дає `pg_ctl start`,
  # а не ця проба. Причину збою не встановлено — див. DEVELOPMENT_LOG.md.
  if pg_isready -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -d postgres -q 2>/dev/null; then
    ok "кластер вже відповідає на 127.0.0.1:$POSTGRES_PORT"
  else
    local pg_ctl initdb
    pg_ctl="$(find_pg_bin pg_ctl)" || die 'не знайдено pg_ctl; встановіть postgresql'
    initdb="$(find_pg_bin initdb)" || die 'не знайдено initdb; встановіть postgresql'

    local pg_run_dir="$DATA_DIR/run"
    mkdir -p "$PGDATA" "$pg_run_dir" "$LOG_DIR"
    pg_own "$PGDATA" "$pg_run_dir" "$LOG_DIR"
    chmod 700 "$PGDATA"
    chmod 777 "$pg_run_dir"

    if [ ! -s "$PGDATA/PG_VERSION" ]; then
      # Каталог без PG_VERSION, але вже не порожній, — це не «кластер ще не
      # створювався», а обрив попереднього initdb: він устиг створити частину
      # файлів і не встиг записати PG_VERSION. Звичайний initdb такий каталог
      # відкидає («exists but is not empty»), тому наступний запуск падав би
      # без назви причини, поки оператор не здогадається видалити каталог
      # вручну. Виміряно 2026-09-29 саме так: `initdb не вдався` без жодної
      # згадки про неповний каталог.
      #
      # Каталог не видаляється сам: так ми відрізняємо обрив від даних, які
      # хтось поклав руками, а знищення даних — це рішення власника, а не
      # побічний ефект підготовки (див. «Гарбейж-колектор» у AGENTS.md).
      if [ -n "$(ls -A "$PGDATA" 2>/dev/null)" ]; then
        die "каталог $PGDATA неповний: є файли, але немає PG_VERSION — це обрив попереднього initdb.
      Перевірте, чи немає там даних, і виконайте:
        rm -rf '$PGDATA'
      Після цього запустіть ./start.sh знову."
      fi
      info "ініціалізуємо кластер у $PGDATA від $PG_RUNAS_USER (UTF8, trust)"
      # LC_COLLATE/LC_CTYPE=C разом з UTF8 дають рівний sort_order, а
      # маркер Intruder '§' зберігається — саме через це шаблон
      # requestrider_utf8_tmpl існує окремо.
      pg_as "$initdb" -D "$PGDATA" -U "$POSTGRES_USER" \
        --auth-local=trust --auth-host=trust \
        --encoding=UTF8 --locale=C >>"$LOG_DIR/postgres-init.log" 2>&1 \
        || die "initdb не вдався; деталі в $LOG_DIR/postgres-init.log"
    else
      skip "кластер уже ініціалізовано: $PGDATA"
    fi

    # Порт, listener і канал передачі записуються у postgresql.conf, а
    # не в аргументи pg_ctl: так налаштування переживає перезапуск,
    # який оператор робить вручну, і лишається в одному місці.
    #
    # Значення передаються вже з лапками, і це не прикраса: PostgreSQL
    # парсить значення як конфігураційний лексем, тому `unix_socket_
    # directories = /home/...` без лапок — синтаксична помилка на `/`,
    # і кластер не стартує взагалі.
    if ! grep -q "request-rider managed" "$PGDATA/postgresql.conf" 2>/dev/null; then
      {
        printf '\n# --- request-rider managed (start.sh) ---\n'
        printf "port = '%s'\n" "$POSTGRES_PORT"
        printf "listen_addresses = '127.0.0.1'\n"
        printf "unix_socket_directories = '%s'\n" "$pg_run_dir"
      } >"$LOG_DIR/pgconf.tmp"
      pg_own "$LOG_DIR/pgconf.tmp"
      pg_as sh -c "cat '$LOG_DIR/pgconf.tmp' >> '$PGDATA/postgresql.conf'"
      rm -f "$LOG_DIR/pgconf.tmp"
    fi
    pg_own "$PGDATA/postgresql.conf"

    info "запускаємо кластер на 127.0.0.1:$POSTGRES_PORT"
    : >"$LOG_DIR/postgres.log"
    pg_own "$LOG_DIR/postgres.log"
    pg_as "$pg_ctl" -D "$PGDATA" -l "$LOG_DIR/postgres.log" -w -t 60 start \
      >>"$LOG_DIR/postgres.log" 2>&1 \
      || die "кластер не піднявся; деталі в $LOG_DIR/postgres.log"

    # `-d postgres` — див. пояснення біля перевірки вище: іменує базу, яка
    # точно є, щоб у лог сервера не потрапляло `database "kali" does not exist`.
    wait_for 'PostgreSQL' "pg_isready -h $POSTGRES_HOST -p $POSTGRES_PORT -d postgres -q" 60 \
      || die "PostgreSQL не відповідає; деталі в $LOG_DIR/postgres.log"

    # Кластер ми підняли — записуємо його, щоб `--stop` зупинив саме цей.
    # Якщо ми його лише переикористали (крок уже відповідав), запису немає:
    # це не наш процес, і зупиняти його --stop не має права.
    local pg_pid
    pg_pid="$(_pidfile_pid "$PGDATA/postmaster.pid")" \
      || die "postmaster.pid не читається в $PGDATA — немає чого записувати у файлі стану"
    state_record 'postgres' "$pg_pid"
  fi

  # База застосунку. createdb з -E UTF8 -T template0 -l C: база, що
  # успадкувала SQL_ASCII-шаблон кластера, не зберігає '§' і падає
  # DataError усередині випадкового тесту.
  if psql -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" \
        -d postgres -tAc "SELECT 1 FROM pg_database WHERE datname='$POSTGRES_DB'" 2>/dev/null | grep -q 1; then
    skip "база $POSTGRES_DB уже існує"
  else
    info "створюємо базу $POSTGRES_DB (UTF8)"
    createdb -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" \
      -E UTF8 -T template0 -l C "$POSTGRES_DB" \
      || die "не вдалося створити базу $POSTGRES_DB"
  fi

  # Тестовий шаблон створює сам runner (core.testdb.ensure_test_template)
  # перед setup_databases, саме тому `manage.py test` має бути зеленим на
  # новому кластері без ручного bootstrap. Тут лише перевірка, що
  # кластер взагалі здатний його створити.
  ok "PostgreSQL готовий: $POSTGRES_USER@$POSTGRES_HOST:$POSTGRES_PORT/$POSTGRES_DB"
}

# ─────────────────────────── Крок 6: redis ───────────────────────────

ensure_redis() {
  step 'Redis (брокер)'
  if redis-cli -p "$REDIS_PORT" ping >/dev/null 2>&1; then
    ok "Redis уже відповідає на 127.0.0.1:$REDIS_PORT"
    return 0
  fi

  mkdir -p "$REDIS_DIR"
  # AOF з fsync=everysec: чергова задача, зникла при рестарті, — це
  # втрачена робота. dump-файлів немає, бо snapshot-ів нам не треба.
  info "запускаємо Redis на 127.0.0.1:$REDIS_PORT"
  redis-server \
    --port "$REDIS_PORT" \
    --bind 127.0.0.1 \
    --dir "$REDIS_DIR" \
    --appendonly yes \
    --appendfsync everysec \
    --save '' \
    --daemonize yes \
    --pidfile "$REDIS_DIR/redis.pid" \
    --logfile "$LOG_DIR/redis.log" \
    || die 'не вдалося запустити Redis'

  wait_for 'Redis' "redis-cli -p $REDIS_PORT ping" 30 \
    || die "Redis не відповідає; деталі в $LOG_DIR/redis.log"

  local redis_pid
  redis_pid="$(_pidfile_pid "$REDIS_DIR/redis.pid")" \
    || die "redis.pid не читається в $REDIS_DIR — немає чого записувати у файлі стану"
  state_record 'redis' "$redis_pid"
  ok "Redis готовий: $CELERY_BROKER_URL"
}

# ─────────────────────────── Крок 7: tor ────────────────────────────
#
# Tor піднімається лише тоді, коли руш реально через нього
# (ROUTE_ADDRESS / RR_ROUTE_VIA_TOR=1). Демон, яким ніхто не маршрутизує,
# — це «живий мусор»: він тримає процес і не робить нічого.

ensure_tor() {
  step 'Tor (маршрут виходу)'

  local want=0
  [ -n "${ROUTE_ADDRESS:-}" ] && want=1
  [ "${RR_ROUTE_VIA_TOR:-0}" = "1" ] && want=1

  if [ "$want" -eq 0 ]; then
    skip 'не запитано (RR_ROUTE_VIA_TOR=1 — підняти й направити рух)'
    return 0
  fi

  if have_cmd tor && ss -tln 2>/dev/null | grep -q ":$SOCKS_PORT "; then
    ok "Tor уже слухає 127.0.0.1:$SOCKS_PORT"
  elif ! have_cmd tor; then
    die 'ROUTE_ADDRESS задано, але Tor не встановлено'
  else
    mkdir -p "$DATA_DIR/tor"
    info "запускаємо Tor (SOCKS $SOCKS_PORT)"
    tor --SocksPort "$SOCKS_PORT" --DataDirectory "$DATA_DIR/tor" \
      --RunAsDaemon 1 --PidFile "$DATA_DIR/tor/tor.pid" \
      --Log 'notice file '"$LOG_DIR"'/tor.log' \
      || die 'не вдалося запустити Tor'
    wait_for 'Tor' "ss -tln 2>/dev/null | grep -q ':$SOCKS_PORT '" 45 \
      || die "Tor не слухає $SOCKS_PORT; деталі в $LOG_DIR/tor.log"

    local tor_pid
    tor_pid="$(_pidfile_pid "$DATA_DIR/tor/tor.pid")" \
      || die "tor.pid не читається в $DATA_DIR/tor — немає чого записувати у файлі стану"
    state_record 'tor' "$tor_pid"
  fi

  export ROUTE_ADDRESS="${ROUTE_ADDRESS:-127.0.0.1:$SOCKS_PORT}"
  ok "Tor готовий, рух engine піде через $ROUTE_ADDRESS"
}

# ─────────────────────────── Крок 8: engine ──────────────────────────

# build_engine_binary — зібрати engine у bin/, якщо його там немає або
# вихідники новіші за нього.
#
# Повертає 0, коли бінарник готовий, 1 — коли перебудова не вдалася.
# Окрема функція, а не=inline блок у `ensure_engine`, тому що її треба
# викликати ДО перевірки `/health` (див. нижче про порядок).
build_engine_binary() {
  mkdir -p "$BIN_DIR"
  if [ ! -x "$ENGINE_BINARY" ]; then
    info 'збираємо engine (перший раз — довго: завантаження модулів)'
    ( cd "$ENGINE_DIR" && go build -o "$ENGINE_BINARY" . ) || return 1
    return 0
  fi
  skip 'бінарник engine вже зібрано'
  # Складається з MAINTENANCE-розбіжностей: бінарник у bin/ може бути
  # старішим за вихідники, тому перебудовуємо, якщо є зміни.
  if [ -n "$(find "$ENGINE_DIR" -name '*.go' -newer "$ENGINE_BINARY" -print -quit 2>/dev/null)" ]; then
    info 'вихідники новіші за бінарник — перебудовуємо'
    ( cd "$ENGINE_DIR" && go build -o "$ENGINE_BINARY" . ) || return 1
  fi
  return 0
}

# engine_running_but_stale — рушій відповідає на /health, але бінарник у
# bin/` старіший за вихідники. Тобто запущений код не той, що в дереві.
#
# Порядок у `ensure_engine` — це і є дефект, який ця функція робить
# видимим. Перевірка «вихідники новіші за бінарник» стояла ПІСЛЯ
# `http_ok "$ENGINE_URL/health"` і раннього `return 0`, тому на живому
# стенді її не міг виконати жоден запуск: єдиний спосіб дістатися
# перебудови було вбити рушій, а `--restart` при цьому гасив увесь стек.
# Виміряно 2026-10-06: engine PID 143834 піднято о 13:53, бінарник зібрано
# о 13:07, 31 вихідний файл новіший — тобто оператор бачив UI, зібраний
# до правок, і «виправлення не працює».
engine_running_but_stale() {
  http_ok "$ENGINE_URL/health" || return 1
  [ -x "$ENGINE_BINARY" ] || return 1
  [ -n "$(find "$ENGINE_DIR" -name '*.go' -newer "$ENGINE_BINARY" -print -quit 2>/dev/null)" ]
}

ensure_engine() {
  step 'Go engine'

  # Перебудова йде ПЕРЕД перевіркою `/health`. Раніше вона була після
  # раннього `return 0`, тож на живому стенді не виконувалася ніколи —
  # див. `engine_running_but_stale`.
  if ! build_engine_binary; then
    die 'збірка/перебудова engine не вдалася'
  fi

  if http_ok "$ENGINE_URL/health"; then
    if engine_running_but_stale; then
      warn "engine на $ENGINE_URL працює з коду, зібраного ДО останніх правок."
      warn "Працює процес із попереднім бінарником, тому UI показує старе"
      warn "повідомлення про статус шаблонів. Застосувати зміни: ./start.sh --restart-engine"
    else
      ok "engine вже працює на $ENGINE_URL"
    fi
    return 0
  fi

  info "запускаємо engine на 127.0.0.1:$ENGINE_PORT, проксі на 127.0.0.1:$PROXY_PORT"
  (
    cd "$ENGINE_DIR"
    GOMEMLIMIT="${GOMEMLIMIT:-2GiB}" \
    PROXY_LISTEN_ADDR="127.0.0.1:$PROXY_PORT" \
    ENGINE_LISTEN_ADDR="127.0.0.1:$ENGINE_PORT" \
    exec "$ENGINE_BINARY"
  ) >>"$LOG_DIR/engine.log" 2>&1 &
  register_pid $! 'engine'

  wait_for 'engine' "curl -fsS $ENGINE_URL/health" 60 \
    || die "engine не піднявся; деталі в $LOG_DIR/engine.log"
  ok "engine готовий: $ENGINE_URL (CA: $CA_DIR)"
}

# ─────────────────────── Крок 9: browser-worker ──────────────────────

start_browser_worker() {
  step 'browser-worker'

  if http_ok "$BROWSER_WORKER_URL/health"; then
    ok "browser-worker уже працює на $BROWSER_WORKER_URL"
    return 0
  fi

  info "запускаємо browser-worker на 127.0.0.1:$WORKER_PORT"
  (
    cd "$WORKER_DIR"
    HOST=127.0.0.1 PORT="$WORKER_PORT" \
    exec "$WORKER_VENV_DIR/bin/python" worker.py
  ) >>"$LOG_DIR/browser-worker.log" 2>&1 &
  register_pid $! 'browser-worker'

  wait_for 'browser-worker' "curl -fsS $BROWSER_WORKER_URL/health" 60 \
    || die "browser-worker не піднявся; деталі в $LOG_DIR/browser-worker.log"
  ok "browser-worker готовий: $BROWSER_WORKER_URL"
}

# ───────────────────── Крок 10: міграції і Celery ────────────────────

run_django() { ( cd "$WEB_DIR" && exec "$VENV_DIR/bin/python" manage.py "$@" ); }

ensure_migrations() {
  step 'Міграції Django'
  # Пароль не друкується: у вивід потрапляє тільки те, чим око перевіряє
  # кластер, і жодного секрету.
  info "PostgreSQL ${POSTGRES_USER}@${POSTGRES_HOST}:${POSTGRES_PORT}/${POSTGRES_DB}"
  run_django migrate --noinput >>"$LOG_DIR/migrate.log" 2>&1 \
    || die "міграції не пройшли; деталі в $LOG_DIR/migrate.log"
  ok 'схема БД актуальна'
}

start_celery() {
  step 'Celery worker + споживач результатів engine'

  if ! _broker_path_enabled; then
    # Процесний runtime виконує workflow-граф у тому ж процесі, де вузол
    # опублікував би задачу, тому Celery і споживач результатів просто не
    # потрібні. Запускати їх «про всяк випадок» — це два процеси, які
    # тримають пам'ять і не роблять нічого.
    skip 'не потрібні для процесного runtime (WORKFLOW_CELERY_ENABLED=1 або WORKFLOW_ENGINE_BROKER_ENABLED=1 — брокерний шлях)'
    return 0
  fi

  if pgrep -f "celery -A core worker" >/dev/null 2>&1; then
    ok 'celery worker уже працює'
  else
    info 'запускаємо celery -A core worker'
    ( cd "$WEB_DIR" && exec "$VENV_DIR/bin/python" -m celery -A core worker --loglevel=info ) \
      >>"$LOG_DIR/celery.log" 2>&1 &
    register_pid $! 'celery'
  fi

  if pgrep -f "manage.py consume_engine_results" >/dev/null 2>&1; then
    ok 'споживач результатів engine вже працює'
  else
    # Саме цей процес читає відповідь движка і просить продовжити run.
    # Без нього workflow-вузол, що опублікував задачу, лишається у
    # стані waiting назавжди.
    info 'запускаємо manage.py consume_engine_results'
    ( cd "$WEB_DIR" && exec "$VENV_DIR/bin/python" manage.py consume_engine_results ) \
      >>"$LOG_DIR/engine-results.log" 2>&1 &
    register_pid $! 'engine-results'
  fi

  # Redis і Celery перевіряються окремо, бо це два різні збої. Redis
  # недоступний — Celery навіть не спробує підключитися. Celery, який
  # піднявся, але не дійшов до `ready`, не споживає жодного workflow
  # (наприклад, падає на неправильній схемі URL), і оператор дізнається
  # про це лише з порожнього Automation. Тому чекаємо на його власний
  # рядок готовності в журналі, а не на «процес десь існує».
  wait_for 'Redis' "redis-cli -p $REDIS_PORT ping" 15 \
    || die 'Redis не відповідає — Celery не може підключитися'

  if pgrep -f "celery -A core worker" >/dev/null 2>&1; then
    wait_for 'celery ready' "grep -qE 'ready\\.|Connected to redis' '$LOG_DIR/celery.log'" 60 \
      || die "celery не дійшов до ready за 60 с; деталі в $LOG_DIR/celery.log"
  fi
  ok 'брокер живий, Celery і споживач результатів запущені'
}

# ─────────────────── Крок 11: блок «Команды проверки» ────────────────

CHECK_NAMES=()
CHECK_RESULTS=()

record_check() {
  CHECK_NAMES+=("$1")
  CHECK_RESULTS+=("$2")
}

# node --check для інлайнового JavaScript: витягуємо інлайновий блок і
# перевіряємо синтаксис, бо сам index.html не є JS-файлом.
#
# Рецепт мусить брати саме HTML-рівень тегів, а не перший-липший `<script>` у
# файлі. Виміряно 2026-10-07 на поточній сторінці: наївний
# `re.findall(r"<script>(.*?)</script>")` стартує з літералу `<script>` усередині
# JS-шаблону генератора звіту (байт 608 482) і закінчується на справжньому
# `</script>` (байт 1 249 636), тобто витягнуті 641 146 байт починаються з
# обривка рядка `` ` reached the document as `` — і `node --check` падає з
# `SyntaxError: Unexpected identifier 'payload'` на **здоровому** файлі.
#
# Розмежування однозначне, бо сам проєкт забороняє писати літеральний закриваючий
# тег у коді, що формує звіт (він збирається з частин), а отже блоки, які JS
# будує як документ, не містять `</script>` узагалі: у файлі їх рівно два —
# вендорний `src` і справжній кінець інлайнового блоку. Тому блок відкриває
# `<script …>` у нульовому стовпці без `src` (тег із nonce), а закриває перший
# `</script>` у нульовому стовпці.
#
# Перевірено цим же способом на поточному файлі: 1 018 901 байт, 19 917 рядків,
# rc=0. AGENTS.md уже описує робочий рецепт саме так («враховує тег із nonce і
# перший `</script>` окремим рядком після нього») — код нижче це і є той рецепт.
check_inline_js() {
  local tmp
  tmp="$(mktemp -t rr-inline-XXXXXX.js)"
  "$VENV_DIR/bin/python" - "$ROOT_DIR/web/templates/lab/index.html" "$tmp" <<'PY'
import re, sys

html = open(sys.argv[1], encoding="utf-8").read()
# Один справжній інлайновий блок: відкриває перший `<script …>` у нульовому
# стовпці без `src`, закриває перший `</script>` у нульовому стовпці після нього.
# Брати всі такі відкривачі не можна: JS будує документи звіту як шаблонні рядки, і
# їхні `<script>` теж стоять у нульовому стовпці, тому «усі блоки» склеїли б у
# витяг поверх справжнього коду і зламали б його.
opens = [m for m in re.finditer(r"^<script\b[^>]*>", html, re.M) if "src=" not in m.group(0)]
closes = [m for m in re.finditer(r"^</script>", html, re.M)]
if not opens or not closes:
    sys.exit("у шаблоні немає інлайнових <script> блоків")
start = opens[0]
end = next((c for c in closes if c.start() > start.start()), None)
if end is None:
    sys.exit("інлайновий <script> блок не закрито")
block = html[start.end():end.start()]
if not block.strip():
    sys.exit("інлайновий <script> блок порожній")
open(sys.argv[2], "w", encoding="utf-8").write(block)
PY
  local extract=$?
  if [ $extract -ne 0 ]; then rm -f "$tmp"; return 1; fi
  node --check "$tmp"
  local rc=$?
  rm -f "$tmp"
  return $rc
}

run_checks() {
  step 'Перевірки (--check)'

  run_one() {
    local name="$1" dir="$2"
    shift 2
    printf '      %-34s ' "$name"
    local start=$SECONDS log
    log="$LOG_DIR/check-$(printf '%s' "$name" | tr -c 'a-zA-Z0-9' '-').log"
    if ( cd "$dir" && "$@" ) >"$log" 2>&1; then
      record_check "$name" 'PASS'
      printf '%sPASS%s  %ss\n' "$C_OK" "$C_OFF" "$((SECONDS - start))"
    else
      record_check "$name" 'FAIL'
      printf '%sFAIL%s  %ss  → %s\n' "$C_ERR" "$C_OFF" "$((SECONDS - start))" "$log"
    fi
  }

  # Django-команди запускаються з очищеним оточенням.
  #
  # Причина виміряна, а не припущена: `WORKFLOW_CELERY_ENABLED=1` або
  # `WORKFLOW_ENGINE_BROKER_ENABLED=1` у спадку переводять тести на
  # брокерний шлях, де publish і обробка результату живуть у різних
  # процесах, і вузол падає з `EngineTaskDeferred: engine task ... is
  # running outside the graph worker`. Той самий набір — 463 тести —
  # дає 58 errors і 3 failures з прапорцями та `OK (skipped=1)` без них.
  #
  # Перевірка має вимірювати документований дефолт незалежно від того, у
  # якому режимі оператор запустив стек, тому прапорці знімаються, а не
  # «наслідуються як є».
  django_clean() {
    env -u WORKFLOW_CELERY_ENABLED -u WORKFLOW_ENGINE_BROKER_ENABLED \
        "$VENV_DIR/bin/python" manage.py "$@"
  }

  # Порядок — від дешевого до дорогого: синтаксис і manage.py check
  # падають за секунди, а -race на engine рахує хвилинами.
  printf '      %-34s ' 'node --check (inline JS)'
  if check_inline_js >"$LOG_DIR/check-node.log" 2>&1; then
    record_check 'node --check (inline JS)' 'PASS'; printf '%sPASS%s\n' "$C_OK" "$C_OFF"
  else
    record_check 'node --check (inline JS)' 'FAIL'
    printf '%sFAIL%s  → %s\n' "$C_ERR" "$C_OFF" "$LOG_DIR/check-node.log"
  fi

  # `git diff --check` шукає конфліктні маркери й кінцеві пробіли в
  # змінах. Без репозиторію перевіряти нічого, тому це SKIP із причиною,
  # а не FAIL: червона позначка на перевірці, яка не залежить від коду,
  # змушує оператора шукати дефект там, де його немає.
  printf '      %-34s ' 'git diff --check'
  if ! git -C "$ROOT_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    record_check 'git diff --check' 'SKIP'
    printf '%sSKIP%s  %s\n' "$C_WARN" "$C_OFF" "немає git-репозиторію (каталог .git відсутній)"
  elif git -C "$ROOT_DIR" diff --check >"$LOG_DIR/check-git.log" 2>&1; then
    record_check 'git diff --check' 'PASS'; printf '%sPASS%s\n' "$C_OK" "$C_OFF"
  else
    record_check 'git diff --check' 'FAIL'
    printf '%sFAIL%s  → %s\n' "$C_ERR" "$C_OFF" "$LOG_DIR/check-git.log"
  fi

  # Go-тести теж мають вимірювати документований дефолт, а не режим, у
  # якому оператор запустив стенд.
  #
  # Причина виміряна 2026-10-07 контрольним прогоном тих самих тестів з
  # тим самим деревом: без ключа брокера — `ok`, з ключем —
  # `FAIL: TestProcessTaskDeliveryPublishesBeforeAck`,
  # `FAIL: TestRedisConsumerTakesATaskInFlightAndAcksAfterTheResult`. Скрипт
  # експортує `RR_ENGINE_BROKER_KEY` (генерується раз на інсталяцію в
  # `data/run/broker_key`), тому `--check` вимірював «налаштований брокер»,
  # тоді як тести утверджують документовану сумісність — непідписані
  # envelope приймаються з гучним попередженням, а не відкидаються з
  # `BAD_SIGNATURE`. Перевірка, чий результат залежить від оточення
  # запуску, перевіркою не є.
  go_clean() {
    env -u RR_ENGINE_BROKER_KEY "$@"
  }

  run_one 'python manage.py check' "$WEB_DIR" \
    django_clean check
  run_one 'go test ./... -count=1' "$ENGINE_DIR" \
    go_clean go test ./... -count=1
  run_one 'go test ./... -race' "$ENGINE_DIR" \
    go_clean go test ./... -count=1 -race
  # `--noinput` тут не «заглушити запит», а необхідність: тестова база
  # створюється runner-ом і лишається після падіння, тому наступний
  # прогін питає «type yes to delete it». У скрипті немає TTY, і Django
  # падає з EOFError замість того, щоб пересоздати базу, яка за
  # визначенням є одноразовою.
  run_one 'python manage.py test' "$WEB_DIR" \
    django_clean test --noinput -v 2

  # Підсумок рахує FAIL, а SKIP — ні: пропущена перевірка не робить
  # зведення зеленим і не робить його червоним, вона окремо називає
  # себе причиною, щоб її не можна було сплутати з результатом.
  local failed=0 skipped=0 name result
  printf '\n'
  for i in "${!CHECK_NAMES[@]}"; do
    name="${CHECK_NAMES[$i]}"; result="${CHECK_RESULTS[$i]}"
    case "$result" in
      PASS) printf '      %-34s %s%s%s\n' "$name" "$C_OK" 'PASS' "$C_OFF" ;;
      SKIP) printf '      %-34s %s%s%s\n' "$name" "$C_WARN" 'SKIP' "$C_OFF"
            skipped=$((skipped + 1)) ;;
      *)    printf '      %-34s %s%s%s\n' "$name" "$C_ERR" 'FAIL' "$C_OFF"
            failed=$((failed + 1)) ;;
    esac
  done

  if [ "$failed" -gt 0 ]; then
    die "$failed з ${#CHECK_NAMES[@]} перевірок не пройшли; логи в $LOG_DIR/check-*.log"
  fi
  if [ "$skipped" -gt 0 ]; then
    ok "усі перевірки пройшли ($skipped пропущено з причиною вище)"
  else
    ok "усі ${#CHECK_NAMES[@]} перевірок пройшли"
  fi
}

# ───────────────────────── Зупинка стеку (--stop / --restart) ─────────
#
# Скільки часу даємо процесу на коректний вихід перед SIGKILL. 10 секунд —
# стільки ж, скільки дає `cleanup`, щоб поведінка «Ctrl+C» і «--stop» не
# відрізнялися в одному і тому ж сценарії.
STOP_GRACE_TICKS=20

# Стан процесу з /proc: `Z` — зомбі. Зомбі вже мертвий і лише чекає, поки
# його забере батько, тому `kill -0` на ньому вдається, а SIGKILL нічого
# не робить. Без цієї перевірки `--stop` друкував би «не завершився за 10 с»
# на процесі, який завершився ще до виклику.
_proc_state() {
  local stat
  stat="$(cat "/proc/$1/stat" 2>/dev/null)" || return 1
  [ -n "$stat" ] || return 1
  stat="${stat##*) }"
  awk '{ print $1 }' <<<"$stat"
}

# Яким сигналом зупиняти сервіс.
#
# runserver і celery виходять з SIGINT коректно, а SIGTERM для них означає
# «померти без підчищення» — саме це вже написано в `cleanup`. У PostgreSQL
# значення протилежне: SIGINT — це fast shutdown (обриває транзакції й
# не чекає клієнтів), а SIGTERM — smart shutdown, який на занятому кластері
# не завершиться ніколи.
_stop_signal() {
  case "$1" in
    web|celery|postgres) printf 'INT' ;;
    *)                   printf 'TERM' ;;
  esac
}

# Нащадки PID, глибші — першими.
#
# Потрібно тому, що один PID — не достатньо. Виміряно 2026-09-30 на чистій
# інсталяції: Django `runserver` з autoreloader форкає дитину, `start.sh`
# реєструє `$!` батька, `kill` убиває батька — а дитина осиротіває з
# PPID=1, лишається слухати порт і далі відповідає 200. `--stop` при цьому
# друкував «зупинено», тобто повідомив про успіх, якого не було.
#
# Дерево збирається ОДИН раз, до вбивства: щойно батько помер, дитина
# переїжджає до init (PPID=1) і стає недосяжною через ланцюг PPID.
#
# Джерело PPID — /proc, а не `ps -o ppid= -p`: список процесів з `ps`
# обрізається, коли він великий, а в /proc воно читається поіменно.
_process_descendants() {
  local root="$1"
  local -a level=("$root") out=() next=()
  local -A parent=()
  local pid cpid ppid stat line

  # Знімок PPID один раз на весь обхід. Читати /proc окремо для кожного
  # PID на кожному рівні — це квадратична робота, а на машині з engine,
  # Django і браузером процесів достатньо, щоб це було помітно.
  for stat in /proc/[0-9]*/stat; do
    [ -r "$stat" ] || continue
    # comm у лапках може містити пробіли, тому PPID береться з хвоста
    # після останньої `) ` — інакше зміщені поля зсовуються.
    line="$(sed 's/^[0-9]* //; s/^.*) //' "$stat" 2>/dev/null)" || continue
    pid="${stat#/proc/}"; pid="${pid%/stat}"
    ppid="$(awk '{ print $2 }' <<<"$line")"
    [ -n "$ppid" ] && parent["$pid"]="$ppid"
  done

  while [ "${#level[@]}" -gt 0 ]; do
    next=()
    for pid in "${level[@]}"; do
      for cpid in "${!parent[@]}"; do
        [ "${parent[$cpid]}" = "$pid" ] || continue
        out+=("$cpid")
        next+=("$cpid")
      done
    done
    level=(${next[@]+"${next[@]}"})
  done
  [ "${#out[@]}" -gt 0 ] && printf '%s\n' "${out[@]}"
  return 0
}

# Зупиняє дерево процесу: спершу нащадки, потім корінь.
#
# Сигнал один і той самий для всього дерева, бо процес не має підсигналів —
# підсигнал ставиться всередині обробника. Після SIGKILL перевіряється
# кожен PID дерева, а не лише корінь.
_stop_tree() { # _stop_tree <pid> <сигнал> -> 0 усі зникли, 1 лишилися
  local pid="$1" sig="$2" i target alive pstate
  local -a tree=() descendants=()
  mapfile -t descendants < <(_process_descendants "$pid")
  if [ "${#descendants[@]}" -gt 0 ]; then
    tree=("${descendants[@]}")
  fi
  tree+=("$pid")

  for target in "${tree[@]}"; do
    kill -"$sig" "$target" 2>/dev/null || true
  done

  for (( i=0; i<STOP_GRACE_TICKS; i++ )); do
    local alive=0
    for target in "${tree[@]}"; do
      pstate="$(_proc_state "$target" 2>/dev/null)" || continue
      [ "$pstate" = Z ] && continue
      alive=1
    done
    [ "$alive" -eq 0 ] && return 0
    sleep 0.5
  done

  for target in "${tree[@]}"; do
    kill -KILL "$target" 2>/dev/null || true
  done
  for (( i=0; i<STOP_GRACE_TICKS; i++ )); do
    local alive=0
    for target in "${tree[@]}"; do
      pstate="$(_proc_state "$target" 2>/dev/null)" || continue
      [ "$pstate" = Z ] && continue
      alive=1
    done
    [ "$alive" -eq 0 ] && return 0
    sleep 0.5
  done
  return 1
}

# Зупиняє все, що записано у файлі стану, — і тільки це.
#
# Чому файл стану, а не пошук за портами: порт зайнятий і нашим engine, і
# чужим стендом, і за портом ці два випадки не відрізнити. Запис у файлі
# стану каже «цей PID підняв цей скрипт», а `starttime` каже «це досі той
# самий процес». Тому чужий стенд, піднятий вручну або іншою копією
# репозиторію, `--stop` не зачіпає навіть випадково.
# Перелік усього, що `--stop` зможе зупинити, у вигляді рядків
# `ім'я pid starttime cmdline`.
#
# Джерела два, і обидва є доказом приналежності:
#
#   1. PID-файли в data/ — цей каталог створює ensure_postgres /
#      ensure_redis / ensure_tor, і чужого кластера або чужого redis
#      тут бути не може. Крок не декоративний: виміряно 2026-09-30, запуск
#      впав на складанні engine (`403 Forbidden` на модулі nuclei),
#      `cleanup` спрацював, але STARTED_PIDS був порожній — і PostgreSQL
#      та Redis лишилися живими без жодного запису у файлі стану.
#   2. Рядки файлу стану — те, що записали попередні запуски.
#
# PID-файли йдуть ПЕРШИМИ, і це не порядок для краси: `stop_stack` читає
# перелік у зворотному порядку, тож web гаситься першим, а PostgreSQL —
# останнім, як у `cleanup`.
owned_processes() {
  local name path pid stime spec
  for spec in "postgres:$PGDATA/postmaster.pid" \
              "redis:$REDIS_DIR/redis.pid" \
              "tor:$DATA_DIR/tor/tor.pid"; do
    name="${spec%%:*}"; path="${spec#*:}"
    # Те, що вже є у файлі стані, двічі не обробляємо.
    if [ -f "$STATE_FILE" ] && grep -q "^$name[[:space:]]" "$STATE_FILE"; then
      continue
    fi
    pid="$(_pidfile_pid "$path")" || continue
    stime="$(_proc_starttime "$pid")" || continue
    printf '%s %s %s %s\n' "$name" "$pid" "$stime" "$(_proc_cmdline "$pid")"
  done
  if [ -f "$STATE_FILE" ]; then
    grep -v '^[[:space:]]*$' "$STATE_FILE" 2>/dev/null || true
  fi
}

# Перезапускає ТІЛЬКИ engine: перебудовує бінарник, гасить наш процес
# рушія, піднімає новий і чекає на /health.
#
# Навіщо окремо від `--restart`: зміни в engine не можуть підхопитися,
# поки працює процес зі старого бінарника, а `--restart` гасить увесь
# стек — разом із відкритими сесіями та будь-яким довгим сканом.
#
# Умова «це наш процес» та сама, що в `stop_stack`: запис у файлі стану
# ПЛЮС збіг starttime у /proc. Чужий стенд на тому самому порту не
# зачіпається — інакше прапорець, доданий для зручності, став би способом
# зупинити сусідню сесію.
restart_engine() {
  step 'Перезапуск engine'

  local pid stime recorded now_stime
  pid=''; recorded=''
  if [ -f "$STATE_FILE" ]; then
    read -r pid recorded < <(grep '^engine[[:space:]]' "$STATE_FILE" 2>/dev/null | head -1 | awk '{print $2, $3}') || true
  fi

  if ! build_engine_binary; then
    die 'перебудова engine не вдалася'
  fi

  if [ -z "$pid" ] || [ -z "$recorded" ]; then
    skip "engine не записаний у $STATE_FILE — перезапускати нічого"
    info "піднімаємо engine, якщо він ще не працює: ./start.sh"
    return 0
  fi

  now_stime="$(_proc_starttime "$pid" 2>/dev/null)" || now_stime=''
  if [ -z "$now_stime" ] || [ "$now_stime" != "$recorded" ]; then
    # Або процесу немає, або номер перероблений. У другому випадку PID
    # належить не нам, і вбивати його не можна ніколи.
    skip "engine (pid $pid) уже не працює або PID перероблено — зупиняти нічого"
  else
    # Діти engine — це активні nuclei-процеси. SIGTERM кореню engine
    # передається їхньому контейнеру, але явна гасіння по дереву
    # (_stop_tree) прибирає і дочірні nuclei, які інакше лишилися б
    # сиротами, займаючи CPU після перезапуску.
    info "зупиняємо engine (pid $pid) разом із його nuclei-процесами"
    _stop_tree "$pid" "$(_stop_signal engine)" \
      || warn "engine (pid $pid) не зупинився повністю — див. $LOG_DIR/engine.log"
  fi

  info "запускаємо engine на 127.0.0.1:$ENGINE_PORT, проксі на 127.0.0.1:$PROXY_PORT"
  (
    cd "$ENGINE_DIR"
    GOMEMLIMIT="${GOMEMLIMIT:-2GiB}" \
    PROXY_LISTEN_ADDR="127.0.0.1:$PROXY_PORT" \
    ENGINE_LISTEN_ADDR="127.0.0.1:$ENGINE_PORT" \
    exec "$ENGINE_BINARY"
  ) >>"$LOG_DIR/engine.log" 2>&1 &
  register_pid $! 'engine'

  wait_for 'engine' "curl -fsS $ENGINE_URL/health" 60 \
    || die "engine не піднявся після перезапуску; деталі в $LOG_DIR/engine.log"
  ok "engine перезапущено: $ENGINE_URL (CA: $CA_DIR)"
}

# Зупиняє все, що повертає `owned_processes` — і тільки це.
#
# Чому не пошук за портами: порт зайнятий і нашим engine, і чужим
# стендом, і за портом ці два випадки не відрізнити. `starttime` каже
# «це досі той самий процес», тому чужий стенд, піднятий вручну або іншою
# копією репозиторію, `--stop` не зачіпає навіть випадково.
stop_stack() {
  local -a lines=() keep=()
  mapfile -t lines < <(owned_processes)

  if [ "${#lines[@]}" -eq 0 ]; then
    skip "немає ні файлу стану $STATE_FILE, ні pid-файлів у data/ — зупиняти нічого"
    return 0
  fi

  local i name pid stime cmdline sig pstate now_stime stopped=0
  local gone=0 reused=0 alive_after=0
  # Зворотний порядок: залежні процеси (web, engine-results, celery)
  # гасяться раніше тих, від яких вони залежать (engine, redis, postgres).
  for (( i=${#lines[@]}-1; i>=0; i-- )); do
    [ -n "${lines[$i]}" ] || continue
    read -r name pid stime cmdline <<<"${lines[$i]}"

    pstate="$(_proc_state "$pid" 2>/dev/null)" || pstate=''
    if [ -z "$pstate" ]; then
      skip "$name (pid $pid) — процесу немає"
      gone=$((gone + 1))
      continue
    fi
    if [ "$pstate" = 'Z' ]; then
      skip "$name (pid $pid) — процес уже мертвий (zombie)"
      gone=$((gone + 1))
      continue
    fi

    now_stime="$(_proc_starttime "$pid")" || now_stime=''
    if [ -z "$now_stime" ]; then
      # /proc читається для живого процесу, тому це не штатний стан.
      # Запис лишаємо: краще лишній запис у файлі, ніж забутий процес.
      warn "$name (pid $pid) — не вдалося прочитати /proc, запис лишаємо"
      keep+=("${lines[$i]}")
      continue
    fi
    if [ "$now_stime" != "$stime" ]; then
      # PID перероблений: наш процес помер, а номер уже займає хтось
      # інший. Убивати його не можна — це вже не наш стенд.
      warn "$name (pid $pid) — starttime не збігається, не чіпаємо: ${cmdline:-?}"
      reused=$((reused + 1))
      continue
    fi

    sig="$(_stop_signal "$name")"
    # Відмова в самому сигналі перевіряється ДО `_stop_tree`, бо вона
    # про права, а не про впертість. Без цієї окремої перевірки root-процес
    # дістав би «НЕ зупинено: живий навіть після SIGKILL» — а SIGKILL ми
    # навіть не надсилали, бо нам не дають права. Різниця між «не можемо»
    # і «не хоче» — не різниця у формулюванні.
    if ! kill -"$sig" "$pid" 2>/dev/null; then
      warn "$name (pid $pid) — не вдалося надіслати SIG$sig (запуск від root?)"
      keep+=("${lines[$i]}")
      continue
    fi
    if _stop_tree "$pid" "$sig"; then
      ok "$name (pid $pid) — зупинено сигналом SIG$sig"
      stopped=$((stopped + 1))
    elif _proc_state "$pid" >/dev/null 2>&1; then
      # Корінь живий навіть після SIGKILL по дереву. Рахувати його
      # зупиненим — пряма брехня: оператор потім побачить зайнятий порт
      # і не матиме жодного способу зрозуміти, чому `--stop` відповів
      # «зупинено». Запис лишаємо, щоб повторний `--stop` його догасив.
      warn "$name (pid $pid) — НЕ зупинено: живий навіть після SIGKILL"
      alive_after=$((alive_after + 1))
      keep+=("${lines[$i]}")
    else
      # Корінь зник, але в дереві лишився нащадок: це той самий випадок,
      # що й раніше, тільки тепер ми його бачимо, а не повідомляємо
      # про успіх.
      warn "$name — корінь зник, але нащадок лишився живий; запис лишаємо"
      alive_after=$((alive_after + 1))
      keep+=("${lines[$i]}")
    fi
  done

  # Вийнятки «зупинено», «немає процесу» і «PID перероблено» роблять запис
  # неактуальним. Лишаємо лише ті, з якими нічого не вдалося зробити, тож
  # наступний `--stop` спробує ще раз. Порожній файл видаляємо, а не
  # залишаємо мертвим.
  if [ "${#keep[@]}" -gt 0 ]; then
    printf '%s\n' "${keep[@]}" >"$STATE_FILE"
  else
    rm -f "$STATE_FILE"
  fi

  printf '\n'
  if [ "$stopped" -gt 0 ]; then
    ok "зупинено $stopped"
  fi
  if [ "$gone" -gt 0 ]; then
    skip "вже не працювали: $gone"
  fi
  if [ "$reused" -gt 0 ]; then
    warn "PID перероблено, залишено чужим: $reused"
  fi
  if [ "$alive_after" -gt 0 ]; then
    warn "НЕ зупинено $alive_after — живі й далі, записи лишилися у $STATE_FILE"
  fi
  # Окремий рядок про записи, з якими нічого не вийшло. Без нього
  # оператор бачить «не вдалося надіслати сигнал» угорі й жодної
  # підказки, що запис уцілів і наступний `--stop` спробує ще раз.
  # Рядок зник, коли з-під мутації M3 відновлювали лічильник
  # `alive_after` — знайдено ізольованим тестом 2026-09-30, після того
  # як два інші тести були зелені.
  if [ "${#keep[@]}" -gt 0 ]; then
    warn "записів лишилося у файлі стану: ${#keep[@]} (${STATE_FILE}) — наступний --stop спробує ще раз"
  fi
  printf '      %s\n' "Дані не видалялися: БД, логи, CA, шаблони nuclei — у data/."
  printf '      %s\n' "Процеси, запущені вручну або іншою копією, --stop не чіпає."

  # Код виходу каже, чи стек зупинено повністю. 0 — усі записані процеси
  # або зупинено, або їх уже не було. Ненуль — лишався живий процес або
  # запис, який не вдалося опрацювати.
  [ "$alive_after" -eq 0 ] && [ "${#keep[@]}" -eq 0 ]
}

# ───────────────────────────── Збірка ───────────────────────────────

cleanup() {
  local status=$?
  trap - EXIT INT TERM

  if [ "${#STARTED_PIDS[@]}" -gt 0 ]; then
    printf '\n%sЗупиняємо те, що підняв цей скрипт:%s\n' "$C_DIM" "$C_OFF"
    local i sig
    # Зворотний порядок: залежні процеси гасимо першими.
    for (( i=${#STARTED_PIDS[@]}-1; i>=0; i-- )); do
      local pid="${STARTED_PIDS[$i]}" name="${STARTED_NAMES[$i]}"
      if kill -0 "$pid" 2>/dev/null; then
        # runserver і celery віддають SIGINT самому себе; SIGTERM для
        # них означає «померти без підчищення», а ми хочемо коректний вихід.
        sig="$(_stop_signal "$name")"
        # Дерево, а не один PID: Django runserver з autoreloader форкає
        # дитину, і kill по батьку лишав її осиротілою з живим портом.
        # Виміряно 2026-09-30 на чистій інсталяції — той самий дефект, що
        # був у `--stop`.
        if _stop_tree "$pid" "$sig"; then
          state_forget "$name"
          printf '      %s· %s (pid %s)%s\n' "$C_DIM" "$name" "$pid" "$C_OFF"
        else
          # Не брешемо: лишаємо запис, щоб наступний `--stop` догасив.
          printf '      %s! %s (pid %s) не зупинився%s\n' "$C_WARN" "$name" "$pid" "$C_OFF"
        fi
      fi
    done
  fi
  exit "$status"
}

main() {
  mkdir -p "$LOG_DIR"
  trap cleanup EXIT INT TERM

  # --stop не запускає нічого, тому банер з адресами піднятого стеку тут
  # брехня: після нього не буде жодного рядка про працюючий сервіс.
  if [ "$RUN_STOP_ONLY" -eq 1 ]; then
    if [ "$RUN_CHECK" -eq 1 ]; then
      printf 'start.sh: --stop не сумісний з --check — перевірки пропущено\n' >&2
    fi
    step 'Зупинка стеку'
    local stop_rc=0
    stop_stack || stop_rc=$?
    trap - EXIT INT TERM
    exit "$stop_rc"
  fi

  print_banner

  # --restart = --stop + звичайний запуск. Саме в такому порядку: кроки
  # ensure_* перевіряють «вже працює — не чіпаю», тому без зупинки
  # рестарт перейменувався б у повторний запуск поверх старого стеку.
  # --restart-engine не сумісний з --stop/--restart: перший перезапускає
  # один сервіс, другий гасить увесь стенд, і разом вони означали б
  # «зупини все, потім підніми тільки engine» — тобто стенд, у якому
  # web, postgres і redis мертві. Це не те, що просили.
  if [ "$RUN_RESTART_ENGINE" -eq 1 ] \
     && { [ "$RUN_STOP_ONLY" -eq 1 ] || [ "$RUN_RESTART" -eq 1 ] || [ "$RUN_STATUS_ONLY" -eq 1 ]; }; then
    printf 'start.sh: --restart-engine не поєднується з --stop/--restart/--status\n' >&2
    exit 2
  fi

  # --restart-engine = перебудувати й перезапустити лише engine, решту
  # стенду не чіпаючи. Виконується після банера, бо оператор має бачити
  # адреси того стенду, у якому це відбувається.
  if [ "$RUN_RESTART_ENGINE" -eq 1 ]; then
    restart_engine
    print_status
    printf '  UI      http://127.0.0.1:%s (engine перезапущено, решта стенду не чіпали)\n\n' \
      "$RUNSERVER_PORT"
    # Рушій живий і має бути живий далі: EXIT-ловушка `cleanup` на
    # виході згасила б саме те, що щойно підняли.
    trap - EXIT INT TERM
    return 0
  fi

  if [ "$RUN_RESTART" -eq 1 ]; then
    step 'Зупинка перед рестартом'
    # Не зупинилося — не зупиняємо рестарт: наступні кроки самі скажуть
    # про кожен зайнятий порт, а мовчазно зупинитися на півдорозі —
    # це стан, у якому оператор не розуміє, що відбувається.
    stop_stack || warn 'деякі процеси лишилися живими — див. рядок вище'
  fi

  if [ "$RUN_STATUS_ONLY" -eq 1 ]; then
    print_status
    trap - EXIT INT TERM
    exit 0
  fi

  ensure_packages
  ensure_ca_trusted
  ensure_go
  ensure_web_venv
  harden_service_log_permissions
  harden_run_secret_permissions
  ensure_worker_venv
  ensure_playwright_browser
  # Chromium для Playwright не входить у `ensure_playwright_browser` (та функція ставить
  # лише Firefox), але контактирує з тією ж кешем і тим самим венв. Ставимо окремо,
  # щоб `./start.sh` фактично гарантував наявність усіх runtime-ів браузерного режиму.
  ensure_playwright_chromium
  # Camoufox — окремий крок, а не хвіст `ensure_playwright_browser`: Firefox
  # на цій машині вже завантажений, тож та функція повертається раніше, ніж
  # дійде до нього. Пояснення вимірювання — над вилученим викликом.
  ensure_camoufox
  ensure_nuclei
  ensure_httpx
  ensure_postgres
  ensure_redis
  ensure_tor
  ensure_engine
  start_browser_worker
  ensure_migrations
  start_celery

  if [ "$RUN_CHECK" -eq 1 ]; then
    run_checks
  else
    step 'Перевірки'
    skip 'не запускалися (--check — прогнати блок «Команды проверки»)'
  fi

  # runserver запускається ДО таблиці стану, і таблиця друкується після
  # його готовності. Інакше вона показує `web DOWN` на той самій секунді,
  # коли скрипт уже повідомляє «стек піднято» і просить відкрити саме цей
  # URL: Django вже відповідає 200, а оператор бачить суперечність і не
  # має підстав вірити жодному рядку таблиці.
  # Якщо web уже відповідає, другий runserver не потрібен: engine і
  # browser-worker перевіряються рівно так (див. вище), а web був єдиним
  # без такої перевірки — і падав на «That port is already in use», коли
  # оператор уже мав стенд відкритим у іншому терміналі. Виміряно
  # 2026-09-29: блок перевірок при цьому повністю зелений, тобто падіння
  # було не в коді, а в кроці підйому після нього.
  if http_ok "http://127.0.0.1:$RUNSERVER_PORT/"; then
    ok "web уже працює на http://127.0.0.1:$RUNSERVER_PORT"
    print_status
    printf '  UI      http://127.0.0.1:%s\n' "$RUNSERVER_PORT"
    printf '  журнали %s\n\n' "$LOG_DIR"
    # Скрипт завершується, а стенд — ні. Trap-и знімаються саме тут: у цьому
    # сценарії запускається не все, а лише те, чого бракувало (engine або
    # browser-worker), і EXIT-ловушка `cleanup` на виході гасила ровно те, що
    # цей запуск щойно підняв.
    #
    # Виміряно 2026-09-30: стенд із живим web і мертвим browser-worker, тобто
    # рівно той стан, заради якого оператор і запускає скрипт. Вивід був
    # такий:
    #
    #     ✓ browser-worker готовий: http://127.0.0.1:8090
    #     ...
    #     Зупиняємо те, що підняв цей скрипт:
    #           · browser-worker (pid 430146)
    #
    # за секунду `./start.sh --status` знову показував `browser-worker DOWN`, і
    # оператор знову отримував `[Errno 111] Connection refused` від gateway.
    # Тобто документований «єдиний вхід» не умів лагодити частково упавший
    # стенд: він піднімав сервіс і сам же його прибивав.
    #
    # Права на `--stop`/`--restart` цим не віднімаються: `register_pid` уже
    # записав pid і starttime у `data/stack.state`, тому `stop_stack` знайде й
    # гаситиме саме ці процеси — за тими самими правилами, що й у звичайному
    # режимі.
    trap - EXIT INT TERM
    return 0
  fi

  info "запускаємо Django UI на 127.0.0.1:$RUNSERVER_PORT"
  ( cd "$WEB_DIR" && exec "$VENV_DIR/bin/python" manage.py runserver "127.0.0.1:$RUNSERVER_PORT" ) &
  local web_pid=$!
  register_pid "$web_pid" 'web'
  wait_for 'web' "curl -fsS http://127.0.0.1:$RUNSERVER_PORT/" 90 \
    || die "Django не відповів за 90 с; деталі в $LOG_DIR/migrate.log і вивід нижче"

  printf '\n%s✓ Стек піднято%s\n' "$C_OK" "$C_OFF"
  print_status
  printf '  UI      http://127.0.0.1:%s\n' "$RUNSERVER_PORT"
  printf '  журнали %s\n' "$LOG_DIR"
  printf '  Ctrl+C зупиняє engine, browser-worker, Celery, споживач і web.\n\n'

  # runserver лишається на передньому плані: це єдиний процес, який
  # зупиняє Ctrl+C, і оператор бачить його журнал прямо в терміналі.
  wait "$web_pid"
}

main "$@"
