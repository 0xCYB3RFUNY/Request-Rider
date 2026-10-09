#!/usr/bin/env bash
#
# Request-Rider — рабочий Docker-стенд: установка, сборка, запуск, отладка.
#
#   ./docker-stand.sh                    то же, что up
#   ./docker-stand.sh doctor             диагностика окружения (и до установки, и после)
#   ./docker-stand.sh install            поставить Docker и выдать группу docker
#   ./docker-stand.sh up                 собрать образы, поднять стенд, дождаться готовности
#   ./docker-stand.sh build              только собрать образы
#   ./docker-stand.sh status             что поднято
#   ./docker-stand.sh check              проверки по реальным путям хост → web → engine
#   ./docker-stand.sh logs [-f] [сервис] журналы
#   ./docker-stand.sh top                чем заняты контейнеры
#   ./docker-stand.sh shell <сервис>     шелл внутри контейнера
#   ./docker-stand.sh exec <сервис> ...  команда внутри контейнера
#   ./docker-stand.sh dbshell            psql внутри postgres
#   ./docker-stand.sh restart [сервис…]  пересоздать всё или указанные сервисы
#   ./docker-stand.sh stop               остановить контейнеры, тома целы
#   ./docker-stand.sh down               снести контейнеры и сеть, тома целы
#   ./docker-stand.sh destroy            снести всё вместе с томами (данные пропадут)
#   ./docker-stand.sh ports              кто держит порты стенда
#   ./docker-stand.sh direct on|off|status   маршрут: напрямую или через Tor
#   ./docker-stand.sh tor                    диагностика Tor: загрузка, мосты, транспорт
#   ./docker-stand.sh env                файл секретов: путь и какие ключи заданы
#
# Это НЕ тестовый стенд. Тестовый живёт в `docker-compose.test.yml` под
# проектом `rr_test`, на портах 18xxx/15xxx, и запускается напрямую через
# Docker Compose. Здесь — рабочий compose из
# `docker-compose.yml`: восемь сервисов, проект `request-rider`, порты 28xxx/25xxx.
#
# ───────────────────────────── Что стенд наружу не отдаёт ─────────────────
#
# Публикуются только 127.0.0.1, поэтому с хоста стенд виден лишь этому
# пользователю. Внутренняя сеть compose при этом не изолирует исходящий трафик
# (`internal: true` не выставлен ни здесь, ни в базовом файле), и это сделано
# намеренно: Tor, OSINT-сбор, nuclei и атаки ходят к целям в интернете. Если
# поставить `internal: true`, стенд поднимется и останется без сети — Tor не
# забустится, а инструменты будут падать на ровно тех запросах, ради которых
# существуют.
#
# ───────────────────────────── Чего скрипт НЕ делает ─────────────────────
#
#   * не останавливает нативный стенд. Порты разведены (28xxx против 8000),
#     так что это не нужно; а если порт занят — скрипт называет, кто его
#     держит, и не трогает процесс. Случай из AGENTS.md: проверка, которая
#     гасила PostgreSQL и Redis чужой сессии по pid-файлам в общем `data/`.
#   * не трогает проект `rr_test` даже при совпадении имён: у compose-проекта
#     `-p requestrider` задан явно и от каталога не зависит.
#   * не делает `docker system prune`: это ресурсы чужих проектов.
#   * не публикует порты наружу. Удалённый доступ — это ещё и ALLOWED_HOSTS:
#     в `web/core/settings.py` он жёстко `["localhost", "127.0.0.1"]`, и без
#     его расширения Django ответит DisallowedHost на любой запрос по адресу
#     машины. Один флаг портов тут не помог бы.
#
# ─────────────────────────── Что пришлось чинить ─────────────────────────
#
# ───────────────────────────── Tor в контейнере ───────────────────────────
#
# На сети, которая вмешивается в соединения с ретрансляторами, Tor не
# поднимается ни при какой настройке: сокет открывается, а TLS-рукопожатие
# обрывается (проверено и Tor, и `openssl s_client`, на четырёх разных реле, при
# том что обычный HTTPS с того же хоста отвечает). Помогает только обфускация
# obfs4, а она бесполезна без мостов, которые выдаются по CAPTCHA и в репозиторий
# не кладутся. Положите их в `data/run/tor.bridges` и выполните
# `./docker-stand.sh restart tor`. Подробности — `./docker-stand.sh tor`.
#
# ───────────────────────────── Что пришлось чинить ────────────────────────
#
# `docker-compose.yml` сам по себе стенд не поднимает; правки вынесены в
# `docker-stand.overlay.yml` и объяснены там. Коротко: движок делает
# `log.Fatalf` на `0.0.0.0` без `RR_ALLOW_NON_LOOPBACK_BIND=1`, а порты
# 8000/8080/8081 совпадают с портами нативного стенда.
#
# Отдельно — третий дефект, который правится не в compose, а в приложении:
# и движок, и browser-worker отвечают 403 на не-loopback `Host`, а под
# контейнерами Django ходит к ним по имени сервиса. Заголовки собраны в
# `web/lab/engine_client.py::internal_service_headers`, и все три места
# вызова — `EngineClient.request`, `open_engine_stream` и `_worker_headers` —
# берут их оттуда. Ключ в `open_engine_stream` не был проведён вообще: с
# включённым ключом живая лента событий отдавала 403.

set -Eeuo pipefail

# Журналы и файлы секретов — только владельцу. `umask` действует в момент
# создания, поэтому ставится до первого касания файлов, а не после.
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="$ROOT_DIR/docker-compose.yml"
OVERLAY_FILE="$ROOT_DIR/docker-stand.overlay.yml"
ENV_FILE="$ROOT_DIR/data/run/compose.env"
# Выбранный оператором маршрут. Лежит рядом с секретами в игнорируемом `data/run`.
#
# Нужен потому, что `ROUTE_ADDRESS` — это переменная окружения контейнера, и
# переживает только пересоздание. Измеренный факт: `docker-stand.sh direct on`,
# а потом `restart` (то есть `up -d` с нуля) — и движок снова получает
# `tor:9050`, потому что compose подставляет своё значение по умолчанию. Стенд
# после этого стоит, а трафик через прокси упирается в неработающий Tor.
#
# Это память о ЯВНОМ решении оператора, а не выбор за него: пока файл не создан,
# поведение прежнее — Tor по умолчанию, и `up` только предупреждает.
ROUTE_STATE_FILE="$ROOT_DIR/data/run/stand.route"
# Конфигурация Tor собирается скриптом и монтируется в контейнер.
#
# На этой машине Tor не выходит из строя ни при какой настройке: TLS к
# ретранслятору рвётся на рукопожатии (см. комментарий в `tor/Dockerfile`, там
# четыре независимые проверки). Единственный известный обход — obfs4, а obfs4
# бесполезен без адресов мостов. Мосты не коммитятся, потому что они выдаются
# под конкретную сеть и по CAPTCHA; оператор кладёт их в `data/run/tor.bridges`
# по одной строке на мост, и они подхватываются при следующем запуске.
TOR_CONFIG_FILE="$ROOT_DIR/data/run/torrc"
TOR_BRIDGES_FILE="$ROOT_DIR/data/run/tor.bridges"

ensure_tor_config() {
  mkdir -p "$ROOT_DIR/data/run"
  # Docker создаёт отсутствующий источник bind-mount КАТАЛОГОМ, без всякого
  # предупреждения: измеренный сбой — `restart tor` отдал
  # «error mounting ... torrc: not a directory», потому что путь ещё не
  # существовал и превратился в пустой каталог. Пустой каталог убирается и
  # заменяется файлом; непустой — это уже данные, и их не трогают молча.
  if [ -d "$TOR_CONFIG_FILE" ]; then
    if [ -z "$(ls -A "$TOR_CONFIG_FILE" 2>/dev/null)" ]; then
      rmdir "$TOR_CONFIG_FILE" || die "не удалось убрать каталог $TOR_CONFIG_FILE"
      warn 'пустой каталог на месте torrc (его создал Docker) — заменён файлом'
    else
      die "$TOR_CONFIG_FILE — непустой каталог, а нужен файл. Уберите его вручную."
    fi
  fi

  printf 'DataDirectory /var/lib/tor\nSocksPort 0.0.0.0:9050\nLog notice stdout\n' \
    >"$TOR_CONFIG_FILE"

  [ -s "$TOR_BRIDGES_FILE" ] || { chmod 644 "$TOR_CONFIG_FILE"; return 0; }

  local line kept=0 fixed=0 dropped=0
  {
    printf '\n# Мосты из %s\n' "${TOR_BRIDGES_FILE##*/}"
    printf 'UseBridges 1\n'
    printf 'ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy\n'

    # Каждая строка проверяется отдельно, потому что tor либо принимает весь
    # конфиг, либо не принимает ни одной строки: одна мусорная строка уронила бы
    # контейнер в перезапуск, а причина в логе указывала бы совсем не туда.
    while IFS= read -r line; do
      case "$line" in
        \#*|"") continue ;;
      esac
      case "$line" in
        Bridge\ *)
          printf '%s\n' "$line"
          kept=$((kept + 1))
          ;;
        # Ошибка копипасты, а не опечатка: строка моста без префикса `Bridge `
        # tor считает неизвестной директивой и отказывается от всего файла.
        # Префикс восстанавливается, а не теряется — иначе оператор решил бы,
        # что мост сломан, и выкинул бы рабочий.
        obfs4\ *|snowflake\ *|scramblesuit\ *)
          printf 'Bridge %s\n' "$line"
          kept=$((kept + 1)); fixed=$((fixed + 1))
          ;;
        *)
          warn "строка в tor.bridges не похожа на мост, пропущена: ${line:0:60}"
          dropped=$((dropped + 1))
          ;;
      esac
    done <"$TOR_BRIDGES_FILE"

    if [ "$kept" -eq 0 ]; then
      rm -f "$TOR_CONFIG_FILE"
      die "в $TOR_BRIDGES_FILE не осталось ни одной годной строки — tor с таким конфигом не стартует вовсе."
    fi
    [ "$fixed" -eq 0 ] || warn "добавлен префикс 'Bridge ' к $fixed строке(ам)"
    [ "$dropped" -eq 0 ] || warn "пропущено строк: $dropped"
  } >>"$TOR_CONFIG_FILE"
  chmod 644 "$TOR_CONFIG_FILE"
}

# Применить сохранённый выбор. Вызывается перед `up -d`, потому что compose
# читает переменную окружения в момент запуска контейнеров.
apply_route_state() {
  [ -s "$ROUTE_STATE_FILE" ] || return 0
  case "$(cat "$ROUTE_STATE_FILE")" in
    direct) export RR_ROUTE_ADDRESS='' ;;
    tor)    export RR_ROUTE_ADDRESS='tor:9050' ;;
  esac
}

# Роутинг сейчас Direct? Пустой ROUTE_ADDRESS — это прямое соединение, и тогда
# Tor в этом запуске не участвует.
route_is_direct() {
  case "$(cat "$ROUTE_STATE_FILE" 2>/dev/null || true)" in
    direct) return 0 ;;
    tor)    return 1 ;;
  esac
  # Файла нет: смотрим на то, что compose подставит по умолчанию, — это Tor.
  [ -n "${RR_ROUTE_ADDRESS+set}" ] && [ -z "$RR_ROUTE_ADDRESS" ] && return 0
  return 1
}

# Исходный argv сохраняется до разбора команд: `ensure_docker_access` при
# необходимости перезапускает скрипт внутри `sg docker`, и взять там "$@"
# уже нельзя — к этому моменту там аргументы того, кто вызвал preflight.
ORIGINAL_ARGV=("$0" "$@")

# Имя проекта задаётся явно. Compose по умолчанию берёт его из имени каталога,
# а этот каталог называется `DevBackUp-5` — то есть имя менялось бы вместе с
# переименованием папки, и `down` раньше снимал бы не тот стенд.
#
# Значение не выбрано произвольно: `request-rider` — это имя проекта compose,
# по которому скрипт находит контейнеры и проверяет их состояние.
# Со своим именем стенд поднимался, а собственный smoke-инструмент проекта
# видел «0 контейнерів» и сыпал шесть FAIL. Тестовый стенд занят `rr_test`,
# поэтому пересечения не будет.
PROJECT=request-rider

# Порты по умолчанию — из overlay. Дублируются здесь, чтобы скрипт мог
# сказать «твой стенд на таком-то порту» и проверить занятость, не разбирая
# чужой compose. Диапазон 28xxx/25xxx свободен и от нативного стенда
# (8000/8080/8081/8090/9050), и от тестового (18xxx/15xxx/16xxx).
WEB_PORT=${RR_WEB_PORT:-28000}
ENGINE_PORT=${RR_ENGINE_PORT:-28081}
PROXY_PORT=${RR_PROXY_PORT:-28080}
WORKER_PORT=${RR_WORKER_PORT:-28090}
PG_PORT=${RR_PG_PORT:-25432}
TOR_PORT=${RR_TOR_PORT:-29050}

# Сервисы без healthcheck: у compose их нет, и «контейнер запущен» для них —
# единственный доступный признак готовности. Их проверяет не compose, а `check`
# настоящим HTTP-запросом.
ALL_SERVICES=(redis postgres tor engine browser-worker web celery engine-results)
HEALTH_SERVICES=(postgres redis web)
PLAIN_SERVICES=(tor engine browser-worker celery engine-results)

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  C_DIM=$'\033[2m'; C_OK=$'\033[32m'; C_WARN=$'\033[33m'
  C_ERR=$'\033[31m'; C_STEP=$'\033[36m'; C_B=$'\033[1m'; C_OFF=$'\033[0m'
else
  C_DIM=''; C_OK=''; C_WARN=''; C_ERR=''; C_STEP=''; C_B=''; C_OFF=''
fi
step() { printf '\n%s%s%s\n' "$C_STEP" "$1" "$C_OFF"; }
info() { printf '      %s\n' "$1"; }
dim()  { printf '      %s%s%s\n' "$C_DIM" "$1" "$C_OFF"; }
ok()   { printf '      %s✓%s %s\n' "$C_OK" "$C_OFF" "$1"; }
warn() { printf '      %s!%s %s\n' "$C_WARN" "$C_OFF" "$1"; }
bad()  { printf '      %s✗%s %s\n' "$C_ERR" "$C_OFF" "$1"; }
die()  { printf '\n%s✗ %s%s\n\n' "$C_ERR" "$1" "$C_OFF" >&2; exit 1; }

have_cmd() { command -v "$1" >/dev/null 2>&1; }

dc() {
  docker compose -p "$PROJECT" \
    -f "$COMPOSE_FILE" -f "$OVERLAY_FILE" \
    --env-file "$ENV_FILE" "$@"
}

# ───────────────────────────── Секреты ─────────────────────────────────────
#
# Файл `data/run/compose.env` лежит в каталоге `data/`, который `.gitignore`
# уже исключает, и поэтому никогда не попадёт в git. Корневой `.env` для этого
# не годится: в `.gitignore` его нет, и сгенерированный пароль стал бы
# содержимым репозитория.
#
# compose читает его только для подстановки `${...}`. Переменная, которая не
# объявлена ни в одном сервисе, в контейнер не попадёт — поэтому список
# ключей здесь и список `environment:` в overlay должны совпадать.

# Значение из env-файла без `source`: файл генерируется этим же скриптом, но
# `source` исполнил бы его как код, а `set -a` здесь не нужен.
env_value() { sed -n "s/^$1=//p" "$ENV_FILE" 2>/dev/null | head -1; }

random_secret() {
  if have_cmd openssl; then openssl rand -hex 32
  elif have_cmd python3; then python3 -c 'import secrets;print(secrets.token_hex(32))'
  else head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'
  fi
}

ensure_env() {
  mkdir -p "$ROOT_DIR/data/run"
  local key existing value file
  for key in POSTGRES_DB POSTGRES_USER POSTGRES_PASSWORD RR_SECRET_KEY \
             RR_ENGINE_BROKER_KEY; do
    existing="$(env_value "$key")"
    [ -n "$existing" ] && continue
    case "$key" in
      POSTGRES_DB|POSTGRES_USER) value=requestrider ;;
      RR_SECRET_KEY)             file="$ROOT_DIR/data/run/secret_key" ;;
      RR_ENGINE_BROKER_KEY)      file="$ROOT_DIR/data/run/broker_key" ;;
      *)                         value='' ;;
    esac
    # Нативный стенд уже сгенерировал эти три ключа в `data/run/`. Переиспользовать
    # их — значит один и тот же ключ на нативном и docker-стенде; новый ключ здесь
    # означал бы, что два стенда на одной машине не доверяют друг другу.
    if [ -n "$file" ] && [ -s "$file" ]; then
      value="$(cat "$file")"
    elif [ -z "$value" ]; then
      value="$(random_secret)"
    fi
    printf '%s=%s\n' "$key" "$value" >>"$ENV_FILE"
    chmod 600 "$ENV_FILE"
  done
  chmod 600 "$ENV_FILE" 2>/dev/null || true
}

# ───────────────────────────── Доступ к Docker ────────────────────────────
#
# На этой машине `kali` уже состоит в группе `docker` (`getent group docker` →
# `docker:x:963:kali`), но процессы сессии были запущены до этого, и в группе
# их нет: сокет `srw-rw---- root docker` недоступен. `usermod` тут ни при
# чём, нужен новый login — или `sg docker`, который поднимает нужную группу
# для одной команды без перелогина.

# Есть ли пользователь в группе docker по /etc/group. Сравнение списка членов
# через grep с шаблоном `,kali` не годится: у ПЕРВОГО члена запятая перед именем
# нет (`docker:x:963:kali`), и самый частый случай — именно первый — не
# находился. Проверяем список членов как список.
in_docker_group_file() {
  getent group docker 2>/dev/null | cut -d: -f4 | tr ',' '\n' | grep -qx "$(id -un)"
}

have_docker() {
  have_cmd docker || die \
"docker не установлен.

  sudo apt-get update && sudo apt-get install -y docker.io
или сразу всё вместе с плагином compose:

  ./docker-stand.sh install"
}

ensure_docker_access() {
  have_docker
  docker info >/dev/null 2>&1 && return 0

  # Уже пробовали перезайти в группу — дальше молча падать нельзя.
  [ "${RR_STAND_REEXEC:-0}" = "1" ] && die \
"docker-демон недоступен и повторный вход в группу docker не помог.

Сокет: $(ls -l /var/run/docker.sock 2>/dev/null | awk '{print $1, $3, $4}' || echo 'нет сокета')
Группы процесса: $(id -nG | tr ' ' ', ')
Группа docker в /etc/group: $(getent group docker | cut -d: -f1,4 || echo 'нет')

  sudo usermod -aG docker $(id -un) && newgrp docker
  # либо разово:
  sg docker -c 'docker ps'"

  id -nG | tr ' ' '\n' | grep -qx docker && die \
"группа docker есть в процессе, но сокет всё равно не открывается:

  sudo systemctl status docker
  sudo usermod -aG docker $(id -un)   # после этого — новый login"

  have_cmd sg || die \
"docker есть, группа docker не выдана, и нет sg.

  sudo usermod -aG docker $(id -un)
затем перелогиньтесь (или newgrp docker) и запустите скрипт снова."

  sg docker -c 'docker info' >/dev/null 2>&1 || die \
"не удалось войти в группу docker через sg:

  sudo usermod -aG docker $(id -un)
затем перелогиньтесь."

  # Перезапуск отдаёт исходный argv, а не текущие "$@" функции: сюда попадают
  # аргументы того, кто вызвал preflight, и подкоманда (`up --no-build`)
  # потерялась бы, а с ней и весь смысл запуска.
  local cmd
  printf -v cmd '%q ' "${ORIGINAL_ARGV[@]}"
  dim 'docker требует группу docker — перезапускаю скрипт через sg docker'
  export RR_STAND_REEXEC=1
  exec sg docker -c "$cmd"
}

# ───────────────────────────── Каталоги и место ───────────────────────────
#
# `data/ca` смонтирован в контейнер движка bind-маунтом. Каталога нет —
# Docker создаст его от root, и движок не сможет писать туда CA. Поэтому
# проверяем до старта, а не после.

preflight_dirs() {
  local d
  for d in data/ca data/run data/logs; do
    [ -d "$ROOT_DIR/$d" ] || { mkdir -p "$ROOT_DIR/$d"; ok "создан $d"; }
  done
  ensure_tor_config
  [ -w "$ROOT_DIR/data/ca" ] || die \
"data/ca недоступен на запись:

  sudo chown -R $(id -un):$(id -gn) $ROOT_DIR/data/ca
CA нужен движку: без него сканеры не смогут перехватывать TLS."
}

free_gb() { df -BG --output=avail "$1" 2>/dev/null | tail -1 | tr -dc '0-9'; }

preflight_disk() {
  local avail
  avail="$(free_gb /)"
  [ -z "$avail" ] && return 0
  # Образы реальные: движок собирается из исходников вместе с nuclei (~1 ГБ в
  # сборочном слое, слои не удаляются), browser-worker ставит Playwright с
  # браузерами, web — Python-зависимости. Сборка без свободного места падает
  # на середине и оставляет после себя сломанные слои.
  if [ "$avail" -lt 20 ]; then
    warn "свободно ${avail} ГБ на / — для сборки нужно ~20 ГБ"
    warn 'освободить: docker image prune   (только свои образы, чужие не трогает)'
  else
    ok "свободно ${avail} ГБ на /"
  fi
}

# Кто занял порт: `-p` у `ss` обязателен, без него pid не печатается и порт
# всегда выглядит свободным. Код возврата 1 означает «свободен» — без этого
# `if holder="$(port_holder "$p")"` истинно всегда, потому что успешный `cut`
# даёт код 0 и на пустом выводе.
#
# Порты, занятые собственными контейнерами стенда, конфликтом не считаются:
# их держит сам стенд.
port_holder() {
  local port="$1" pid
  pid="$(ss -tlnpH "sport = :$port" 2>/dev/null \
    | grep -o 'pid=[0-9]*' | head -1 | cut -d= -f2)"
  [ -n "$pid" ] || return 1
  printf '%s' "$pid"
}

port_busy_for_us() {
  local port="$1" cid
  cid="$(dc ps -q 2>/dev/null || true)"
  [ -n "$cid" ] || return 1
  docker inspect -f '{{range .NetworkSettings.Ports}}{{.HostPort}} {{end}}' $cid 2>/dev/null \
    | tr ' ' '\n' | grep -qx "$port"
}

preflight_ports() {
  local busy=() name port holder
  for entry in "web:$WEB_PORT" "proxy:$PROXY_PORT" "engine:$ENGINE_PORT" \
               "browser-worker:$WORKER_PORT" "postgres:$PG_PORT" "tor:$TOR_PORT"; do
    name="${entry%%:*}"; port="${entry##*:}"
    port_busy_for_us "$port" && continue
    holder="$(port_holder "$port" || true)"
    [ -n "$holder" ] && busy+=("$name :$port занят pid $holder $(cat "/proc/$holder/comm" 2>/dev/null || echo '?')")
  done
  [ "${#busy[@]}" -eq 0 ] && return 0
  printf '\n%sПорты стенда заняты:%s %s\n\n' "$C_ERR" "$C_OFF" "${busy[*]}" >&2
  cat >&2 <<'EOF'
Это не ошибка стенда: порт занят чужим процессом, и скрипт не будет его
убивать — в AGENTS.md записан случай, когда проверка погасила PostgreSQL и
Redis соседней сессии по pid-файлам в общем data/.

Смотрите, что это:

  ss -tlnp | grep -E ':(28000|28080|28081|28090|25432|29050)'

Если это нативный стенд Request-Rider — остановите его сами:

  ./start.sh --stop

Если это тестовый стенд rr_test — тот ходит на 18xxx/15xxx и не должен
пересекаться; тогда смотрите, что именно слушает порт.

Свой порт на этот запуск, ничего не останавливая:

  RR_WEB_PORT=38000 RR_PROXY_PORT=38080 RR_ENGINE_PORT=38081 \
  RR_WORKER_PORT=38090 RR_PG_PORT=35432 RR_TOR_PORT=39050 ./docker-stand.sh up

EOF
  exit 1
}

# Интернет нужен стенду по существу: Tor, OSINT-сбор, nuclei-шаблоны и сам
# инструмент атаки ходят к целям наружу. Проверяем один раз и предупреждаем,
# а не запрещаем: локальный стенд против 127.0.0.1 работает и без сети.
preflight_egress() {
  if have_cmd curl && curl -sS -m 8 -o /dev/null https://check.torproject.org/ 2>/dev/null; then
    ok 'интернет с хоста есть — Tor и OSINT смогут ходить наружу'
  else
    warn 'с хоста не отвечает https://check.torproject.org/'
    warn 'Tor не забустится (ждёт «Bootstrapped 100% (done)»), OSINT и nuclei'
    warn 'шаблоны не скачаются. Нативный стенд против локальных целей работает.'
  fi
}

preflight() {
  ensure_docker_access "$@"
  have_cmd docker && docker compose version >/dev/null 2>&1 || die \
"нет compose v2.

  sudo apt-get install -y docker-compose-v2
или переустановить docker.io, который тянет плагин."
  preflight_dirs
  preflight_disk
  preflight_ports
  preflight_egress
}

# ───────────────────────────── Состояние ──────────────────────────────────

service_row() { dc ps --format '{{.Service}}|{{.State}}|{{.Status}}' "$1" 2>/dev/null | head -1; }

service_state()  { service_row "$1" | cut -d'|' -f2; }
service_status() { service_row "$1" | cut -d'|' -f3; }

# Сколько раз Docker перезапустил контейнер. Нужно, потому что «running» here
# means «running right now», not «works»: a container that exits instantly with
# `restart: unless-stopped` alternates between `running` and `restarting`, and a
# single observation of `running` during the wait loop declared a crash-looping
# service ready. Measured on browser-worker: 12 restarts, `exit=1`, and the stand
# reported all eight services up.
service_restarts() {
  local cid
  cid="$(dc ps -q "$1" 2>/dev/null | head -1)"
  [ -n "$cid" ] || { printf '0'; return; }
  docker inspect -f '{{.RestartCount}}' "$cid" 2>/dev/null || printf '0'
}

# `healthy` из .Status вида «Up 2 minutes (healthy)».
service_health() {
  local status; status="$(service_status "$1")"
  case "$status" in
    *"(healthy)"*)   printf 'healthy' ;;
    *"(unhealthy)"*) printf 'unhealthy' ;;
    *"(health: starting)"*) printf 'starting' ;;
    *)               printf 'нет healthcheck' ;;
  esac
}

tor_bootstrapped() { dc logs --no-color --tail=200 tor 2>/dev/null | grep -q 'Bootstrapped 100%'; }

# ───────────────────────────── Команды ────────────────────────────────────

cmd_doctor() {
  step 'Докер'
  if have_cmd docker; then
    ok "docker $(docker --version 2>/dev/null | awk '{print $3}' | tr -d ',')"
    if docker info >/dev/null 2>&1; then
      ok "демон доступен: хранилище $(docker info --format '{{.Driver}}' 2>/dev/null)"
    else
      bad "демон недоступен из этой сессии"
      dim "сокет: $(ls -l /var/run/docker.sock 2>/dev/null | awk '{print $1, $3, $4}')"
      dim "группы процесса: $(id -nG | tr ' ' ', ')"
      dim "docker в /etc/group: $(getent group docker | cut -d: -f1,4 || echo 'нет группы')"
      dim 'если группа есть, а в процессе её нет — помогает sg docker:'
      dim '  sg docker -c "docker ps"'
    fi
  else
    bad 'docker не установлен — ./docker-stand.sh install'
  fi
  if have_cmd docker && docker compose version >/dev/null 2>&1; then
    ok "compose $(docker compose version --short 2>/dev/null)"
  else
    bad 'compose v2 не установлен'
  fi

  step 'Группа docker'
  if id -nG | tr ' ' '\n' | grep -qx docker; then
    ok 'группа docker есть в текущей сессии'
  elif in_docker_group_file; then
    warn 'вы состоите в docker, но группа не попала в эту сессию (логин был раньше)'
    dim 'скрипт перезапустит себя через sg docker; руками: newgrp docker'
  else
    bad 'вы не в группе docker'
    dim '  sudo usermod -aG docker '"$(id -un)"'   # и перелогиниться'
  fi

  step 'Каталоги'
  local d
  for d in data/ca data/run data/logs; do
    if [ -d "$ROOT_DIR/$d" ] && [ -w "$ROOT_DIR/$d" ]; then ok "$d на месте и доступен"
    else bad "$d отсутствует или не на запись — ./docker-stand.sh up создаст и скажет"; fi
  done

  step 'Место'
  local avail; avail="$(free_gb /)"
  [ -n "$avail" ] && { [ "$avail" -lt 20 ] && warn "свободно ${avail} ГБ, сборке нужно ~20" \
                                 || ok "свободно ${avail} ГБ"; }

  step 'Порты стенда'
  local entry name port holder
  for entry in "web:$WEB_PORT" "proxy:$PROXY_PORT" "engine:$ENGINE_PORT" \
               "browser-worker:$WORKER_PORT" "postgres:$PG_PORT" "tor:$TOR_PORT"; do
    name="${entry%%:*}"; port="${entry##*:}"
    if holder="$(port_holder "$port")" && [ -n "$holder" ]; then
      bad "$port занят pid $holder ($(cat "/proc/$holder/comm" 2>/dev/null || echo '?')) — $name"
    else
      ok "$port свободен — $name"
    fi
  done

  step 'Интернет'
  preflight_egress

  step 'Секреты'
  if [ -f "$ENV_FILE" ]; then
    ok "$ENV_FILE"
    local key
    for key in POSTGRES_PASSWORD RR_SECRET_KEY RR_ENGINE_BROKER_KEY; do
      [ -n "$(env_value "$key")" ] && ok "$key задан" || bad "$key пуст"
    done
  else
    dim 'файла нет — он создастся при первом up'
  fi

  step 'Соседние стенды (не трогаются этим скриптом)'
  if [ -s "$ROOT_DIR/data/stack.state" ]; then
    dim 'нативный стенд: записи в data/stack.state есть, ./start.sh --status'
  else
    dim 'нативный стенд: не запущен'
  fi
  if docker ps --filter 'label=com.docker.compose.project=rr_test' \
       --format '{{.Names}}' 2>/dev/null | grep -q .; then
    dim 'тестовый стенд rr_test: поднят'
  else
    dim 'тестовый стенд rr_test: не поднят'
  fi
}

cmd_install() {
  step 'Docker'
  if have_cmd docker; then
    ok "уже установлен: $(docker --version | awk '{print $3}')"
  else
    info 'ставлю docker.io'
    sudo apt-get update
    sudo apt-get install -y docker.io
    ok 'docker.io установлен'
  fi

  if docker compose version >/dev/null 2>&1; then
    ok "compose уже есть: $(docker compose version --short 2>/dev/null)"
  else
    # На Kali пакет называется docker-compose-v2, на Debian/Ubuntu —
    # docker-compose-plugin. Перебираем, а не угадываем.
    local pkg installed=0
    for pkg in docker-compose-v2 docker-compose-plugin docker-compose; do
      info "пробую $pkg"
      if sudo apt-get install -y "$pkg" >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
        ok "compose v2 установлен ($pkg)"
        installed=1
        break
      fi
    done
    [ "$installed" = "1" ] || warn 'compose v2 не поставился: docker-compose из apt может быть v1 — тогда плагин ставься вручную'
  fi

  step 'Демон'
  if pgrep -x dockerd >/dev/null 2>&1 || docker info >/dev/null 2>&1; then
    ok 'демон отвечает'
  else
    info 'запускаю docker.service'
    sudo systemctl enable --now docker || warn 'systemctl не сработал — демон, видимо, уже занят'
  fi

  step 'Группа docker'
  if id -nG | tr ' ' '\n' | grep -qx docker; then
    ok 'группа уже в этой сессии'
  elif in_docker_group_file; then
    ok 'вы в группе docker (/etc/group), но не в этой сессии'
    dim 'скрипт продолжит через sg docker — перелогиниваться не обязательно'
  else
    info "usermod -aG docker $(id -un)"
    sudo usermod -aG docker "$(id -un)"
    ok 'группа выдана'
  fi

  step 'Каталоги стенда'
  preflight_dirs

  step 'Проверка'
  ensure_docker_access doctor
}

cmd_build() {
  local no_cache=0
  [ "${1:-}" = "--no-cache" ] && no_cache=1
  preflight
  step 'Сборка образов'
  dim 'движок собирается из исходников вместе с nuclei (v3.11.1), это ~10-25 минут;'
  dim 'browser-worker ставит Playwright с браузерами. Первый раз — долго, дальше из кеша.'
  local args=(build)
  [ "$no_cache" = "1" ] && args+=(--no-cache)
  if dc "${args[@]}"; then
    ok 'образы собраны'
  else
    die "сборка упала. Лог целиком: $ROOT_DIR/data/logs/docker-stand-build.log
Движок тянет модули через цепочку GOPROXY-зеркал с тремя попытками на каждое —
это в его Dockerfile, и падение сети выглядит как ошибка сборки."
  fi
}

cmd_up() {
  local do_build=1 timeout=420
  while [ $# -gt 0 ]; do
    case "$1" in
      --no-build) do_build=0 ;;
      --wait)    timeout="${2:-420}"; shift ;;
      *) die "не понимаю аргумент: $1" ;;
    esac
    shift
  done
  preflight
  if [ "$do_build" = "1" ]; then cmd_build; fi
  ensure_env
  step 'Запуск'
  # Сохранённый маршрут применяется ДО `up -d`: compose подставляет
  # ROUTE_ADDRESS в момент запуска контейнера, и после — уже поздно.
  apply_route_state
  if [ -s "$ROUTE_STATE_FILE" ]; then
    info "маршрут из $ROUTE_STATE_FILE: $(cat "$ROUTE_STATE_FILE")"
  fi
  dc up -d || die "docker compose up упал, смотрите: docker-stand.sh logs"
  step 'Готовность'
  # Не `wait_ready || true`: недождаться — это результат, и печатать состояние и
  # подсказки после этого всё равно нужно. Выход по коду — в конце.
  local ready=0
  wait_ready "$timeout" || ready=1
  cmd_status
  print_next_steps
  [ "$ready" = "0" ] || return 1
}

# Готовность — по разным признакам на каждый сервис, а не «контейнер есть».
#
# Tor здесь НЕ входит в условие готовности, и это не снижение требований: сам
# compose выставляет движку `ROUTE_ADDRESS=tor:9050`, но приложение по
# документации умеет и Direct (в UI «Tor/Proxy» — пустой адрес). Ставить
# небустившийся Tor запретом на `up` значило бы запрещать стенд, который
# работает. Вместо этого Tor ждёт отдельно и о неудаче говорит с последствием.
wait_ready() {
  local timeout="${1:-420}" waited=0 pending=() svc state health restarts
  while [ "$waited" -lt "$timeout" ]; do
    pending=()
    for svc in "${HEALTH_SERVICES[@]}"; do
      health="$(service_health "$svc")"
      [ "$health" = "healthy" ] || pending+=("$svc($health)")
      restarts="$(service_restarts "$svc")"
      [ "${restarts:-0}" = "0" ] || pending+=("$svc(перезапущен ${restarts}×)")
    done
    for svc in "${PLAIN_SERVICES[@]}"; do
      state="$(service_state "$svc")"
      [ "$state" = "running" ] || pending+=("$svc($state)")
      # Перезапуск — тоже не готовность: сервис, который падает и поднимается
      # снова, не «поднят», даже если в момент проверки он running.
      restarts="$(service_restarts "$svc")"
      [ "${restarts:-0}" = "0" ] || pending+=("$svc(перезапущен ${restarts}×)")
    done
    if [ "${#pending[@]}" -eq 0 ]; then
      ok "все восемь сервисов подняты за ${waited}с"
      break
    fi
    if [ $((waited % 30)) -eq 0 ] && [ "$waited" -gt 0 ]; then
      dim "ждём: ${pending[*]}"
    fi
    sleep 5; waited=$((waited + 5))
  done
  if [ "${#pending[@]}" -ne 0 ]; then
    warn "за ${timeout}с не дождались: ${pending[*]}"
    info 'сервис, который перезапускается, падает в своём же журнале:'
    info '  ./docker-stand.sh logs <сервис> | tail -20'
    info 'а пересоздать его с исправленным compose: ./docker-stand.sh restart <сервис>'
    return 1
  fi

  step 'Маршрут'
  if route_is_direct; then
    # Tor в этом запуске не участвует, поэтому ждать его и ругаться на него
    # незачем: пустой ROUTE_ADDRESS означает, что трафик идёт напрямую.
    ok 'Direct (ROUTE_ADDRESS пуст) — Tor в этом запуске не участвует'
    return 0
  fi
  step 'Tor'
  if wait_tor 90; then
    ok 'Bootstrapped 100% (done) — маршрут через Tor доступен'
  else
    warn 'Tor не забустился'
    cat <<EOF
      Измерено на этой машине: соединение с ретранслятором устанавливается,
      и TLS-рукопожатие срывается на каждом релее (count растёт, Stuck at 10%).
      Это сеть, а не стенд:compose здесь ничего не меняет. Контроль — обычный
      HTTPS с хоста в эту же минуту отвечает, а системный Tor этой машины
      через SOCKS5 не отвечает вовсе.

      Что это значит на практике. Compose выставляет движку
      ROUTE_ADDRESS=tor:9050, поэтому до переключения запросы через пассивный
      прокси пойдут в Tor и не дойдут.

      Одна команда вместо копания в UI, и выбор запоминается:

        ./docker-stand.sh direct on     пересоздаст двигатель с пустым
                                       ROUTE_ADDRESS; следующие up и restart
                                       поднимут его так же
        ./docker-stand.sh direct off    вернёт Tor
        ./docker-stand.sh direct status  покажет, что сейчас

      Скрипт не переключает режим молча: «анонимно» и «напрямую» — разные
      postures, и решать их должен оператор, а не строка в compose.

      Диагностика, если Tor перестанет буститься по другой причине:

        ./docker-stand.sh logs tor | grep -i bootstrap
EOF
  fi
  return 0
}

wait_tor() {
  local timeout="${1:-90}" waited=0
  while [ "$waited" -lt "$timeout" ]; do
    tor_bootstrapped && return 0
    sleep 5; waited=$((waited + 5))
  done
  return 1
}

cmd_status() {
  step "Стенд $PROJECT"
  printf '      %-16s %-12s %-26s %s\n' СЕРВИС СОСТОЯНИЕ ЗДОРОВЬЕ ПОРТ
  printf '      %s\n' '------------------------------------------------------------'
  dim 'состояние вроде running/restart — число после «/» это число перезапусков'
  local svc state health
  for svc in "${ALL_SERVICES[@]}"; do
    state="$(service_state "$svc")"
    # У несуществующего контейнера нет и состояния, и здоровья: «нет
    # healthcheck» здесь читалось бы как утверждение о сервисе, которого нет.
    if [ -z "$state" ]; then
      state='нет контейнера'; health='—'
    else
      health="$(service_health "$svc")"
      # Перезапуски видны прямо в таблице: контейнер, который «работает» только
      # между падениями, иначе выглядит исправным.
      local restarts; restarts="$(service_restarts "$svc")"
      [ "${restarts:-0}" != "0" ] && state="$state/$restarts"
    fi
    printf '      %-16s %-12s %-26s %s\n' "$svc" "$state" "$health" \
      "$(port_of "$svc")"
  done
  printf '\n'
  info "web        http://127.0.0.1:$WEB_PORT"
  info "engine     http://127.0.0.1:$ENGINE_PORT   (пассивный прокси :$PROXY_PORT)"
  info "worker     http://127.0.0.1:$WORKER_PORT"
  info "postgres   postgresql://$(env_value POSTGRES_USER)@127.0.0.1:$PG_PORT/$(env_value POSTGRES_DB)"
  info "tor        socks5://127.0.0.1:$TOR_PORT"
}

port_of() {
  case "$1" in
    web)            printf '127.0.0.1:%s' "$WEB_PORT" ;;
    engine)         printf '127.0.0.1:%s, :%s' "$ENGINE_PORT" "$PROXY_PORT" ;;
    browser-worker) printf '127.0.0.1:%s' "$WORKER_PORT" ;;
    postgres)       printf '127.0.0.1:%s' "$PG_PORT" ;;
    tor)            printf '127.0.0.1:%s' "$TOR_PORT" ;;
    *)              printf '—' ;;
  esac
}

print_next_steps() {
  step 'Дальше'
  info "открыть UI:            http://127.0.0.1:$WEB_PORT"
  info "проверить цепочку:     ./docker-stand.sh check"
  info "маршрут Tor:           UI → Tor/Proxy → socks5://tor:9050 (внутри сети)"
  info "остановить:            ./docker-stand.sh stop"
  printf '\n'
  cat <<EOF
${C_WARN}Стенд поднят, но проверка цепочки ещё не пройдена:${C_OFF}
  контейнеры в порядке, а работают ли между собой Django, движок и воркер —
  измеряет только ./docker-stand.sh check, потому что единственный честный
  признак здесь это реальный код ответа на настоящем пути.

EOF
}

# ───────────────────────────── Проверки ───────────────────────────────────

# Код HTTP одним числом. `000` — запрос не дошёл: curl печатает его сам даже при
# неудаче, поэтому дописывать запасной '0' нельзя — в отчёте появлялось «0000».
# Ключ шлём там, где он нужен: движок требует его на всех путях, кроме /health.
http_code() {
  local url="$1" extra="${2:-}" code
  have_cmd curl || { printf '0'; return; }
  code="$(curl -sS -m 12 -o /dev/null -w '%{http_code}' $extra "$url" 2>/dev/null)" || code=''
  printf '%s' "${code:-0}"
}

# Строкой: «000» читается как диагноз, а не как выдуманный код.
http_line() {
  local code="$1"
  if [ "$code" = "000" ] || [ "$code" = "0" ]; then printf 'не дошёл'; else printf 'HTTP %s' "$code"; fi
}

# Главная проверка: хост → web → engine, и она обязана идти ЧЕРЕЗ КОД ПРИЛОЖЕНИЯ.
#
# Предыдущая версия дёргала из контейнера `web` голый `urllib`. Это было неверно:
# `urllib` не шлёт `Host: 127.0.0.1`, поэтому оба сервиса отвечали 403
# FORBIDDEN_HOST — и проверка показывала бы провал даже при совершенно правильной
# правке. Проверять надо ровно то, чем пользуется Django: `EngineClient.request`,
# `views._worker_headers` и `views.open_engine_stream`.
check_from_web() {
  dc exec -T web python - <<'PY'
import os, sys

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "core.settings")
sys.path.insert(0, os.getcwd())
import django

django.setup()

from urllib.error import HTTPError
from urllib.request import Request, urlopen

from lab import views
from lab.engine_client import EngineClient


def report(name, ok, detail):
    print(f"{name}\t{'OK' if ok else 'FAIL'}\t{detail}".replace("\n", " ")[:300])


def hint(detail):
    if "FORBIDDEN_HOST" in detail or "not loopback" in detail:
        return " — Django не шлёт loopback Host; проверьте internal_service_headers"
    return ""


# 1. Движок — тем же клиентом, что и весь шлюз.
try:
    status, payload = EngineClient(views.ENGINE_URL).request("GET", "/health", timeout=15)
    if status == 200:
        report("engine (EngineClient)", True, f"{views.ENGINE_URL} -> 200")
    else:
        body = payload if isinstance(payload, dict) else {}
        report(
            "engine (EngineClient)",
            False,
            f"{views.ENGINE_URL} -> {status} {body.get('reason', '')} {body.get('error', '')}{hint(str(body))}",
        )
except Exception as error:  # noqa: BLE001 — отчёт должен быть, а не трассировка
    report("engine (EngineClient)", False, f"{type(error).__name__}: {error}")

# 2. Воркер — теми же заголовками, что даёт приложение.
try:
    with urlopen(
        Request(views.BROWSER_WORKER_URL + "/health", headers=views._worker_headers()),
        timeout=15,
    ) as response:
        report("browser-worker (_worker_headers)", response.status == 200,
               f"{views.BROWSER_WORKER_URL} -> {response.status}")
except HTTPError as error:
    body = error.read(200).decode("utf-8", "replace")
    report("browser-worker (_worker_headers)", False,
           f"{views.BROWSER_WORKER_URL} -> {error.code} {body}{hint(body)}")
except Exception as error:  # noqa: BLE001
    report("browser-worker (_worker_headers)", False, f"{type(error).__name__}: {error}")

# 3. Живая лента событий — путь, который раньше не знал про ключ вовсе.
try:
    stream = views.open_engine_stream(f"{views.ENGINE_URL}/events/stream", {})
    if hasattr(stream, "status_code"):
        body = stream.content[:200].decode("utf-8", "replace")
        report("engine SSE (open_engine_stream)", False, f"-> {stream.status_code} {body}")
    else:
        report("engine SSE (open_engine_stream)", True, "поток открыт")
        try:
            stream.close()
        except Exception:  # noqa: BLE001
            pass
except Exception as error:  # noqa: BLE001
    report("engine SSE (open_engine_stream)", False, f"{type(error).__name__}: {error}")
# 3. Выходной IP по текущему маршруту. Единственная проверка, которая отличает
# «движок жив» от «движок выходит туда, куда надо»: контейнер может быть в порядке
# и при этом выходить напрямую мимо Tor.
try:
    status, payload = EngineClient(views.ENGINE_URL).request(
        "POST", "/route/check",
        {"url": "http://check.torproject.org/", "timeout_ms": 120000},
        timeout=240,
    )
    route = (payload or {}).get("route") or {}
    external = (payload or {}).get("external_ip") or {}
    address = route.get("address", "")
    ip = external.get("ip", "")
    is_tor = bool(external.get("is_tor"))
    if status == 200 and ip:
        verdict = "Tor" if is_tor else "НЕ Tor"
        where = "через Tor-контейнер" if address else "напрямую (ROUTE_ADDRESS пуст)"
        report(
            "выходной IP",
            True,
            f"{ip} — {verdict}, {where}, маршрут={address or '(пусто)'}, "
            f"{external.get('latency_ms', '?')} мс",
        )
        if address and not is_tor:
            print("ROUTE\tWARN\tмаршрут Tor задан, но выход не опознан как Tor")
        if not address and is_tor:
            # Не поломка: на части сетей трафик анонимизирует шлюз. Но решение
            # принимает оператор, и молчать об этом нельзя.
            print(
                "ROUTE\tWARN\tROUTE_ADDRESS пуст, но выход опознан как Tor: "
                "трафик анонимизирует шлюз сети, а не стенд"
            )
    else:
        detail = (payload or {}).get("error") or (payload or {}).get("reason") or ""
        report("выходной IP", False, f"HTTP {status} {detail}")
except Exception as error:  # noqa: BLE001
    report("выходной IP", False, f"{type(error).__name__}: {error}")
PY
}

cmd_check() {
  ensure_docker_access
  ensure_env
  local key failures=0 name code detail

  step 'С хоста'
  code="$(http_code "http://127.0.0.1:$WEB_PORT/")"
  if [ "$code" = "200" ]; then ok "web /            HTTP $code"
  else bad "web /            $(http_line "$code")"; failures=$((failures+1)); fi

  code="$(http_code "http://127.0.0.1:$ENGINE_PORT/health")"
  if [ "$code" = "200" ]; then ok "engine /health   HTTP $code"
  else bad "engine /health   $(http_line "$code")"; failures=$((failures+1)); fi

  code="$(http_code "http://127.0.0.1:$WORKER_PORT/health")"
  if [ "$code" = "200" ]; then ok "worker /health   HTTP $code"
  else bad "worker /health   $(http_line "$code")"; failures=$((failures+1)); fi

  # Не-/health путь: сервисного ключа більше немає, тому 403 тут означає
  # справді зламаний движок, а не «забули підписати запит».
  code="$(http_code "http://127.0.0.1:$ENGINE_PORT/route")"
  if [ "$code" = "200" ]; then ok "engine /route    HTTP $code (маршрут видно)"
  else bad "engine /route    $(http_line "$code")"; failures=$((failures+1)); fi

  step 'Маршрут'
  if route_is_direct; then
    ok 'Direct (ROUTE_ADDRESS пуст) — Tor в этом запуске не участвует'
  elif tor_bootstrapped; then
    ok 'Tor: Bootstrapped 100% (done)'
  else
    bad 'Tor не забустился, а движок отправлен через tor:9050'
    info 'весь трафик через пассивный прокси будет упираться в Tor и уйдёт с ошибкой'
    info 'переключить: ./docker-stand.sh direct on'
    info "журнал: ./docker-stand.sh logs tor | grep -i bootstrap"
    failures=$((failures+1))
  fi

  step 'Изнутри web — настоящим кодом приложения'
  local name verdict detail
  while IFS=$'\t' read -r name verdict detail; do
    [ -n "$name" ] || continue
    if [ "$verdict" = "OK" ]; then
      ok "$name — $detail"
    elif [ "$verdict" = "WARN" ]; then
      warn "$name — $detail"
    else
      bad "$name — $detail"
      failures=$((failures+1))
    fi
  done < <(check_from_web 2>/dev/null || printf 'проверка из web\tFAIL\tнет вывода\n')

  step 'Воркеры'
  local svc running
  for svc in celery engine-results; do
    running="$(service_state "$svc")"
    if [ "$running" = "running" ]; then ok "$svc запущен"
    else bad "$svc: ${running:-нет контейнера}"; failures=$((failures+1)); fi
  done
  for svc in celery engine-results; do
    if dc logs --no-color --tail=40 "$svc" 2>/dev/null | grep -q 'Traceback'; then
      bad "$svc: в журнале есть Traceback — ./docker-stand.sh logs $svc"
      failures=$((failures+1))
    fi
  done

  printf '\n'
  if [ "$failures" -eq 0 ]; then
    ok 'все проверки прошли'
  else
    warn "провалено проверок: $failures"
    info 'это измерение, а не мнение: каждый пункт — реальный код HTTP или вывод контейнера'
  fi
  return "$failures"
}

cmd_logs() {
  ensure_docker_access
  local follow=0 svc=""
  while [ $# -gt 0 ]; do
    case "$1" in
      -f|--follow) follow=1 ;;
      *) svc="$1" ;;
    esac
    shift
  done
  local args=(logs --no-color --tail=200)
  [ "$follow" = "1" ] && args+=(-f)
  if [ -n "$svc" ]; then
    dc "${args[@]}" "$svc"
  else
    dc "${args[@]}"
  fi
}

cmd_top() {
  ensure_docker_access
  local ids; ids="$(dc ps -q 2>/dev/null || true)"
  [ -n "$ids" ] || die 'стенд не поднят'
  docker stats --no-stream --format \
    'table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}\t{{.BlockIO}}' $ids
}

cmd_shell() {
  ensure_docker_access
  local svc="${1:-}"
  [ -n "$svc" ] || die 'укажите сервис: ./docker-stand.sh shell web'
  dc exec "$svc" sh
}

cmd_exec() {
  ensure_docker_access
  local svc="${1:-}"
  [ $# -ge 1 ] || die 'укажите сервис и команду: ./docker-stand.sh exec web env'
  shift
  [ $# -ge 1 ] || die 'укажите команду: ./docker-stand.sh exec web python -V'
  dc exec -T "$svc" "$@"
}

cmd_dbshell() {
  ensure_docker_access
  dc exec postgres psql -U "$(env_value POSTGRES_USER)" -d "$(env_value POSTGRES_DB)"
}

cmd_restart() {
  ensure_docker_access
  # Конфиг Tor готовится ДО compose: путь используется как источник bind-mount,
  # и если его нет, Docker создаст на этом месте каталог (см. ensure_tor_config).
  ensure_tor_config
  if [ $# -gt 0 ]; then
    step "Пересоздать: $*"
    # Именно `up -d`, а не `docker compose restart`: restart перезапускает
    # контейнер с его СТАРОЙ средой, и правка в compose (например, добавленный
    # RR_ALLOW_NON_LOOPBACK_BIND) после рестарта не действует. Именно так
    # browser-worker одиннадцать раз перезапускался с прежним refusе.bind.
    #
    # И именно `up -d --force-recreate`, потому что измеренная ловушка: compose
    # сравнивает СВОЮ конфигурацию, и изменение содержимого bind-mounted файла для
    # него невидимо. Добавленные мосты в `data/run/tor.bridges` попадают в
    # `/etc/tor/torrc` через монтирование, конфигурация compose не меняется, и
    # обычный `up -d` оставляет старый контейнер — а tor продолжает ходить
    # напрямую с тем конфигом, который прочитал при запуске.
    dc up -d --force-recreate "$@"
    ok "пересоздано: $*"
    printf '\n'
    info 'проверьте лог сервиса: ./docker-stand.sh logs '"${1}"
  else
    step 'Пересоздание стенда'
    apply_route_state
    dc up -d
    wait_ready 420 || true
    cmd_status
  fi
}

cmd_stop() {
  ensure_docker_access
  step 'Остановка контейнеров (тома целы)'
  dc stop
  ok 'остановлено; up вернёт стенд с теми же данными'
}

cmd_down() {
  ensure_docker_access
  step 'Снос контейнеров и сети (тома целы)'
  dc down
  ok 'снято; база и очередь на месте'
  dim "тома: docker volume ls | grep ${PROJECT}"
}

cmd_destroy() {
  ensure_docker_access
  local typed=0
  [ "${1:-}" = "--yes" ] && typed=1
  if [ "$typed" = "0" ]; then
    printf '\n%sБудут удалены тома проекта %s:%s\n' "$C_WARN" "$PROJECT" "$C_OFF" >&2
    cat >&2 <<EOF
  requestrider_postgres_data   база: проекты, запуски, результаты
  requestrider_redis_data      очередь задач

Восстановить будет нечем. Введите имя проекта, чтобы продолжить:
EOF
    printf '  %s > ' "$PROJECT" >&2
    read -r reply
    [ "$reply" = "$PROJECT" ] || { printf '\nОтменено.\n\n' >&2; exit 1; }
  fi
  step 'Снос всего'
  dc down --volumes
  ok 'снято вместе с томами'
  info 'файл секретов data/run/compose.env остался — ключи те же'
}

# Маршрут: Tor или Direct. Переключение пересоздаёт контейнер двигателя, потому
# что ROUTE_ADDRESS — это его переменная окружения, и смена значения без
# пересоздания не действует.
#
# Скрипт не переключает режим молча: «анонимно» и «напрямую» — разные postures
# для инструмента, который держит трафик цели, и решать это должен оператор.
# Поэтому здесь явная команда, а `up` только говорит, что она есть.
cmd_direct() {
  ensure_docker_access
  local mode="${1:-}"
  case "$mode" in
    on|Direct|direct)
      export RR_ROUTE_ADDRESS=""
      printf 'direct' >"$ROUTE_STATE_FILE"
      step 'Маршрут: Direct'
      dc up -d --force-recreate engine
      ok 'двигатель пересоздан с пустым ROUTE_ADDRESS — трафик идёт напрямую'
      ok 'выбор сохранён: следующие up и restart поднимут движок так же'
      ;;
    off|tor|Tor)
      export RR_ROUTE_ADDRESS="tor:9050"
      printf 'tor' >"$ROUTE_STATE_FILE"
      step 'Маршрут: Tor'
      dc up -d --force-recreate engine
      if wait_tor 90; then
        ok 'Tor забустился и двигатель пересоздан с ROUTE_ADDRESS=tor:9050'
      else
        warn 'Tor не забустился, а ROUTE_ADDRESS уже tor:9050'
        info 'весь трафик через пассивный прокси будет упираться в Tor и уйдёт с ошибкой'
        info 'вернуть рабочий режим: ./docker-stand.sh direct on'
      fi
      ok 'выбор сохранён: следующие up и restart поднимут движок так же'
      ;;
    status|"")
      step 'Маршрут двигателя'
      local address
      address="$(dc exec -T engine sh -c 'printf %s "$ROUTE_ADDRESS"' 2>/dev/null || printf 'нетипизировано')"
      if [ -z "$address" ]; then
        ok 'ROUTE_ADDRESS пуст — Direct'
      else
        ok "ROUTE_ADDRESS=$address"
      fi
      if tor_bootstrapped; then ok 'Tor забустился'
      else warn 'Tor не забустился — см. ./docker-stand.sh logs tor'; fi
      if [ -s "$ROUTE_STATE_FILE" ]; then
        info "сохранённый выбор: $(cat "$ROUTE_STATE_FILE") ($ROUTE_STATE_FILE)"
      else
        info 'выбор не сохранён: up и restart вернут Tor по умолчанию'
        info 'зафиксировать текущий режим: ./docker-stand.sh direct '"$([ -z "$address" ] && echo on || echo off)"
      fi
      ;;
    *)
      die "не понимаю: $mode (ожидается on | off | status)"
      ;;
  esac
}

cmd_tor() {
  ensure_docker_access
  ensure_tor_config
  step 'Tor: состояние'
  if tor_bootstrapped; then
    ok 'Bootstrapped 100% (done)'
  else
    warn 'не забустился'
  fi

  step 'Tor: транспорт'
  if [ -s "$TOR_BRIDGES_FILE" ]; then
    ok "мостов в файле: $(grep -cvE '^\s*(#|$)' "$TOR_BRIDGES_FILE")"
    dim "файл: $TOR_BRIDGES_FILE"
  else
    info 'мостов нет — Tor ходит напрямую и на этой машине не пройдёт'
    dim "почему: $TOR_BRIDGES_FILE"
    dim 'обфускация obfs4 включится автоматически, как только файл будет непустым.'
    cat <<'EOF'

      Мосты берутся на bridges.torproject.org (выдача под сеть, по CAPTCHA —
      автоматически не получится и в репозиторий они не годятся). Формат строки:

        Bridge obfs4 <ip>:<port> <40 hex отпечатка> cert=<base64 сертификата>

      Дальше:

        ./docker-stand.sh restart tor
        ./docker-stand.sh tor
EOF
  fi
  if dc exec -T tor sh -c 'command -v obfs4proxy' >/dev/null 2>&1; then
    ok 'obfs4proxy в образе есть'
  else
    warn 'obfs4proxy в образе нет — образ старый, нужен ./docker-stand.sh build tor'
  fi

  step 'Tor: конфигурация в контейнере'
  local mounted
  mounted="$(dc exec -T tor sh -c 'cat /etc/tor/torrc' 2>/dev/null | grep -vE '^\s*$' || true)"
  if [ -z "$mounted" ]; then
    warn 'прочитать /etc/tor/torrc не удалось'
  else
    printf '%s\n' "$mounted" | sed 's/^/      /'
    if printf '%s' "$mounted" | grep -q '^UseBridges 1'; then
      ok 'мосты включены'
    else
      # Отсутствие этих строк здесь — правильное состояние, а не поломка:
      # они добавляются только когда файл мостов непуст.
      dim 'UseBridges/ClientTransportPlugin отсутствуют — мостов нет, это ожидаемо'
    fi
  fi
}

cmd_ports() {
  step 'Порты стенда'
  local entry name port holder
  for entry in "web:$WEB_PORT" "proxy:$PROXY_PORT" "engine:$ENGINE_PORT" \
               "browser-worker:$WORKER_PORT" "postgres:$PG_PORT" "tor:$TOR_PORT"; do
    name="${entry%%:*}"; port="${entry##*:}"
    if holder="$(port_holder "$port")" && [ -n "$holder" ]; then
      bad "$port занят pid $holder ($(cat "/proc/$holder/comm" 2>/dev/null || echo '?')) — $name"
    else
      ok "$port свободен — $name"
    fi
  done
  printf '\n'
  dim 'свой диапазон выбран, чтобы рабочий стенд не мешал нативному (8000/8080/8081)'
  dim 'и тестовому rr_test (18xxx/15xxx) — все три могут стоять одновременно'
}

cmd_env() {
  if [ ! -f "$ENV_FILE" ]; then
    dim "файла нет; он создастся при up: $ENV_FILE"
    return 0
  fi
  step "Секреты: $ENV_FILE"
  ls -l "$ENV_FILE" | awk '{print "      права "$1" "$3" "$4}'
  local key
  for key in POSTGRES_DB POSTGRES_USER POSTGRES_PASSWORD RR_SECRET_KEY \
             RR_ENGINE_BROKER_KEY; do
    if [ -n "$(env_value "$key")" ]; then
      # Значения не печатаются: этот ключ — пароль базы и HMAC-ключ конвертов.
      ok "$key задан ($(printf '%s' "$(env_value "$key")" | wc -c) символов)"
    else
      bad "$key пуст"
    fi
  done
  dim 'в контейнеры попадает ровно то, что перечислено в environment: docker-stand.overlay.yml'
}

# ───────────────────────────── Разбор команд ──────────────────────────────

usage() {
  sed -n '2,/^set -Eeuo/p' "${BASH_SOURCE[0]}" | sed '$d; s/^# \{0,1\}//'
}

main() {
  local cmd="${1:-up}"
  [ $# -gt 0 ] && shift || true
  case "$cmd" in
    up)        cmd_up "$@" ;;
    build)     ensure_env; cmd_build "$@" ;;
    status|ps) ensure_docker_access; ensure_env; cmd_status ;;
    check)     cmd_check ;;
    doctor)    cmd_doctor ;;
    install)   cmd_install ;;
    logs)      ensure_env; cmd_logs "$@" ;;
    top)       ensure_env; cmd_top ;;
    shell)     ensure_env; cmd_shell "$@" ;;
    exec)      ensure_env; cmd_exec "$@" ;;
    dbshell)   ensure_env; cmd_dbshell ;;
    restart)   ensure_env; cmd_restart "$@" ;;
    stop)      ensure_env; cmd_stop ;;
    down)      ensure_env; cmd_down ;;
    destroy)   ensure_env; cmd_destroy "$@" ;;
    ports)     ensure_env; cmd_ports ;;
    direct)    ensure_env; cmd_direct "$@" ;;
    tor)       ensure_env; cmd_tor ;;
    env)       cmd_env ;;
    -h|--help|help) usage ;;
    *) printf 'неизвестная команда: %s\n\n' "$cmd" >&2; usage >&2; exit 1 ;;
  esac
}

main "$@"
