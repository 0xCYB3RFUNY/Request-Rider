#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export CA_DIR="${CA_DIR:-$ROOT_DIR/data/ca}"
export ENGINE_URL="${ENGINE_URL:-http://127.0.0.1:8081}"
# Порт browser-worker задаётся переменной по той же причине, что и
# `RUNSERVER_PORT` ниже: пока порт был зашит в `PORT=8090`, скрипт не мог
# поднять worker на свободном порту и молча переиспользовал чужой процесс на
# :8090, а изоляция тестов требует своего порта. Типовое значение прежнее.
export WORKER_PORT="${WORKER_PORT:-8090}"
export BROWSER_WORKER_URL="${BROWSER_WORKER_URL:-http://127.0.0.1:$WORKER_PORT}"
# PostgreSQL — единственная база данных приложения, а `web/core/settings.py`
# требует `POSTGRES_HOST` (или `DATABASE_URL`) уже на импорте настроек и без
# них падает с `ImproperlyConfigured`. Раньше эти переменные нужно было
# экспортировать руками перед каждым запуском, и `./run-engine.sh` в новом
# терминале падал на `manage.py migrate`. Теперь у локального запуска есть
# собственные значения по умолчанию, а переменная из окружения всегда имеет
# приоритет — поэтому CI, Docker и тестовые кластеры (`POSTGRES_PORT=...`,
# `POSTGRES_DB=...`) продолжают работать без правки этого файла. Значения
# печатаются перед миграцией, то есть используемый кластер всегда виден.
export POSTGRES_HOST="${POSTGRES_HOST:-127.0.0.1}"
export POSTGRES_PORT="${POSTGRES_PORT:-55433}"
# Пользователь по умолчанию — имя текущего пользователя ОС: локальный кластер
# с `trust`-аутентификацией отдаёт его по умолчанию, поэтому пароль не нужен.
export POSTGRES_USER="${POSTGRES_USER:-$(id -un)}"
export POSTGRES_DB="${POSTGRES_DB:-requestrider}"
# Порт Django. Типове значення незмінне, але змінна потрібна: :8000 часто
# вже зайнятий іншим стендом (Docker Compose, інша сесія, залишковий
# `runserver`), і тоді весь успішний старт до цього місця падає на
# `That port is already in use`. Ізоляція тестів вимагає власного порту.
export RUNSERVER_PORT="${RUNSERVER_PORT:-8000}"
WEB_DIR="$ROOT_DIR/web"
VENV_DIR="$WEB_DIR/.venv"
WORKER_DIR="$ROOT_DIR/browser-worker"
WORKER_VENV_DIR="$WORKER_DIR/.venv"
ENGINE_LOG="$ROOT_DIR/.request-rider-engine.log"
WORKER_LOG="$ROOT_DIR/.request-rider-browser-worker.log"
ENGINE_PID=""
WORKER_PID=""

ensure_venv() {
  local venv_python="$VENV_DIR/bin/python"

  if [ ! -x "$venv_python" ] || ! "$venv_python" -c "import pip" >/dev/null 2>&1; then
    echo "[run-engine] creating Python virtualenv at $VENV_DIR"
    if command -v virtualenv >/dev/null 2>&1; then
      virtualenv --clear "$VENV_DIR" >/dev/null
    else
      python3 -m venv "$VENV_DIR"
    fi
  fi

  if ! "$venv_python" -c "import django, psycopg, celery" >/dev/null 2>&1; then
    echo "[run-engine] installing Django dependencies in $VENV_DIR"
    "$venv_python" -m pip install --quiet --disable-pip-version-check --break-system-packages -r "$WEB_DIR/requirements.txt"
  fi
}

start_engine() {
  if curl -fsS "$ENGINE_URL/health" >/dev/null 2>&1; then
    echo "[run-engine] engine already running at $ENGINE_URL"
    return 0
  fi

  echo "[run-engine] starting Go engine"
  (
    cd "$ROOT_DIR/engine"
    exec go run . >>"$ENGINE_LOG" 2>&1
  ) &
  ENGINE_PID=$!

  local attempts=0
  while [ "$attempts" -lt 30 ]; do
    if curl -fsS "$ENGINE_URL/health" >/dev/null 2>&1; then
      echo "[run-engine] engine started on $ENGINE_URL"
      return 0
    fi
    sleep 1
    attempts=$((attempts + 1))
  done

  echo "[run-engine] engine failed to start; see $ENGINE_LOG"
  return 1
}

ensure_browser_worker() {
  local venv_python="$WORKER_VENV_DIR/bin/python"

  if [ ! -x "$venv_python" ]; then
    echo "[run-engine] creating browser-worker virtualenv at $WORKER_VENV_DIR"
    python3 -m venv "$WORKER_VENV_DIR"
  fi

  if ! "$venv_python" -c "import playwright" >/dev/null 2>&1; then
    echo "[run-engine] installing Playwright browser-worker dependencies in $WORKER_VENV_DIR"
    "$venv_python" -m pip install --quiet --disable-pip-version-check -r "$WORKER_DIR/requirements.txt"
  fi

  # Динамическая проверка реального наличия бинарника Firefox
  local playwright_path="${PLAYWRIGHT_BROWSERS_PATH:-$HOME/.cache/ms-playwright}"
  if compgen -G "$playwright_path/firefox-*/firefox/firefox" >/dev/null 2>&1; then
    for firefox_binary in "$playwright_path"/firefox-*/firefox/firefox; do
      if [ -x "$firefox_binary" ]; then
        export FIREFOX_EXECUTABLE_PATH="$firefox_binary"
        echo "[run-engine] using cached Playwright Firefox runtime: $firefox_binary"
        return 0
      fi
    done
  fi

  # Проверка наличия Node.js перед скачиванием
  if ! command -v node >/dev/null 2>&1; then
    echo "[run-engine] ERROR: Node.js is required by Playwright but was not found."
    echo "[run-engine] Please run: sudo apt update && sudo apt install -y nodejs npm"
    return 1
  fi

  echo "[run-engine] Firefox runtime missing. Installing Playwright Firefox..."
  "$venv_python" -m playwright install firefox
}

start_browser_worker() {
  if curl -fsS "$BROWSER_WORKER_URL/health" >/dev/null 2>&1; then
    echo "[run-engine] browser worker already running at $BROWSER_WORKER_URL"
    return 0
  fi

  ensure_browser_worker
  echo "[run-engine] starting browser worker"
  (
    cd "$WORKER_DIR"
    PORT="$WORKER_PORT" exec "$WORKER_VENV_DIR/bin/python" worker.py >>"$WORKER_LOG" 2>&1
  ) &
  WORKER_PID=$!

  local attempts=0
  while [ "$attempts" -lt 30 ]; do
    if kill -0 "$WORKER_PID" 2>/dev/null && curl -fsS "$BROWSER_WORKER_URL/health" >/dev/null 2>&1; then
      echo "[run-engine] browser worker started on $BROWSER_WORKER_URL"
      return 0
    fi
    sleep 1
    attempts=$((attempts + 1))
  done

  echo "[run-engine] browser worker failed to start; see $WORKER_LOG"
  return 1
}

ensure_httpx() {
  # Зібраний бінарник — runtime-артефакт проєкту, тому живе в корені (bin/) і
  # збирається виключно з актуального engine/go.mod.
  local httpx_bin="$ROOT_DIR/bin/httpx"
  if [ -n "${RR_HTTPX_BIN:-}" ] && [ -x "$RR_HTTPX_BIN" ]; then
    echo "[run-engine] using RR_HTTPX_BIN=$RR_HTTPX_BIN"
    return 0
  fi
  if [ -x "$httpx_bin" ]; then
    echo "[run-engine] using project httpx binary"
  elif command -v httpx >/dev/null 2>&1; then
    httpx_bin="$(command -v httpx)"
    echo "[run-engine] using system httpx binary at $httpx_bin"
  else
    echo "[run-engine] building httpx binary from engine/go.mod"
    mkdir -p "$ROOT_DIR/bin"
    if ! (cd "$ENGINE_DIR" && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o "$ROOT_DIR/bin/httpx" github.com/projectdiscovery/httpx/cmd/httpx); then
      echo "[run-engine] ERROR: httpx build from engine/go.mod failed."
      return 0
    fi
    httpx_bin="$ROOT_DIR/bin/httpx"
  fi
  export RR_HTTPX_BIN="${RR_HTTPX_BIN:-$httpx_bin}"
}

cleanup() {
  if [ -n "${WORKER_PID:-}" ] && kill -0 "$WORKER_PID" 2>/dev/null; then
    kill "$WORKER_PID" 2>/dev/null || true
    wait "$WORKER_PID" 2>/dev/null || true
  fi
  if [ -n "${ENGINE_PID:-}" ] && kill -0 "$ENGINE_PID" 2>/dev/null; then
    kill "$ENGINE_PID" 2>/dev/null || true
    wait "$ENGINE_PID" 2>/dev/null || true
  fi
}

trap cleanup EXIT
ensure_httpx
start_engine
start_browser_worker

ensure_venv
cd "$WEB_DIR"

echo "[run-engine] applying Django migrations"
# Пароль не печатается: в вывод попадает только то, что нужно, чтобы глазами
# проверить кластер, и никаких секретов.
echo "[run-engine] using PostgreSQL ${POSTGRES_USER}@${POSTGRES_HOST}:${POSTGRES_PORT}/${POSTGRES_DB}"
"$VENV_DIR/bin/python" manage.py migrate --noinput

echo "[run-engine] starting Django UI on http://127.0.0.1:$RUNSERVER_PORT using $VENV_DIR"
ENGINE_URL="$ENGINE_URL" BROWSER_WORKER_URL="$BROWSER_WORKER_URL" "$VENV_DIR/bin/python" manage.py runserver "127.0.0.1:$RUNSERVER_PORT"
