#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export CA_DIR="${CA_DIR:-$ROOT_DIR/data/ca}"
export ENGINE_URL="${ENGINE_URL:-http://127.0.0.1:8081}"
export BROWSER_WORKER_URL="${BROWSER_WORKER_URL:-http://127.0.0.1:8090}"
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

  if ! "$venv_python" -c "import django" >/dev/null 2>&1; then
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
    echo "[run-engine] using cached Playwright Firefox runtime"
    return 0
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
    PORT=8090 exec "$WORKER_VENV_DIR/bin/python" worker.py >>"$WORKER_LOG" 2>&1
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
start_engine
start_browser_worker

ensure_venv
cd "$WEB_DIR"

echo "[run-engine] applying Django migrations"
"$VENV_DIR/bin/python" manage.py migrate --noinput

echo "[run-engine] starting Django UI using $VENV_DIR"
ENGINE_URL="$ENGINE_URL" BROWSER_WORKER_URL="$BROWSER_WORKER_URL" "$VENV_DIR/bin/python" manage.py runserver 127.0.0.1:8000
