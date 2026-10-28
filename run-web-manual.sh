#!/bin/bash
# Підняти Django вручну — лише для знімків мануала.
#
# Навіщо окремий скрипт, а не `./start.sh`: знімки запускаються після того, як
# основний стенд уже працює, і `start.sh` на кожному запуску проходить весь
# цикл встановлення.
#
# Окремої експорти `RR_INTERNAL_API_KEY` тут більше немає: ключ видалено
# наскрізь, і web більше нічого не підписує на внутрішні виклики.
set -e
cd /home/kali/Desktop/DevBackUp-5/web

export POSTGRES_HOST="${POSTGRES_HOST:-127.0.0.1}"
export POSTGRES_PORT="${POSTGRES_PORT:-55433}"
export POSTGRES_USER="${POSTGRES_USER:-$(id -un)}"
export POSTGRES_DB="${POSTGRES_DB:-requestrider}"
export POSTGRES_TEST_TEMPLATE="${POSTGRES_TEST_TEMPLATE:-requestrider_utf8_tmpl}"
export SECRET_KEY_FILE=/home/kali/Desktop/DevBackUp-5/data/run/secret_key

exec .venv/bin/python manage.py runserver 127.0.0.1:8000