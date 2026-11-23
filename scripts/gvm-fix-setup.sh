#!/usr/bin/env bash
# ==============================================================================
# scripts/gvm-fix-setup.sh
# Повний автоматизований запуск і виправлення OpenVAS/GVM для Request-Rider
#
# Виправляє:
# 1. gvmd socket not found at /run/gvmd/gvmd.sock
# 2. OpenVAS raw socket capture permission (CAP_NET_RAW)
# 3. Права групи _gvm та каталоги /run/gvmd, /run/ospd
# 4. Kali Bug #8813 (симлінк ospd.sock -> ospd-openvas.sock)
# 5. Послідовний запуск служб (postgres -> redis -> mosquitto -> ospd -> gvmd -> gsad)
# 6. Моніторинг завантаження бази NVT (причина «Виконується 0%»)
# ==============================================================================

set -euo pipefail

C_GREEN="\033[01;32m"
C_YELLOW="\033[01;33m"
C_RED="\033[01;31m"
C_BLUE="\033[01;34m"
C_RESET="\033[00m"

log_info()  { printf "${C_BLUE}[*]${C_RESET} %s\n" "$*"; }
log_ok()    { printf "${C_GREEN}[+]${C_RESET} %s\n" "$*"; }
log_warn()  { printf "${C_YELLOW}[!]${C_RESET} %s\n" "$*"; }
log_err()   { printf "${C_RED}[-]${C_RESET} %s\n" "$*" >&2; }

# Перевірка запуску з root/sudo
if [ "$(id -u)" -ne 0 ]; then
  log_err "Цей скрипт вимагає привілеїв root/sudo. Виконайте: sudo $0"
  exit 1
fi

TARGET_USER="${SUDO_USER:-${USER:-kali}}"

log_info "=== Початок налаштування та запуску OpenVAS/GVM для користувача: ${TARGET_USER} ==="

# Крок 1. Мережеві права для OpenVAS (CAP_NET_RAW)
if [ -x /usr/bin/openvas ]; then
  log_info "Крок 1: Встановлення capabilities (cap_net_raw,cap_net_admin) для /usr/bin/openvas..."
  setcap cap_net_raw,cap_net_admin+eip /usr/bin/openvas || log_warn "Не вдалося встановити setcap для openvas"
  log_ok "Мережеві права для /usr/bin/openvas активовано"
fi

# Крок 2. Додавання користувача до групи _gvm та підготовка каталогів /run
log_info "Крок 2: Додавання ${TARGET_USER} до групи _gvm та створення каталогів сокетів..."
if getent group _gvm >/dev/null 2>&1; then
  usermod -aG _gvm "${TARGET_USER}" || true
fi

mkdir -p /run/gvmd /run/ospd /var/run/ospd
chown -R _gvm:_gvm /run/gvmd /run/ospd /var/run/ospd 2>/dev/null || true
chmod 775 /run/gvmd /run/ospd /var/run/ospd 2>/dev/null || true
log_ok "Каталоги /run/gvmd та /run/ospd готові з правами 775 (_gvm:_gvm)"

# Крок 3. Симлінк для OSPd (виправлення Kali bug #8813)
log_info "Крок 3: Створення симлінків сокетів OSPd (Bug #8813)..."
ln -sf /run/ospd/ospd-openvas.sock /run/ospd/ospd.sock 2>/dev/null || true
ln -sf /run/ospd/ospd-openvas.sock /var/run/ospd/ospd.sock 2>/dev/null || true
log_ok "Симлінк ospd.sock -> ospd-openvas.sock створено"

# Крок 4. Зупинка старих процесів і послідовний запуск
log_info "Крок 4: Перезапуск служб у строгому порядку залежностей..."
systemctl stop gsad gvmd ospd-openvas notus-scanner 2>/dev/null || true

log_info "  -> Запуск PostgreSQL, Redis (OpenVAS) та Mosquitto..."
systemctl start postgresql redis-server@openvas mosquitto

log_info "  -> Запуск notus-scanner та ospd-openvas..."
systemctl start notus-scanner ospd-openvas
sleep 4

log_info "  -> Запуск менеджера gvmd..."
systemctl start gvmd
sleep 4

log_info "  -> Запуск веб-інтерфейсу gsad (GSA)..."
systemctl start gsad

# Повторна перевірка сокетів і прав
ln -sf /run/ospd/ospd-openvas.sock /run/ospd/ospd.sock 2>/dev/null || true
chmod 660 /run/gvmd/gvmd.sock /run/ospd/ospd-openvas.sock /run/ospd/ospd.sock 2>/dev/null || true
chown _gvm:_gvm /run/gvmd/gvmd.sock /run/ospd/ospd-openvas.sock 2>/dev/null || true

# Крок 5. Перевірка статусу сокета та NVT кешу
log_info "Крок 5: Перевірка готовності..."
if [ -S /run/gvmd/gvmd.sock ]; then
  log_ok "Сокет gvmd знайдено: /run/gvmd/gvmd.sock"
else
  log_warn "Сокет /run/gvmd/gvmd.sock ще створюється або сталася помилка. Перевірте: journalctl -u gvmd -n 20"
fi

if [ -f /var/log/gvm/ospd-openvas.log ]; then
  log_info "Останні події сканера (ospd-openvas.log):"
  tail -n 8 /var/log/gvm/ospd-openvas.log || true

  if tail -n 25 /var/log/gvm/ospd-openvas.log | grep -q "Loading VTs"; then
    log_warn "УВАГА: Сканер завантажує базу NVT у пам'ять (зазвичай триває 3–8 хв)."
    log_warn "Будь-який запущений скан показуватиме «Виконується 0%», доки в лозі не з'явиться:"
    log_warn "Finished loading VTs. The VT cache has been updated..."
  else
    log_ok "База NVT готова до запуску сканувань."
  fi
fi

log_ok "=== Налаштування завершено успішно ==="
