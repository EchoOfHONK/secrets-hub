#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
command -v docker >/dev/null || { echo 'Установите Docker Engine и Docker Compose v2 (инструкция в README.md).'; exit 1; }
docker compose version >/dev/null 2>&1 || { echo 'Нужен Docker Compose v2: docker compose version'; exit 1; }
docker info >/dev/null 2>&1 || { echo 'Docker недоступен. Запустите docker.service и выполните installer с доступом к Docker.'; exit 1; }
command -v openssl >/dev/null || { echo 'Установите openssl: sudo apt install openssl'; exit 1; }
if [[ -e .env ]]; then
  echo 'Конфигурация .env уже существует. Повторная установка может изменить адрес приложения.'
  read -r -p 'Использовать существующую конфигурацию и запустить приложение? [Y/n] ' answer
  [[ "${answer,,}" != n ]] || exit 0
  docker compose up -d --build --wait --wait-timeout 180
  echo 'Приложение запущено. Адрес находится в .env (APP_URL).'
  exit 0
fi
read -r -p 'Порт на Debian-сервере [8080]: ' port
port="${port:-8080}"
[[ "$port" =~ ^[0-9]{1,5}$ ]] && (( 10#$port >= 1 && 10#$port <= 65535 )) || { echo 'Порт должен быть 1–65535.'; exit 1; }
port=$((10#$port))
read -r -p 'Домен или IP сервера, без http:// и пути [localhost]: ' host
host="${host:-localhost}"
[[ "$host" =~ ^[A-Za-z0-9.-]+$ ]] || { echo 'Укажите доменное имя или IPv4 без пути и порта.'; exit 1; }
read -r -p 'Каталог данных [/var/lib/secrets-hub]: ' data_directory
data_directory="${data_directory:-/var/lib/secrets-hub}"
[[ "$data_directory" =~ ^/[A-Za-z0-9_./-]+$ ]] && [[ "$data_directory" != / ]] && [[ "$data_directory" != *'/../'* ]] && [[ "$data_directory" != */.. ]] || { echo 'Нужен отдельный абсолютный путь без пробелов и ..'; exit 1; }
data_directory="$(realpath -m -- "$data_directory")"
case "$data_directory" in
  /|/etc|/usr|/var|/var/lib|/home|/root|/bin|/sbin|/lib|/lib64|/opt|/tmp)
    echo 'Выберите отдельный каталог приложения, например /var/lib/secrets-hub.'; exit 1 ;;
esac
if [[ -d "$data_directory" ]]; then
  [[ -r "$data_directory" ]] || { echo 'Каталог данных недоступен для проверки. Запустите installer через sudo.'; exit 1; }
  [[ -z "$(find "$data_directory" -mindepth 1 -maxdepth 1 -print -quit)" ]] || {
    echo 'Каталог данных уже содержит файлы. Используйте исходный .env, либо новый пустой каталог и restore.sh.'; exit 1;
  }
fi
read -r -p 'HTTPS завершается на nginx/reverse proxy? [y/N]: ' proxy
if [[ "${proxy,,}" == y ]]; then
  app_url="https://$host"
  secure_cookies=true
  bind_address=127.0.0.1
  edge_proxy_ip=172.30.251.1
else
  app_url="http://$host:$port"
  secure_cookies=false
  edge_proxy_ip=127.0.0.1
  read -r -p 'Открыть порт для LAN, а не только localhost? [y/N]: ' lan
  if [[ "${lan,,}" == y ]]; then bind_address=0.0.0.0; else bind_address=127.0.0.1; fi
  echo 'Для повседневной работы через LAN или интернет настройте HTTPS. Браузер может запрещать clipboard на HTTP IP.'
fi
read -r -p 'Создать администратора через браузер после запуска? [Y/n]: ' create_admin
if [[ -w "$(dirname -- "$data_directory")" ]] || [[ -d "$data_directory" && -w "$data_directory" ]]; then
  mkdir -p "$data_directory/app" "$data_directory/postgres"
  chmod 700 "$data_directory" "$data_directory/app"
  if (( EUID == 0 )); then chown 10001:10001 "$data_directory/app"; else
    command -v sudo >/dev/null || { echo 'Нужен sudo для назначения владельца данных UID 10001.'; exit 1; }
    sudo chown 10001:10001 "$data_directory/app"
  fi
else
  command -v sudo >/dev/null || { echo 'Нет доступа к каталогу данных: используйте sudo ./install.sh'; exit 1; }
  sudo mkdir -p "$data_directory/app" "$data_directory/postgres"
  sudo chmod 700 "$data_directory" "$data_directory/app"
  sudo chown 10001:10001 "$data_directory/app"
fi
db_password="$(openssl rand -hex 32)"
{
  printf 'PORT=%s\n' "$port"
  printf 'BIND_ADDRESS=%s\n' "$bind_address"
  printf 'APP_URL=%s\n' "$app_url"
  printf 'SECURE_COOKIES=%s\n' "$secure_cookies"
  printf 'EDGE_PROXY_IP=%s\n' "$edge_proxy_ip"
  printf 'DATA_DIRECTORY=%s\n' "$data_directory"
  printf 'DB_PASSWORD=%s\n' "$db_password"
} > .env
unset db_password
chmod 600 .env
docker compose up -d --build --wait --wait-timeout 180
printf '\nSecrets Hub запущен: %s\n' "$app_url"
if [[ "${create_admin,,}" != n ]]; then
  echo 'Откройте адрес в браузере и пройдите Setup Wizard. Пароли и recovery key создаются только там.'
else
  echo 'До завершения Setup Wizard хранилище не готово к работе. Откройте приложение для создания администратора.'
fi
