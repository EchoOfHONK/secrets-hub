#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
[[ -f .env ]] || { echo 'Сначала запустите ./install.sh'; exit 1; }
[[ $# -eq 1 && -f "$1" ]] || { echo 'Использование: ./restore.sh /absolute/path/backup.shbak'; exit 1; }
backup_file="$(realpath -- "$1")"
echo 'Восстановление полностью заменит пользователей, секреты, настройки и ключ хранилища.'
read -r -p 'Введите RESTORE для продолжения: ' confirmation
[[ "$confirmation" == RESTORE ]] || exit 0
IFS= read -r -s -p 'Пароль backup (Enter для machine-копии): ' restore_password
printf '\n'
[[ ${#restore_password} -le 1024 ]] || { unset restore_password; echo 'Пароль слишком длинный.'; exit 1; }
docker compose stop api
restart_api() { unset restore_password; docker compose up -d --wait --wait-timeout 180 api web; }
trap restart_api EXIT
# Pipe the password and encrypted backup: UID 10001 needs no access to the host file.
{ printf '%s\n' "$restore_password"; cat -- "$backup_file"; } | docker compose run --rm -T --no-deps api python -m app.backup restore --input - --password-stdin
unset restore_password
echo 'Восстановление завершено. Все сессии отозваны: войдите заново.'
