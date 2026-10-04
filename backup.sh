#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
[[ -f .env ]] || { echo 'Сначала запустите ./install.sh'; exit 1; }
# The CLI reads its password from the terminal, never from arguments or environment.
filename="secrets-hub-$(date -u +%Y%m%dT%H%M%SZ)-$(openssl rand -hex 4).shbak"
docker compose exec api python -m app.backup backup --output "/data/backups/$filename"
printf 'Backup: app/backups/%s in DATA_DIRECTORY\n' "$filename"
