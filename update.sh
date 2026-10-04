#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
[[ -f .env ]] || { echo 'Сначала запустите ./install.sh'; exit 1; }
echo 'Перед обновлением будет создана зашифрованная резервная копия.'
./backup.sh
if [[ "$(git rev-parse --show-toplevel 2>/dev/null || true)" == "$PWD" ]]; then
  [[ -z "$(git status --porcelain --untracked-files=no)" ]] || { echo 'Есть изменения в отслеживаемых файлах. Сохраните их перед обновлением.'; exit 1; }
  git pull --ff-only
else
  echo 'Git checkout не найден: используются файлы текущего релиза.'
fi
docker compose build --pull
docker compose up -d --wait --wait-timeout 180
echo 'Обновление завершено. Откройте Security Center и проверьте /health.'
