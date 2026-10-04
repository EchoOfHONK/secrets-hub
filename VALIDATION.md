# Проверки Secrets Hub

Проверки выполнены 3 октября 2026 года. Проверены backend, миграции, production-сборка React, настоящие Docker Compose контейнеры, установка на чистые данные, nginx, HTTPS, зашифрованные копии и восстановление. Это инженерная проверка реализации, **не независимый аудит безопасности и не сертификация production-ready**.

## Автоматические тесты

Последний полный прогон после обновления зависимостей, исправления обработки медленной загрузки, отказа при отсутствующем DATABASE_URL и сохранения локального каталога backup при restore:

| База данных | Результат | Время |
|---|---:|---:|
| PostgreSQL 17.11 | **41 passed** | 20.23 s |
| SQLite, изолированная временная БД | **41 passed** | 17.85 s |

В обоих прогонах осталось одно предупреждение тестового framework: Starlette сообщает, что его интеграция с `httpx` устарела и предлагает `httpx2`. Ошибок тестов и конфликтов зависимостей нет; `pip check` завершился сообщением `No broken requirements found`.

Тесты запускают настоящие FastAPI routes через ASGI TestClient/HTTPX и используют настоящую PostgreSQL для основного прогона. Отдельно проведён описанный ниже HTTP-сценарий через Docker/nginx. Тестовая PostgreSQL отделена от базы, используемой для просмотра интерфейса.

Проверены:

- однократный Setup, Argon2id, login, persistent rate limiting, secure cookie attributes, CSRF/Origin, истечение сессии, idle/manual lock, logout all devices, повторная проверка личности;
- AES-GCM, случайные nonce, привязка ciphertext к записи, отсутствие значений в metadata/list/search/audit/health, отложенная загрузка ciphertext;
- secret CRUD, collection/shared permissions, запрет Copy, защита от повышения роли и делегирования чужого доступа, версии и восстановление версии;
- expiration, certificate PEM/private key match и вычисление срока сертификата, ограничения файлов и generic errors;
- temporary links: password, revoke, expiration, ограничение просмотров, атомарный одноразовый доступ при конкурентных запросах, copy audit и повторная проверка актуальных прав автора;
- импорт JSON/CSV/.env/WireGuard/SSH, atomic import, SSH Ed25519 с passphrase и fingerprint, WireGuard config/QR/export/duplicate, генераторы;
- изменение полного WireGuard config обновляет canonical endpoint в data и metadata; индивидуально выданный Write+Copy позволяет Editor скопировать секрет из недоступной collection в Personal, Viewer не получает Write;
- TOTP, запрет replay, одноразовые recovery codes, восстановление администратора, повторная генерация recovery codes с reauth и аудитом;
- переносимый encrypted backup, machine backup, отказ при неверном пароле/повреждении, retention, CLI backup/restore через stdin, восстановление в пустую БД без локального master key;
- restore сохраняет существующий локальный каталог backup, его файлы, возможность скачать копию и last_backup; каталог других копий не импортируется из snapshot;
- восстановление после прерванной замены ключа с fsync journal; API и health недоступны до завершения восстановления, scheduler не изменяет данные в этом состоянии;
- после restore старые временные ссылки остаются отозванными, TOTP recovery codes и pending setup инвалидируются; зашифрованный TOTP seed сохраняется и позволяет войти и создать новые codes;
- удаление просроченных сессий/старых rate-limit записей с сохранением актуальных сессий и действующих блокировок;
- медленная загрузка тела запроса не блокирует другие API-запросы; истёкший cookie на mutation даёт authentication error;
- CSV export защищён от spreadsheet formula injection и не содержит secret values.

Воспроизведение из `backend/`:

```bash
pip install -r requirements-dev.txt
pytest -q
```

Для PostgreSQL используйте **отдельную тестовую БД**: фикстуры удаляют таблицы перед каждым тестом.

```bash
TEST_DATABASE_URL=postgresql+psycopg://test_user:test_password@127.0.0.1:5432/secrets_hub_test pytest -q
```

## Проверка интерфейса в браузере

В React-интерфейсе с настоящей PostgreSQL вручную пройден мастер чистой установки, вход, создание и копирование Login, создание collection, импорт WireGuard с просмотром конфигурации/QR, генерация SSH Ed25519, одноразовая временная ссылка, включение TOTP, скачивание recovery codes, создание и скачивание зашифрованного backup, загрузка файла и Restore. После Restore выполнен повторный вход с TOTP и проверены восстановленные записи. Скачивание файлов и подтверждения проверены в Google Chrome. Также проверены блокировка/разблокировка, история версий и восстановление предыдущей версии, повторная генерация recovery codes и обработка неправильного пароля при reauth.

Затем проверена окончательная production-сборка из Docker через nginx: вход, Dashboard, список и маскирование значений, действие Copy с записью в audit, Security Center и сохранённый каталог backup после CLI Restore. Все записи в QA созданы для тестирования; они не включены в исходники и архивы приложения.

Проверены размеры desktop 1440×960, tablet 1024×768 и mobile 390×844. На мобильной ширине горизонтального переполнения страницы нет: ширина body равна 390 px. Финальные снимки интерфейса сохранены отдельно от исходников. TypeScript и Vite production build завершились успешно.

## Миграции

В отдельной чистой PostgreSQL выполнены `alembic upgrade head` и `alembic check`. Созданы revision `0001` и единственная строка неинициализированных настроек. Проверка схемы завершилась: `No new upgrade operations detected.`

## Зависимости

`pip-audit 2.10.1` проверил закреплённые требования и разрешённые транзитивные зависимости. Найденные advisories старых `cryptography 46.0.5` и `pytest 9.0.2` устранены обновлением до `cryptography 50.0.2` и `pytest 9.0.3`. Pytest и HTTPX находятся только в `requirements-dev.txt`.

| Проверка | Проверено пакетов | Результат |
|---|---:|---|
| `pip-audit -r backend/requirements.txt` | 29 | No known vulnerabilities found |
| `pip-audit -r backend/requirements-dev.txt` | 36 | No known vulnerabilities found |
| `pip-audit` по фактическому `pip freeze` Linux Docker API | 30 | No known vulnerabilities found |

Первые два прогона проверили разрешённые Python-пакеты в CPython 3.12/macOS arm64; третий — все точные версии, фактически установленные в Linux API-образе, включая Linux-only greenlet. Найденных известных advisories нет. OCI images и пакеты ОС этим аудитом не проверялись. Обновление cryptography сверено с [официальным changelog](https://cryptography.io/en/latest/changelog/). Frontend использует Vite 6.4.3; проверка `pnpm audit` не выявила известных vulnerabilities.

## Развёртывание

Выполнены `bash -n` для `install.sh`, `update.sh`, `backup.sh`, `restore.sh` и `docker-compose config --quiet`. Для реального запуска создан отдельный Colima-профиль с Docker Engine 29.5.2, Linux arm64, Ubuntu 24.04.4. Чужие Docker/Colima profiles не изменялись. API использует Debian 13.7 внутри `python:3.12-slim`, PostgreSQL — `postgres:17-alpine`, web — `nginx:stable-alpine`.

Оба образа успешно собраны из окончательных исходников: frozen pnpm install, TypeScript, Vite production build и установка Python dependencies. Финальный JavaScript bundle — 311.33 kB, gzip 90.91 kB. После `docker compose up --wait` все три контейнера Healthy; наружу открыт только web, API/PostgreSQL портов на host нет.

Настоящий `install.sh` прошёл на новом пустом каталоге Linux-VM: вопросы о порте, адресе, пути данных, HTTP/HTTPS behind proxy и создании администратора через браузер. Установщик создал `.env` с правами 600 и случайным DB password; Setup затем выполнен через настоящий HTTP API. Первый installer smoke выявил ошибку вложенного PGDATA при umask 077; исправлена конфигурация на штатный `/var/lib/postgresql/data`. Повторная установка с ещё одним пустым каталогом прошла полностью. Фактический PGDATA имеет права 700 и владельца postgres UID 70.

В окончательных контейнерах проверены:

- `nginx -t` — successful;
- API работает от UID/GID 10001, `CapEff=0`, запись в read-only `/app` запрещена;
- `/data`, `/data/keys`, `/data/backups` — 700; `master.key` — 600, владелец 10001;
- `/health` проверяет DB, storage и encryption и возвращает 200 после setup/restore;
- PostgreSQL runtime settings: `log_statement=none`, `log_min_error_statement=panic`, оба parameter logging limits — 0;
- фактические Docker logs не содержат ни одного известного значения секрета, пароля, recovery key, TOTP seed или recovery code из сценария;
- отдельный `pip check` в API-образе — No broken requirements found.

Через настоящий HTTP nginx успешно пройдены 11 этапов: чистый Setup → administrator → logout/login → Create Secret → explicit Copy → Collection/Edit → WireGuard import/config/QR/export → SSH Ed25519/passphrase/fingerprint → password-protected one-time Temporary Link/Copy/exhaustion → Enable TOTP/recovery-code login → Create/Download encrypted Backup → Delete Secret → Restore → session/link/recovery-code revocation → login с TOTP и создание новых recovery codes. Metadata и audit проверены на отсутствие secret value. Дополнительно повторён restore после последнего исправления каталога копий: record, файл, download и last_backup сохраняются.

Сам `restore.sh` также выполнен в Linux-VM: подтверждение RESTORE, пароль только через stdin, остановка API, offline restore, автоматический restart, health200 и отзыв сессии. Исходный encrypted файл с правами 600 не изменялся.

Для HTTPS поднят отдельный локальный nginx proxy с временным сертификатом. Проверка выполнена через `curl --cacert` и HTTPX с доверенным CA, без отключения certificate validation. Проверены HTTPS health200, HSTS, Secure/HttpOnly/SameSite=Strict cookies, login, Origin/CSRF, создание/Copy/удаление секрета и `HTTPS Detected=true`. Proxy переписывает поддельные X-Forwarded-For/Proto; прямой HTTP запрос с forged `X-Forwarded-Proto: https` даёт `HTTPS Detected=false`. API доверяет только web-контейнеру, web — только точному настроенному IP TLS proxy.

Общий nginx API limiter 30 requests/second с burst60 проверен настоящим burst180: получено 98 nginx HTTP429, остальные запросы завершились200; static приложение оставалось доступно200.

Конфигурация учитывает request buffering в tmpfs 128 MiB для допустимой encrypted backup, отключает сохранение API responses во временные proxy files и SQL parameter/statement logging. Restore передаёт пароль и encrypted backup через stdin, чтобы не раскрывать пароль в аргументах/environment и не требовать UID 10001 доступа к исходному host-файлу.

**Границы проверки:** installer запускался на чистых данных Ubuntu Linux-VM, а не на отдельной чистой машине Debian 12/13. Debian проверен как реальный API container userland. Не выполнены bare-metal Debian install, публичный DNS/ACME/боевой сертификат, amd64 build, длительный нагрузочный прогон, независимый pentest и аудит пакетов ОС/OCI images. Перед размещением настоящих секретов повторите установку и restore на целевом Debian с вашим HTTPS proxy и политикой резервного хранения.
