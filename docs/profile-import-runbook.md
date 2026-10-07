# Trusted client import · v0.14.0

Importer работает на локальном Linux стенде с user portal v5 и profile vault. Создаёт только зашифрованную pending-запись. Не устанавливает peer, не подключается к VPS, не меняет routes/firewall, не объявляет профиль ready и не выдаёт download.

Поддерживаются **`vless-reality-uri` и `awg-3.1-conf` subsets** из `client-format-matrix.md`. `vpn://`, JSON, full-access Amnezia export, SSH credentials и wrappers не принимаются. Client URI содержит секреты: хранить исходник приватно, не вставлять URI в flags/URL/logs/git/чат и не пытаться передавать её аргументом CLI. Схемный validator не является универсальным DLP-анализатором; trusted operator отвечает за происхождение выбранного клиентского экспорта.

## Подготовка и выбор цели

```sh
npm run setup
npm run build
npm run auth
```

Пользователь активирует приглашение и добавляет заявку на устройство. Остановить стенд для локального обслуживания (транзакции защищают от параллельной записи, но dry-run не резервирует revision). Затем создать отдельный ключ и initialized vault, если это ещё не сделано:

```sh
./build/vpnctl profile-key-create
./build/vpnctl profile-vault-init
./build/vpnctl profile-targets --login family-test
```

Не повторять key-create поверх существующего файла: exclusive create откажется. После ротации явно передавать актуальный `--profile-key` во все import/vault commands. `profile-targets` выводит только owner/device/profile ID, protocol/generation/revision/state/format/stored. Можно добавить `--device-id DEVICE_ID`. Указывать активный обычный аккаунт; device другого owner не появится.

Выбрать **REALITY или AWG pending slot**, соответствующий формату, и скопировать точные ID/generation/device revision из отчёта. Для AWG заменить `--format vless-reality-uri` на `--format awg-3.1-conf` и указать private `.conf` файл. CLI выводит protocol из формата; несовместимый slot отклоняется. Нельзя угадывать revision или исправлять live DB вручную ради приёмки.

## Dry-run и запись

Подготовить файл `client.txt` с одним клиентским URI в отдельном каталоге 0700, файл 0600, принадлежащем текущему UID. Symlink/aliased parent, nonregular file, публичные permissions, пустой/слишком большой источник отклоняются. Максимум 64 KiB; stdin поддерживается через `--input -`, но не вводить секрет в открытый терминал с echo/history. Размер одного input ограничен до чтения/валидации.

```sh
./build/vpnctl profile-import --owner-id OWNER_ID --device-id DEVICE_ID --profile-id PROFILE_ID --generation 1 --expected-revision REVISION --format vless-reality-uri --input /absolute/private/client.txt --dry-run
```

Без `--dry-run`/`--apply` поведение тоже **dry-run**. JSON `would-import`, `dry_run:true`, текущая `device_revision`. CLI открывает SQLite read-only, не пишет audit/ciphertext/revision и не создаёт/мигрирует БД. SQLite может управлять WAL sidecar files; обещание относится к логическим данным и отсутствию mutating SQL. Проверяется активный ключ, owner/target/current generation/pending state/revision, возможный повтор и конфликт клиентской identity. Source не переписывается.

С теми же flags для записи:

```sh
./build/vpnctl profile-import --owner-id OWNER_ID --device-id DEVICE_ID --profile-id PROFILE_ID --generation 1 --expected-revision REVISION --format vless-reality-uri --input /absolute/private/client.txt --apply
```

Apply повторяет все проверки под writer lock. JSON `imported-pending`, новая device revision. До commit ошибка audit/SQL откатывает всё. Следующий identical retry → `already-stored` и текущая revision; старый expected revision при replay допустим. Иной payload/format, изменённая revision новой записи или другое поколение — конфликт. Изменение URI query order/newline считается другим payload; данные не нормализуются. Выход из pending запрещает повторную запись.

Один UUID нельзя назначить двум неотозванным профилям даже разных owners/endpoints; это локальная политика проекта. Проверка включает все неотозванные поколения и устройства, в том числе disabled owners (отключение кабинета не отзывает VPN). Decrypt/parse выполняются в памяти; credential hash/UUID в БД или отчёт не добавляются. После key rotation конфликт сохраняется. Unknown peers не перечисляются и не удаляются: ни один сетевой adapter не вызывается.

## Результат и ошибки

В кабинете: **«Сохранён, ждёт сверки»**, пояснение о неподтверждённой установке. Нет URI/UUID/pbk, ссылки download и кнопки отмены импортированной заявки. API metadata содержит только format/state; pending download →409, попытка cancel →409. IP allocation/installed revision остаются отсутствующими. Все CLI отчёты явно содержат `ready:false` и `peers_verified:false`.

| Код | Следующее действие |
|---|---|
| `UNSUPPORTED_FORMAT` / `INVALID_EXPORT` | Сверить матрицу; не удалять неизвестные поля ради обхода проверки |
| `INPUT_SOURCE` | Проверить источник/размер/permissions приватного файла |
| `INVALID_TARGET` / `TARGET_NOT_FOUND` | Повторить profile-targets, проверить owner/device/profile/generation |
| `REVISION_OR_CONTENT_CONFLICT` | Обновить targets; убедиться, что импортируется тот же файл. Не перезаписывать уже сохранённый профиль |
| `CREDENTIAL_CONFLICT` | Получить отдельный клиентский UUID или AWG keypair для другого устройства |
| `TARGET_NOT_PENDING` / `OWNER_INACTIVE` | Проверить состояние владельца/устройства; не править state вручную |
| `PROFILE_KEY_UNAVAILABLE` / `PROFILE_AUTHENTICATION_FAILED` | Проверить active key/vault; не генерировать replacement поверх ключа |
| `IMPORT_FAILED` | Общая ошибка DB/IO/context; приватно проверить доступность локального state и повторить безопасный dry-run |

При ошибке CLI возвращает nonzero exit и безопасный JSON report. URI, UUID, pbk, исходный path, поля чужого profile и parser error details не печатаются. `profile-targets` отдельно возвращает nonsecret IDs выбранного пользователя.

## Обновление и следующие границы

Новых migrations нет: portal v5, control v4, admin v1. Старый профиль хранится без пересериализации; key rotation из v0.7 продолжает работать. Обновление source не переносит runtime state/keys автоматически. Plaintext исходник всё ещё находится у trusted operator: его защита и отдельная процедура очистки остаются его ответственностью.

Дальше нужен actual RU peer reconciliation, подтверждение expected endpoint/параметров и installed revision, затем verified owner download. Client import на реальных устройствах и AWG 3.1 round-trip не проверены. Этот локальный importer не закрывает DEV-08 целиком и не проходит production gate.

## AWG 3.1

Нативный `.conf` без wrappers, один `[Interface]`, затем один `[Peer]`. PrivateKey/HeaderProtectionKey/optional PresharedKey — секреты. Поддерживаемые поля и пределы — `client-format-matrix.md`; нельзя выбрасывать отвергнутые неизвестные параметры, чтобы пройти importer. Не запускайте client export через awg-quick для проверки: importer не исполняет hooks и не изменяет сеть.

Original bytes остаются неизменными, включая новые timers, CPS, comments, LF/CRLF. Credential conflicts сравниваются по public key, вычисленному из PrivateKey; два различающихся private encodings одного X25519 ключа считаются одной identity. Статус после сохранения остаётся pending, device revision увеличивается на один; повтор exact bytes безопасен. Read-only dry-run не резервирует слот/ключ. Настройка работающего сервера, IP ownership и нативный клиент ещё требуют отдельной проверки.

Обновление v0.19: консервативная VLESS credential uniqueness учитывает UUID wire aliases bytes6/7 по pinned Xray contract, сохраняя exact UUID/export bytes. Snapshot/users readback отвергают duplicate wire identity; alias не exact match. Partial users CLI описан в profile-xray-users-runbook.md; enumeration/core identity/revision/transport/client/ready не подтверждены. Это не general VLESS compatibility acceptance.
