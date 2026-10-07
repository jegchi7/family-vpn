# ADR-0002 — хранилища и миграции первой рабочей схемы

Статус: реализовано локально в v0.2.0. Не заменяет deployment-проверку прав разных UID.

## Решение

Две SQLite БД в отдельных приватных каталогах: `portal/state.db` и `control/state.db`. Portal содержит users/credentials/sessions/tokens/devices/profiles/instructions/health/audit и безопасные копии статусов операций. Control содержит nodes/revisions/operations/revocations и метаданные gateway pairing/sync. Приватные ключи узлов и gateway credentials в этих таблицах отсутствуют; это будущий agent secret store.

`PRAGMA application_id` различает назначение файлов. Versioned embedded SQL migrations, SHA-256 каждого файла в history и `user_version` проверяются при каждом открытии. Будущая версия, пробел/подмена history, файл другой роли и сторонняя SQLite БД отклоняются. Весь набор ожидающих миграций выполняется в одной `BEGIN IMMEDIATE` транзакции; SQL error откатывает и DDL, и version/history.

`modernc.org/sqlite v1.60.0`, pure Go, закреплен в go.mod/go.sum. Foreign keys включены для каждого соединения через DSN; writer использует WAL, synchronous FULL, busy timeout 5 с. Один connection на store упрощает внутреннюю сериализацию, SQLite locking координирует разные процессы.

HTTP processes не запускают миграции и открывают **только portal DB read-only**. Admin пока читает ту же безопасную публичную модель; privileged reconciler ещё не реализован. `vpnctl demo-init` — явный локальный writer, готовит обе БД и seed. Demo-init не переименовывает существующие устройства и не освежает измерения. Это раздельные транзакции двух БД, не общая атомарная операция: повтор безопасен, будущий cross-store reconcile отдельный.

Интерфейс repository.Reader скрывает SQL и исключает управляющие команды. При отказе хранилища HTTP возвращает 503 STORAGE_UNAVAILABLE без SQL/path/driver messages; не подставляет новые fixtures. /healthz — liveness процесса, /readyz — доступность portal store.

## Права и ограничения

Новые каталоги 0700, файлы 0600; existing broad permissions и symlinks отклоняются вместо неявного chmod. Production требует разных UID и защищённых от подмены ancestor directories. Local demo запускает оба процесса одним владельцем, поэтому наличие двух файлов само по себе не является ОС-изоляцией. Windows ACL deployment не реализован; production предназначен для Linux после NET-07.

HTTP запуск без --demo всё ещё запрещён. Дополнительно AssertDemo отвергает БД без явного seed marker. AUTH ещё нет; schema credentials не реализует password/WebAuthn flows. Ciphertext поля профилей — заготовка под DEV-07, шифрование пока не реализовано, реальные конфиги не принимать.

Append-only triggers защищают tombstones от обычного UPDATE/DELETE, но не от привилегированного владельца файла, который может изменить schema. Tombstone record сам по себе не отключает реальный VPN. Runtime revoke и backup/restore policy остаются DEV-18/25.

## Источники

- https://pkg.go.dev/modernc.org/sqlite — driver, DSN, pure-Go implementation.
- https://www.sqlite.org/lang_transaction.html — транзакции и BEGIN IMMEDIATE.
- https://www.sqlite.org/pragma.html — application_id, user_version, foreign_keys, WAL.

## Дополнение v0.3.0

ADR-0004 добавляет separate local-auth mode: portal DB writable для auth, runtime schema validation без миграций. Прежний demo остаётся read-only. Portal schema v2 добавляет password uniqueness и persistent rate counters; control schema не меняется.
