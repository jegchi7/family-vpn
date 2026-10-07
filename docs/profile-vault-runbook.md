# Client profile vault · v0.8.0

Локальный слой DEV-07 хранит непрозрачные клиентские данные зашифрованными. Он не определяет совместимость формата и не устанавливает VPN peers. Trusted CLI profile-import использует отдельный clientconfig validator и ImportClientProfile. Поддерживается только VLESS/REALITY URI subset; инструкция — profile-import-runbook.md. Публичного upload и plaintext dump/рабочего download нет; storage API не заменяет проверку client-only экспорта.

## Первый запуск на Linux

После `npm run setup`, `npm run build` и создания user state через `npm run auth` остановить локальный стенд. Выполнить:

```sh
./build/vpnctl profile-key-create
./build/vpnctl profile-vault-init
./build/vpnctl profile-vault-check
```

По умолчанию user state — `var/auth`, ключ — **`var/profile-secrets/current.key`**, вне этого state root. Parent directory 0700 и key file 0600 принадлежат текущему effective UID. Key loader отказывает при symlink/alias, чужом владельце, общедоступных правах, неподходящем формате и отсутствующем ключе. Не исправляет существующие permissions молча. Key creation только явная и exclusive, без перезаписи; runtime не генерирует ключ автоматически.

Файл — purpose-tagged JSON с random 256-bit key. Admin TOTP использует отдельный raw key: его файл не принимается как client key. В БД нет ключевого материала; сохраняются только purpose-separated key ID, nonce и ciphertext. CLI не выводит plaintext или bytes ключа. `profile-vault-init` привязывает пустое хранилище к ключу; при повторе проверяет все зашифрованные записи. Иной ключ или ciphertext без metadata не принимаются автоматически.

`profile-vault-check` расшифровывает все зашифрованные поколения/состояния, очищает временные byte buffers и выводит только число записей и статус. Пустое хранилище → 0; это не проверка настоящих клиентов. HTTP процессы этой поставки **не открывают profile key**. Password/TOTP и запуск кабинета не зависят от его создания.

## Ротация ключа хранилища

Это перешифрование at rest, не ротация VPN-ключей/поколений и не отзыв доступа. Сначала отдельно создать и сохранить новый ключ:

```sh
./build/vpnctl profile-key-create --profile-key var/profile-secrets/next.key
./build/vpnctl profile-key-rotate --profile-key var/profile-secrets/current.key --new-key var/profile-secrets/next.key
./build/vpnctl profile-vault-check --profile-key var/profile-secrets/next.key
```

Ключи должны лежать вне выбранного `--root`. Обе файловые версии остаются на месте. После commit активный ключ БД — `next.key`; следующие операции явно получают `--profile-key var/profile-secrets/next.key`. Имя файла само по себе не выбирает активную версию. Проверка со старым файлом отклоняется. Автоматического удаления/переименования ключей нет.

Одна writer transaction читает записи всех поколений, включая pending и revoked, аутентифицирует их старым ключом и перешифровывает новым. Затем меняет active key ID и пишет audit. Не меняет profile state, generation, device revision или installed revision. До commit читатель со старым ключом работает со своей SQLite snapshot; после commit новый запрос со старым ключом безопасно отказывает. Старый writer повторно проверяет active key под writer lock и не может записать ciphertext предыдущей версии.

Повреждение любой записи, отсутствие ключа, audit/SQL error или отмена context откатывают всю транзакцию. Без успешного commit активным остаётся старый ключ. Повтор той же команды после неизвестного результата commit проверяет все записи новым ключом и возвращает 0 изменений; это безопасный retry. Оператор не должен удалять старый ключ до проверки результата и срока хранения старых резервных копий. Stop/restart с правильным ключом потребуется будущему download runtime; он ещё не подключён.

## Свойства storage API

AES-256-GCM через стандартный Go `NewGCMWithRandomNonce`: random 96-bit nonce, отдельные DB fields nonce/ciphertext. UNIQUE index `(key_id,nonce)` запрещает сохранённую коллизию. AAD содержит purpose/version/key ID и однозначный JSON tuple owner/device/profile/protocol/generation/format. Любая подмена tuple/nonce/ciphertext отклоняется; смешанные ключи не принимаются. Не использовать один ключ для 2^32 или более операций шифрования; при нашем масштабе запас большой, но это ограничение GCM сохраняется. DB index гарантирует уникальность сохранённых nonce, а не счётчик всех попыток Seal до rollback.

Лимит plaintext — 64 KiB, пустая запись запрещена. Внутренний `StageProfileSecret` требует active owner, совпадающее текущее поколение, pending device/profile и expected device revision. Транзакционно сохраняет ciphertext, увеличивает device revision и пишет audit. Повтор с тем же содержимым возвращает текущую запись; иное содержимое/format конфликтует. Повтор после выхода из pending отклоняется. Profile остаётся pending: нет IP allocation, installed proof, публикации и agent call. Отмена заявки после staging запрещена.

Внутренний owner reader отдаёт bytes только для текущего ready-поколения с непустым installed revision, active/partial устройством и активным обычным пользователем. Чужое/отсутствующее ID одинаково not found. Это ещё не HTTP выдача и не верификация внешнего peer. Формат-label в storage — metadata, не гарантия импорта в AWG/Amnezia/другой клиент.

## Обновление и резервные копии

Portal v4→v5 добавляет profile-vault metadata и unique nonce index. Остановить local HTTP процессы, сохранить консистентный private state принятым SQLite backup способом, обновить source и собрать, затем `./build/vpnctl auth-init --root var/auth`. Runtime со старой схемой отказывает, сам миграции не выполняет. v3→v5 также поддерживается последовательными миграциями. Control v2 и admin v1 не меняются.

Нельзя копировать только `.db` активной WAL базы и считать это консистентным backup. Ключи резервируются отдельно от DB state. Сохранить соответствие **snapshot → key ID → отдельный key backup**; архивы прошлых версий требуют старых ключей. Backup/restore automation и проверенный recovery drill ещё DEV-25/NET-09. Потеря всех копий нужного ключа означает потерю расшифровки; команда не создаёт replacement key поверх существующего.

At-rest encryption защищает отдельную копию SQLite, не процесс с правом чтения ключа, его память/core dump/swap или root. Очистка временных byte buffers — best effort, Go/AEAD и JSON key parsing не гарантируют уничтожение всех копий в памяти. Trusted ancestors и раздельные production UID требуют отдельной проверки. Linux local run проверен; macOS не проверен, Windows/другие ОС fail-closed без реализации owner/ACL checks.
