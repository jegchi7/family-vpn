# ADR-0008 · Отдельное хранилище клиентских конфигов

Дата: 04.10.2026. Статус: принято для локального семейного MVP.

DEV-07 выделяется из форматного importer/download: storage не может доказать client-only export или установленный peer. Поэтому trusted StageProfileSecret остаётся внутренним API; произвольного CLI import/dump и публичной выдачи в v0.7 нет. DEV-08 требует PRE-04 и отдельного parser/round-trip review.

Выбран стандартный AES-256-GCM с random nonce. AAD связывает purpose/key ID, владельца, устройство, профиль, протокол, поколение и format. Ограничение 64 KiB на запись; UNIQUE index защищает сохранённые `(key_id,nonce)`. Секреты хранятся в ранее предусмотренных profile columns; portal schema v5 добавляет singleton активного ключа и индекс.

Profile key — отдельный purpose-tagged файл вне user state root, 0700/0600/current UID без aliases. Не использовать admin TOTP key. CLI создаёт его исключительно; missing/wrong/corrupt key не приводит к plaintext fallback или runtime key generation. HTTP пока не получает новый ключ.

Масштаб семейного MVP позволяет атомарное перешифрование всех записей одной writer transaction, с одним plaintext buffer на запись. Старый ключ читается до commit; прежний файл не удаляется. Metadata меняется только в той же транзакции после перешифрования. Stale writers проверяют active key под writer lock. Ошибка любой записи/audit откатывает всё; retry завершённой ротации проверяет новым ключом все записи. Batch/resumable rotation пока не нужна; production объём/timeout и backup recovery остаются отдельной проверкой.

Ротация storage key сохраняет поколения, состояния и installed revisions: она не отзывает конфиги, уже полученные пользователем, и не заменяет network revoke. Plaintext не передаётся в SQL или audit. At-rest encryption не защищает скомпрометированный процесс с доступом к ключу. Распределение UID и полноценный backup/restore drill не доказаны локальными тестами.
