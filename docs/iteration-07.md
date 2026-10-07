# Итерация 07 · v0.7.0

Дата: 4 октября 2026. Результат — локальный encrypted client-profile store DEV-07 с отдельным ключом и атомарной ротацией. Приоритет владельца сохранён: полезный кабинет/конфиги раньше WebAuthn, recovery codes и fresh auth. Существующие user login/recovery и admin TOTP не менялись.

## Выполнено

- Пакет `internal/profilevault`: AES-256-GCM стандартной Go библиотеки, random 96-bit nonce, раздельные nonce/ciphertext. AAD связывает purpose/version/key ID и owner/device/profile/protocol/generation/format. Лимит plaintext 64 KiB, пустая запись запрещена.
- Отдельный purpose-tagged random 256-bit key file. Explicit/exclusive create, private parent/file permissions, effective UID, отказ от symlinks/aliases и неизвестного формата. Admin TOTP raw key не принимается. CheckLocation требует расположение вне user state/DB backup root; key bytes не печатаются.
- Portal schema v5: singleton активного key ID/revision и UNIQUE index `(key_id,nonce)` для encrypted records. User state v4→v5 и v3→v5 мигрирует CLI; runtime с прежней схемой закрыт. Control v2/admin v1 сохранены.
- Trusted storage API StageProfileSecret: owner/current generation/pending/revision binding, транзакционное сохранение ciphertext + audit и увеличение device revision. Повтор того же содержимого идемпотентен, перезапись конфликтует. Plaintext не передаётся в SQL/audit. Staging остаётся pending, не создаёт installed proof/IP/peer и запрещает локальную отмену заявки.
- Внутренний owner reader принимает только current ready generation, непустой installed revision, active/partial device и active user. Чужое/отсутствующее ID одинаково not found. Не регистрирует HTTP route и не подтверждает actual peer.
- Ротация перешифровывает все состояния и поколения, включая revoked, одной writer transaction с одним plaintext buffer на запись. Active key меняется вместе с ciphertext и audit. Повреждение любой записи/audit error откатывают всё; stale writer после commit отказывает; retry неизвестного результата проверяет всю БД новым ключом. Прежние key files сохраняются.
- Trusted CLI: `profile-key-create`, `profile-vault-init`, `profile-vault-check`, `profile-key-rotate`. Нет plaintext import/dump. CLI открывает только существующий user store без автоматической миграции или создания новой БД.
- Добавлены ADR-0008 и profile-vault runbook; обновлены README/AGENTS/API version, canonical backlog и ближайшая очередь.

Storage API вызывается тестами и подготовлен для следующего проверенного importer. Он принимает opaque bytes и **не является валидатором client-only экспорта**. В кабинете текущей поставки рабочие конфиги не появляются. HTTP процессы не получают profile key; full-access/management exports не имеют нового пути upload.

## Проверки

| Проверка | Результат |
|---|---|
| `npm run check` | PASS: Go vet/race tests, generated API drift, Svelte/TS 0 errors / 0 warnings, Vite build |
| `npm run build` | PASS: frontend и 6 Go executables |
| `npm run test:persistence` | PASS: persistence/revision/ownership/readiness/listener regression с portal v5 |
| Demo browser | 4/4 PASS, desktop/mobile |
| User auth и devices browser | 6/6 PASS: invite/login/logout/recovery, request/reload/conflict/rename/cancel/quota |
| Admin browser | 2/2 PASS: пароль/TOTP, отдельная сессия, CLI lifecycle |
| AEAD binding | PASS: round-trip; разные nonce; подмена owner/device/profile/protocol/generation/format, nonce и ciphertext; wrong/nil key; invalid size |
| Key files | PASS: missing/overwrite, сохранение идентичности, symlink/ancestor alias, permissions, external state root, raw admin key/invalid purpose/version/JSON |
| Staging/reader | PASS: ownership/revision/generation, повтор/конфликт, pending запрет, active ready read, disabled user запрет, staged cancel guard |
| At-rest boundary | PASS: random test plaintext отсутствует в SQLite DB и WAL после staging; это локальный тест, не доказательство отсутствия всех копий в памяти/OS |
| Atomic rekey | PASS: все записи читаются новым ключом, включая revoked; состояния/поколения сохраняются; повтор не меняет данные |
| Rollback | PASS: stage audit failure не сохраняет secret; rotate audit failure откатывает записи; повреждение последней записи откатывает уже выполненные rekey updates |
| Concurrent DB handles | PASS: stage со старым ключом и rotation сериализуются; результат содержит только новый активный key ID, поздний stale writer отклонён |
| Nonce/cancel guards | PASS: DB отвергает одинаковый nonce/key ID; отмена запрещена при установленном другом поколении и наличии subscription |
| Upgrade v4→v5 | PASS: user session и request ID/revision сохраняются; пустая заявка остаётся отменяемой. Прежний v3 upgrade test также PASS |
| CLI lifecycle | PASS: exclusive key create, init/check, rotation/retry, старый ключ отказывает, оба файла остаются; ключ внутри state root отклонён до записи |

Полный браузерный набор — **12/12 PASS** на desktop и mobile 320 px. Среда: Linux x86_64, Go 1.27.1, Node 24.19.0, npm 11.9.0, Playwright 1.63.0, Chromium 153.0.8010.0. Использованы внешние launch configs для доступного локального Chromium; в исходниках обычные Playwright configs. Self-signed TLS допускается только browser configs локального стенда. Remote CI не запускался.

Новый nonce index обнаружил невалидную старую test fixture: два profiles получали одинаковые искусственные key ID/nonce. Fixture скорректирована на один профиль; сам cancel guard не ослаблен, uniqueness отдельно проверена. При подготовке не были использованы реальные credentials/конфиги. Браузерные сценарии подтвердили регрессии интерфейса; отдельной формы vault UI нет.

## Статус бэклога

Canonical `vpn-platform-backlog-v1.0.md` обновлён до содержимого версии 1.2, ID/критерии сохранены. **DEV-07: Backlog → Verification** — локальные crypto/storage/rotation критерии проверены, production UID/backup recovery и интеграция importer/download остаются открытыми. Из 63 исходных задач: **49 Backlog, 11 In progress, 3 Verification, 0 Done по полным критериям**. GW-01…08 — 8 Backlog без runtime pairing/apply.

Основная specification и отчёты iteration-01…06 сохранены без изменений. DEV-02 отражает portal v5; DEV-08 не объявлен выполненным. Следующий результат: **PRE-04 + DEV-08 trusted client-only import**, затем DEV-09 verified download/QR/client round-trip. См. `next-iteration.md`.

## Ограничения

Ротация storage key не отзывает VPN-доступ и не меняет его ключи/поколения. Удалять старые key backups автоматически нельзя: они нужны прошлым snapshot. Ротация работает одной транзакцией с 30s CLI timeout; большие production наборы и recovery после реального crash/потери питания отдельно не тестировались. Транзакционный rollback при error проверен, это не полноценный backup/restore drill.

At-rest encryption защищает отдельную копию БД, не скомпрометированный процесс/root с доступом к ключу; best-effort clear не уничтожает гарантированно все копии в Go/AEAD/JSON memory. Уникальность сохранённых nonce проверяется DB, но все попытки шифрования до rollback не учитываются постоянным счётчиком: сохраняется стандартный лимит <2^32 GCM encryptions на ключ.

Реальные VPS, firewall/routes/SSH, agent, реальные VPN-клиенты и доступность из РФ не изменялись/не проверялись. Production UID isolation, Windows ACL/macOS и backup recovery не доказаны. HTTP profile-key startup check/real download будут подключены после проверенного importer; текущий HTTP процесс не открывает ключ. G0/G1 и последующие gates остаются открыты.

Архив содержит source и документацию, без runtime DB, keys, credentials, dependencies и executables. Git/remote не создавались; пользователь загрузит проект позже.
