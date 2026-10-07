# Read-only админка · v0.10.0

## Запуск

Настроить отдельный password+TOTP вход по `admin-auth-runbook.md`, затем `npm run admin` и открыть https://127.0.0.1:9443. User portal остаётся на 8443; admin DB/master key отдельно. Process admin читает user portal DB **read-only**, profile key/agent socket/control DB не открывает. Демонстрационный listener не показывает эти списки. Нет production bind.

## Экраны

- Заявки и устройства: default pending, фильтр всех states, owner login, OS, generation/revision, current profiles. «Ждёт импорта»/«Сохранён, ждёт сверки». Раскрываемые IDs помогают выбрать importer binding; plaintext/key/address/installed revision не выдаются. Unknown peers не изменяются.
- Пользователи: обычные users invited/active/disabled, занятые слоты/лимит, состояние live/expired/used invitation и live recovery. Admin credentials сюда не входят. Raw invitation/recovery token и hashes не возвращаются.
- Журнал: известные действия кабинета/trusted CLI, actor category, existing object ID соответствующего типа, timestamp и allowlisted result. Arbitrary action/outcome заменяются other/unknown, actor/free-text object_ref/request_id/operation_id не выдаются. Это portal audit, не полный admin-auth или agent journal.

На экране 25 записей. «Далее» заменяет страницу, «Сначала»/«Обновить список» начинают сначала. Устройства/users сортируются по stable IDs; audit по нормализованному UTC времени и ID descending. Наносекунды сохраняются. Новые строки между запросами не превращают keyset pagination в immutable snapshot; refresh покажет актуальный первый набор. Filters сбрасывают cursor. Нет автоматического infinite scroll.

## API

GET `/api/v1/admin/users`, `/api/v1/admin/devices`, `/api/v1/admin/audit`. Authenticated separate admin listener only. limit default25, range1..100, optional after≤256; devices state defaults pending и допускает all/pending/active/partial/revoking/revoked/error. Неизвестные/duplicate keys, invalid query encoding, cursor/state дают400 без echo. Cursor — metadata, не credential и не permission. User/demo404 даже с copied admin cookie, anonymous management401; нет admin POST mutations. Headers no-store/no-referrer/nosniff.

Invitations/recovery/import продолжают выдавать существующие trusted CLI команды; интерфейс не отправляет их людям. Snapshot/config keys остаются за management boundary. Stale profile state не является доказательством online; даже ready DTO лишь состояние записи. Current generation only. Schema migration не требуется: portal5/control2/admin1.

## Проверка и пределы

RO DB store tests: pagination users/audit (включая equal timestamp и fractions), slot/invitation state, imported pending metadata, invalid requests, unknown audit leakage, no mutation. HTTP: password/TOTP boundary, public copied-cookie404, bad query400, cache/referrer headers. Browser: imported request/users/audit desktop+320px, no secrets or overflow. Скриншоты `screenshots/iteration10`.

Real service UID isolation/production management origin, retention, admin mutations и сетевой журнал ещё не приняты. Admin UI работает только локально; не выставлять стенд наружу ради удобства. Приватные fixtures тестов вне source/архива, profile plaintext не попадает в screenshots.
