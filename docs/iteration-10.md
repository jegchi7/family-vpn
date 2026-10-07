# Итерация 10 · v0.10.0 · 04.10.2026

## Результат

DEV-12/13: separate authenticated management API/UI — users, invitation/recovery state, current-generation device/import queue, safe audit. Admin process читает user DB read-only, master/admin DB остаются отдельно. Нет profile key/control DB/agent socket/mutations. Default page25, максимум100, keyset cursors, state filter/reset/refresh/next; summary count обновляется вместе со списком. Unknown/free-text audit values не выдаются; time sorting сохраняет fractional seconds и deterministic ID ties.

OpenAPI/TS generation и info/server metadata обновлены. Profile/config/endpoint/credentials/one-time token/hash не входят в DTO. User/demo listeners404 даже с copied admin cookie; anonymous management401, bad query400. Cache/referrer protection сохранены. UI keyboard/buttons/details, desktop/320px без overflow.

## Проверки

- npm run check PASS: Go vet/race всех пакетов, API drift, Svelte 0 errors/0 warnings, Vite. Повтор после исправления summary refresh PASS.
- npm run build PASS, 6 Go binaries; npm run test:persistence PASS.
- Browser user/auth/devices/import/preflight8/8, demo4/4, admin TOTP/seeded actual portal requests/import/users/audit2/2 — 14/14 PASS. После summary refresh повтор admin2/2 PASS.
- Store RO handle, bounded/keyset pages, slot/live invitation states, current profiles, no read mutation, unknown audit no-secret output; fractional/equal timestamp cursor tests PASS.
- HTTP isolation/public404/admin MFA + safe headers, malformed/duplicate/unknown/oversized query/limit/state/cursor400 PASS.
- Desktop/mobile queue/users screenshots visually inspected; test-generated IDs допустимы metadata, raw config/TOTP secret/token/password отсутствуют.

Linux x86_64, Go1.27.1, Node24.19, npm11.9, Playwright1.63, Chromium153.0.8010.0. Browser configs вне source для available local binary. Schema5/2/1, без новой миграции. JS gzip около27.98kB.

## Границы

Только локальный стенд; production bind/VPS/Git/CI не выполнялись. View не доказывает online клиента. Issuance остаётся trusted CLI. Это portal audit, не full admin-auth/agent audit; retention впереди. Между страницами новые записи возможны, immutable snapshot не обещан. Real UID isolation и production management origin не приняты. DEV-12/13 целиком не Done.

Canonical backlog1.5 обновлён; baseline spec и reports01–09 сохранены. Следующая независимая поставка DEV-10: versioned guides/offline памятка, без выдуманной client compatibility. Runtime/client evidence до ready/download остаётся обязательным.
