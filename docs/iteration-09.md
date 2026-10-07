# Итерация 09 · v0.9.0 · 04.10.2026

## Результат

DEV-08 получил trusted read-only `profile-preflight`: stored client binding/current generation/device revision, pinned private Xray JSON snapshot, explicit inbound tag и endpoint mapping. Сверяются UUID/flow/порт/listen/SNI/shortId и X25519-derived public key. Duplicate/case-alias JSON keys, ambiguity, unknown selected security fields и unsupported transport закрыты. Snapshot/server keys не сохраняются в portal DB. Report только fixed mismatch names и safe error codes; ready/runtime/client verified всегда false.

## Фактическая проверка

- npm run check PASS: Go vet/race всех пакетов, API generation drift, Svelte 0 ошибок/0 предупреждений, Vite.
- npm run build PASS: frontend и 6 Go binaries; npm run test:persistence PASS.
- Browser: user auth/device/import+compiled preflight 8/8; demo 4/4; admin TOTP 2/2 — 14/14 PASS.
- Parser tests: match/каждый mismatch, snapshot digest drift, duplicate keys/tags/UUID, extensions и malformed inputs. Store: RO handle, active owner/generation/revision/key, no audit/state/revision writes. CLI default binding/unknown apply flag/невывод секретов.
- JSON fuzz smoke: 3s, 2 workers, 50 927 executions, PASS; не exhaustive security proof.

Окружение: Linux x86_64, Go 1.27.1, Node 24.19, npm 11.9, Playwright 1.63, Chromium 153.0.8010.0. Runtime browser config вне source для доступного local binary; shipped configs стандартные. Self-signed TLS только local stand.

## Ограничения и следующий шаг

Проверен comparator, не actual running core. Нет изменения сети, ready, real owner download, AWG import или мобильного VPN client round-trip. Server snapshot может быть stale даже при matching digest; endpoint mapping заявляет trusted оператор. Нет гарантированного memory zeroisation Go allocations. Реальные VPS, external Git/CI/deploy не затронуты. Portal/control/admin schemas остались v5/v2/v1.

Основной backlog версии 1.4 обновлён, исторические 01–08 и baseline spec сохранены. Цель владельца — итеративная v1; локальные закрытые части и внешние inputs записаны в delivery-roadmap. Следующая независимая поставка — DEV-12/13 closed read-only admin queue и safe audit.
