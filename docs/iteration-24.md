# Итерация24 · v0.24.0 · 07.10.2026

## Исправления review и подготовка отдельного стенда

OpenAPI Profile.format и generated TS включают awg-3.1-conf; DeviceManager показывает сохранённый pending status для AWG и VLESS, download/cancel restrictions сохранены. AdminUsers исключает revoked invite/recovery tokens, used не выводится по отозванному token; expiry сравнивается через julianday с fractional seconds. Safe audit представляет device.request.cancel как device.cancel с безопасным device ID, поддерживает прежний action, неизвестные payloads не раскрываются. SQLite Windows drive letter теперь находится в file URI path вместо authority.

Local-auth portal/admin проверяют TLS lifetime/SAN/key match/server EKU и Linux private key permissions до открытия DB/listener, а также built frontend entry/mount, referenced assets и весь обслуживаемый tree. Symlink/Windows junction/hidden/unexpected assets отклоняются. Trusted stand-check читает существующие DB без migrations/audit/session writes, проверяет local-auth dataset/schema/TLS/frontend; --require-admin требует Linux/separate state/key/decryptability/confirmed MFA account. Logical read_only:true не означает отсутствие SQLite WAL/SHM side effects, что явно отражено sqlite_sidecars_possible:true и в runbook. Нет control DB/profile key/network/tool calls или ready transition, VPN/delivery flags всегда false.

Linux amd64/arm64 bundle использует prebuilt dist и CGO-disabled cross-build только portal/admin/vpnctl. Closed archive includes frontend/admin helper/runbook/release manifest/checksums, executable modes0755; secrets/state/caches/sources/agent/controller/probe отсутствуют. Не перезаписывает архив; cleanup confined to new staging. Инструкция direct loopback HTTPS startup, private external state/offline init/enroll/confirm/restart находится в stand-runbook.md. Без Node/Go на runtime. Linux execution/native/client/UID acceptance в manifest false, cross-build не заменяет фактический запуск.

E2E executable paths исправлены для Windows. Optional FVPN_TEST_BROWSER=chrome|msedge выбирает installed channel; unset остаётся pinned bundled Chromium, unknown value отвергается. Suites не пропускаются. source-map-js обновлён1.2.1→1.2.2 из-за GHSA-68fv-2mgg-jv7q; direct dependencies/go.sum не менялись. CI дополнен release/intents checks и cross-build; удалённого CI запуска нет.

## Проверки на текущем Windows компьютере

Node24.21.0/npm11.19.0, official SHA-verified Go1.27.1. Project engine допускает этот Node; сборочная SDK/cache находятся только в ignored build. Windows Chrome154.0.8037.98 использован через explicit channel: bundled Chromium install после пяти CDN timeout не выполнен.

- npm run build PASS: Svelte0 errors/warnings, Vite frontend +6 Go executables.
- npm run test:release PASS8/8: closed targets/private inputs/link rejection, hash/false acceptance, независимый USTAR inspector и actual Windows tar extraction.
- npm run test:persistence PASS: process restart/revision/ownership/read-only HTTP/listener separation.
- npm run test:e2e PASS4/4, desktop/mobile demo.
- npm run test:e2e:auth PARTIAL:8/12 PASS (invite/login/recovery/devices/guides desktop/mobile),4 import tests FAIL на intentional Windows profile-key ownership restriction. AWG pending browser regression требует Linux.
- npm run test:e2e:admin BLOCKED на intentional Windows admin master-key ownership restriction; authenticated cancel/recovery browser regressions требуют Linux.
- npm run check NOT PASS: Go vet прошёл; go test -race остановился: CGO/C compiler unavailable. Remaining API generation drift/Svelte/Vite проверяются отдельно, это не полный check.
- go test ./... без race NOT PASS: store/app/auth/httpapi/agentprotocol/guides/reconciler/runtimeenv/AWG/Xray inventory/observe packages PASS;5 existing key/private-file tests в cmd/vpnctl/adminauth/clientconfig/profilevault FAIL вследствие strict Windows unsupported file ownership. Policy не ослаблялась, skips не добавлялись.
- New app boundary targeted tests43 PASS/4 SKIP:3 leaf-symlink privilege unavailable, POSIX0644 privacy case inapplicable on Windows. Windows root/ancestor/referenced/unreferenced junction и TLS parent cases PASS. New stand CLI portal read-only/hash/no-control/missing/demo/invalidargs/platform-negative tests PASS. Linux positive admin MFA branch не выполнен.
- Targeted admin users/audit/views tests PASS; fractional expiry/revocation/consumption/cancel/legacy/allowlist regressions included.
- New TestAdminReadOnly PASS: pending→confirmed MFA→disabled; read-only mutation denied, account/audit/session unchanged, wrong-kind/checksum-corrupt/missing DB rejected. Uses random in-memory vault for store boundary, не проверяет Linux filesystem key ownership.
- npm run test:intents NOT PASS на Windows: worker SIGTERM через Node принудительно завершает процесс, exit code null вместо Linux clean code0; synthetic worker shutdown smoke requires Linux. Не выдавать kill за graceful shutdown.

Final API generation drift PASS, Windows Go vet PASS; Linux amd64 CGO0 cross-target go vet ./... PASS (статический анализ, не execution). Final npm audit:0 vulnerabilities. Gofmt clean. Actual Linux process/admin/import, AWG/Xray tool/API/responding core/current revision/REALITY transport, client export/import/handshake/DNS/routing и UID/socket/fail-closed acceptance не выполнены. Linux stand и версии VPN/client ещё не определены владельцем. Никаких VPS/SSH/firewall/routes/public deploy действий.

Built vpnctl Windows CLI dispatch smoke PASS: isolated auth-init→stand-check с настоящим built dist сообщает status:ok и все VPN/delivery flags:false; control state отсутствует, одноразовый state удалён после проверки. Linux amd64 и arm64 runtime tar.gz cross-build PASS. Финальные архивы проверены независимым Python tar reader:10 файлов, only3 binaries, ELF64 little-endian arch62/183, executable0755, non-executable0644, closed contents/no state/keys, внешние/внутренние SHA256 и release.json metadata/false acceptance совпадают. Linux runtime не запускался.

## Статусы

Canonical snapshot1.19 обновлён локально, исходные63 work/dependencies/acceptance и statuses45 Backlog/15 In progress/3 Verification/0 Done сохранены. GW8Backlog; auth extras Deferred. KUK-5/M1-02/native/core/client/audited readiness transition, KUK-6/7 delivery и G1 остаются открыты. Linear/remote Git/CI в этой поставке не обновлялись. Source archive и runtime bundle не являются production/pilot RC. Следующий шаг: реальный Linux regression run, approved VPN stand inputs, затем actual core/client proof и audited transition; M2 после M1.
