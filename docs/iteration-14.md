# Итерация14 · v0.14.0 · 05.10.2026

## Реализованный срез M1-01 / DEV-08

Возвращён фокус к выбранному владельцем M1/G1 — ручная выдача рабочих профилей. milestone-m1.md содержит последовательность M1-01…05, criterion/evidence и зависимость от фактического runtime/клиента. DEV-14/15 задел сохраняется, его дальнейшее расширение идёт после M1.

Новый explicit format awg-3.1-conf принимает client-only single Interface/Peer с ограниченной allowlist всех перечисленных AWG3.1 fields: J/S/H, HeaderProtectionKey, ContentPaddingAddition, таймеры, RandomTrailers/DisableCookies, I1…5 CPS, peer PersistentKeepalive range. Размер64KiB, duplicate/unknown fields, hooks/management/wrappers, неверные keys/ranges/CPS/endpoint/address/DNS отклоняются. Полный scope — client-format-matrix.md; это собственный subset, не универсальная upstream compatibility.

Original bytes хранятся неизменными, включая CRLF/LF, комментарии и порядок ключей. Identity AWG — public key, вычисленный из client PrivateKey; clamped equivalents конфликтуют даже при разных bytes. Validated identity расширена16→32 in-memory bytes, VLESS/Xray credential comparison остаётся16 bytes, DB/API schema не меняется. CLI выводит protocol из format; storage повторяет validation/binding в transaction. Dry-run read-only, apply pending, exact replay безопасен, audit failure rollback и rekey сохраняются.

Новых migrations нет: portal/control/admin5/4/1. Нет перехода в ready/installed revision, выдачи конфига, network/agent calls или core execution. Нет VPS/Git/deploy. ADR-0012, основной backlog1.9, README, import runbook, format matrix, roadmap/next-iteration обновлены.

## Выполненные проверки

- `npm run check` PASS: Go vet/race all packages, API generated drift, Svelte0 errors/warnings, Vite build. Existing VLESS/Xray preflight regressions проходят после расширения private identity.
- `npm run build` PASS: frontend и шесть Go binaries.
- Go parser tests PASS: все fields, optional variants/LF/CRLF, no mutation/redacted JSON/String, duplicate/case/sections, management/hooks/unknown fields, malformed/range/boundary/CPS bounds. Синтетические ключи создаются в памяти, plaintext fixtures не сохранены.
- Go store/race PASS: read-only AWG dry-run без ciphertext, owner/protocol mismatch, audit rollback, exact replay vs different newline conflict, rotation byte-exact, old key rejection, pending gate. Два DB handles и clamped equivalent key: ровно один successful import и один credential conflict.
- CLI tests для VLESS/AWG PASS: default dry-run/apply/replay/private file/error codes/target selection, sanitized reports и ready:false/peers_verified:false.
- Fuzz `FuzzAWG31DoesNotAlterInput`5s/2 workers PASS:197073 executions, без сбоя/неожиданной ошибки/изменения входа.
- `npm run test:persistence` PASS: separate CLI processes/state/repeat init/ownership/revision/HTTP boundary. Первый запуск до окончания build получил ENOENT vpnctl; после завершения build финальный прогон PASS.
- `npm run test:intents` PASS: admission/replay/conflicts/cancel/pages, unavailable-agent durable retries/process restart/SIGTERM; no runtime applied.
- `npm --prefix web run test:e2e:auth -- --list` PASS:12 discovered desktop/mobile scenarios, включая два новых AWG scenarios. Это только discovery/transpilation, не browser execution.

## Невыполненные проверки

- Chromium `--version` завершается139/SIGSEGV до приложения. E2E execution и новые screenshots не выполнены. UI source не менялся; прошлые screenshots в архиве — история, не новая приёмка.
- `TestPeerUIDAndStrictSocketBody` и `TestSocketApplyLostResponseThenReconcile` SKIP:AF_UNIX EPERM. Native acceptance `FVPN_REQUIRE_UNIX=1` обязательна на разрешённом Linux стенде.
- Native AWG3.1 app/core importer, round-trip, реальный peer/address allocation, handshakes и сеть/утечки не проверены. Go encryption round-trip не заменяет VPN client round-trip.

## Бэклог и поставка

M1-01 локально Done; DEV-08 и PRE-04 In progress по полной приёмке. G1 открыт. Main63:45 Backlog/15 In progress/3 Verification/0 Done; GW8Backlog. Следующий M1-02 — independent current runtime/client evidence, затем M1-03 download/QR. Runtime state/keys/TLS/executables/dependencies/test artifacts не включаются в source archive; исходные требования и история01–13 сохранены.
