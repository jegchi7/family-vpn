# Итерация20 · v0.20.0 · 05.10.2026

## KUK-5 / M1-02 / DEV-08

Устранено неограниченное ожидание stdout/stderr у AWG/Xray observer: прежний CommandContext мог завершить непосредственный процесс, но оставшийся потомок удерживал pipe, блокируя Run. Общий internal observerexec runner запускает уже проверенный descriptor в отдельной группе, сохраняет timeout4s и ограничивает pipe wait через WaitDelay200ms. Cancellation завершает группу; ранний parent exit с retained pipe завершается ошибкой и cleanup. Native adapters очищают partial output и возвращают прежний safe ErrRuntime. Fixed tool ownership/hash pin/commands/args/output bounds, immutable binding/exact bytes/TTL и pending gate сохранены. ADR-0018 описывает границы: это не sandbox для hostile executable и не real-time guarantee.

## Проверки

`npm run check` PASS: Go vet/race всех packages, API generation без drift, Svelte0 errors/warnings и Vite. `npm run build` PASS: frontend +6 Go binaries. `npm run test:persistence` и `npm run test:intents` PASS. Targeted observerexec/profileobserve/xrayobserve race tests PASS. Gofmt clean.

Новые regression tests выполняют реальные локальные helper subprocess: успешный parent exit с удерживаемым stdout, отмена работающей группы с потомком, descriptor success/nonzero exit/cancelled start. Проверено ограниченное завершение и остановка descendant; zombie допускается как остановленный процесс до init reaping. Test shell используется только как helper; production tool path/args не расширены. Tests не запускают actual AWG/Xray tools/core/API/clients. Existing parser/output-limit/secret-redaction tests входят в общий check; fuzz не повторялся, parser не менялся.

Два native Unix tests TestPeerUIDAndStrictSocketBody/TestSocketApplyLostResponseThenReconcile подтверждённо SKIP/AF_UNIX restriction. Native acceptance с FVPN_REQUIRE_UNIX=1 отдельно. UI/API/tests22 byte-identical к v0.19, новый browser E2E не запускался. Original63 work/dependencies/acceptance автоматически сравнены без изменений; statuses45 Backlog/15 In progress/3 Verification/0 Done, GW8Backlog. Схемы6/4/1, Go dependencies unchanged.

## Статусы и синхронизация

KUK-5 In Progress. Четыре native AWG/Xray/client/audited transition acceptance пункта открыты; full runtime/core identity/revision/REALITY transport/client acceptance не выполнена. KUK-6/7 download/QR заблокированы; KUK-19 In Progress, KUK-8 G1 Backlog. Профили pending, выдача заблокирована. Source archive не содержит dependencies/build/state/secrets/research sources.

Sync receipt v0.20: существующая KUK-5/project baseline/M1 milestone обновлены и прочитаны обратно. Baseline v0.20.0/snapshot1.15; исходный Acceptance, четыре unchecked пункта, relations и IDs сохранены. Нет assignee/дубликатов/M2/M3 mutations/messages/VPS/network config/deploy/GitHub remote CI. Primary Go contract URLs находятся в ADR-0018.
