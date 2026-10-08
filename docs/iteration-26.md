# Итерация26 · v0.26.0 · 08.10.2026

## Pinned cores и Foreign operator toolset

По запросу владельца добавлена практическая подготовка VPN-ядер для двух Ubuntu20.04/~1GiB. Установка выполняется оператором из CLI, до network activation. Локальная задача к VPS не подключалась, firewall/routes/SSH/systemd не меняла, приложение не публиковала.

`core-plan --role ru|foreign`, `core-install --core xray|sing-box|hysteria`, `core-status [--core ...]`: closed embedded Linux amd64/arm64 catalogue Xray26.3.27, sing-box1.14.2 musl, Hysteria2.13.0. Default install dry-run не скачивает/пишет; apply Linux root-only. TLS redirects только official GitHub/CDN, environment proxy не используется, download/extraction потоковые с timeout/size/SHA pins. Exact archive member set, link/traversal/duplicate/PAX/bomb bounds и binary SHA/static ELF проверяются независимо. Protected descriptor walk `/usr/bin`, staged0600→root0755, fsync/RENAME_NOREPLACE, идемпотентный same pin, чужой existing file не перезаписывается. Ни одно ядро не исполняется установщиком; нет service/config/network/DB/readiness changes. AWG install blocked: upstream Ubuntu22.04 artifact не принят для20.04, go binaries отсутствуют, selected AdvancedSecurity readback contract остаётся открытым.

`foreign-init` принимает независимо выбранные public literal endpoint/RU source/REALITY target и hostname, default pure dry-run. Apply генерирует UUID/X25519/short ID в private fixed `/etc/family-vpn/foreign-staging`: Xray server config и sing-box RU outbound fragment, files0600/dir0700. Atomic new directory publication/no-overwrite, bounded protected reads, exact canonical pair regeneration и private/public matching, unknown/duplicate/case-alias/depth/input/policy-expansion checks. Bundle serialization/formatting redacted; reports/errors не содержат credentials/IP/SNI/config/path. Это не user export и не pairing descriptor; portal/control/admin DB и HTTP не подключаются к staging.

Xray default blackhole, explicit one-RU primary source/inbound rule, bounded public DNS route, deny private/special/metadata/management destinations обоих VPS. ForceIP/domain routing не kernel guard. В pinned26.3.27 finalRules отсутствует, не генерируется. `foreign-check --native-check` допускает только fixed protected exact pinned core descriptor и config descriptor, clean environment, fixed run-test/JSON args, timeout/process group cancellation и discarded output. Это только parser check; runtime/kernel/routing/DNS/client/ready false. Hysteria binary можно установить, backup TLS config/runtime ещё нет. Root wrapper `scripts/bootstrap-foreign.sh [--apply]` валидирует четыре несекретных ввода до установки, затем готовит primary pair/check; никаких сервисов/сети. Включён в runtime bundle вместе с runbook.

Actual pinned Windows Xray config-only invocation выявила ошибку mapped IPv6 CIDR `/96`: Xray canonicalizes его в IPv4 и отклоняет prefix>32. Routing representation исправлена, mapped inputs по-прежнему запрещены и private IPv4 policy сохранена. После исправления generated IPv4/IPv6 configs проходят parser. Independent review выявил неправильное ожидание EOF у Readdirnames: positive pair readback исправлен и покрыт Linux root temp-directory regression. Concurrent same-pin install metadata исправлена. Нерешённых actionable review findings не найдено; это не native network acceptance.

## Проверки и ограничения

На текущем Windows: Node24.21.0/npm11.19.0, pinned Go1.27.1. SDK/cache/tools только ignored build; private generated check files удалены, в архивы не входят.

- Targeted common/CLI tests PASS14 top-level плюс существенные subtests: closed catalogue, member/hash/ELF/download/redirect bounds, cancellation/no-proxy, dry-run/argument redaction, public/private/family/IP/SNI boundaries, crypto freshness/pair mix, policy expansion/duplicate/unknown/depth/redaction. Linux root tests не выполнялись на Windows.
- Negative-only parser fuzz PASS30 780 executions; seeds не содержат generated credentials. Final family boundary/fuzz seed tests и built CLI core-plan/foreign-init dry-run smoke PASS. Ни один dry-run не скачивает, не генерирует secrets и не открывает DB.
- Дополнительный opt-in `FVPN_VERIFY_CORE_ASSETS=1` PASS6/6: настоящие официальные Linux archives/raw bytes скачаны и проверены собственными Go download→extract→binary SHA→static ELF функциями. Ядра не запускались; обычные unit tests offline.
- Pinned Windows Xray26.3.27 `run -test` PASS2/2, с generated IPv4/IPv6 server config в private temporary scope; никаких listeners. Не подтверждает Linux runtime, RU sing-box fragment native acceptance или TLS transport/client.
- npm run build PASS: Svelte0 errors/warnings, Vite119 modules, six Go executables. Generated API drift PASS; API/schema/UI/auth flows не менялись, browser E2E не повторялись.
- Windows Go vet PASS; Linux amd64 CGO0 cross-vet ./... и test binary compile обоих новых packages PASS. Это static/cross-build, не Linux execution.
- npm run test:release PASS8/8. Bash wrapper syntax `bash -n` PASS; Linux operator wrapper не исполнялся.
- npm run check NOT PASS: CGO1/race остановился на отсутствии `gcc`. Полный Linux check/race и auth/admin/import/browser regressions остаются обязательными. Ограничения v0.24 Windows key ownership не ослаблялись.
- CI дополнен Linux root synthetic installer/stage filesystem tests в temp dirs; не устанавливает cores/system paths, не запускает VPN. CI/source версии v0.26 на remote не опубликованы и не исполнялись.

Linux amd64/arm64 runtime bundles cross-built, архивы независимо проверены по ELF arch/modes/closed contents/internal+external SHA/false acceptance. Source archive имеет allowlisted source manifest; private keys/configs/DB/core downloads/cache/SDK отсутствуют. Native Ubuntu kernel/root paths/memory/service restart, namespace/firewall/isolation/IPv6/DNS/fail-closed и Android round-trip не выполнены. Комплект не production/pilot RC и не принимается как M1/G1.

## Реестр и следующий шаг

Canonical snapshot1.21: PRE-05 In progress за частичные owner inputs/core pins/tools. Исходные63 work/dependencies/acceptance сохранены byte-for-byte; статусы44 Backlog/16 In progress/3 Verification/0 Done. GW8Backlog, auth extras Deferred, schemas6/4/1 unchanged. Linear/remote Git/CI v0.26 не обновлены. M1-02/03/05, KUK-5/6/7 и G1 открыты. Runbook vpn-bootstrap-runbook.md, ADR-0023, roadmap/milestone/next-iteration обновлены.

Далее: actual Linux root/race regression и approved inventory/recovery inputs; проверенный kernel guard/vpn-data netns, RU ingress/TUN/selector и TLS backup; pinned Android import/handshake/DNS/TCP/UDP/Foreign-loss/resource/restart acceptance. AWG compatible build/security observer contract отдельно. Actual client/runtime proof и все guards нужны в одной audited writer transaction до ready/download; install/config-only check не повышают состояние. M2 profile automation после M1.
