# Итерация 29 · v0.29.0 · 09.10.2026

## Forwarding0 и Foreign Docker/Amnezia

По запросу владельца продолжена локальная реализация двух сетевых границ после v0.28: RU host forwarding0 и Foreign с действующим Docker/Amnezia UDP30759. Исходное состояние сообщено владельцем; это не independently observed acceptance из этой задачи. К VPS задача не подключалась, firewall/routes/SSH/Docker/services не меняла. Публичный кабинет, Linear и GitHub не публиковались и не изменялись.

`internal/netstand/forwarding*` снимает полный закрытый IPv4 devconf и NIC feature subset из текущего expected host scope. Baseline остаётся opaque trusted memory; procfs file/ancestor FD удерживаются до окончания процедуры. Unknown/missing keys, mixed non-loopback forwarding, requested/active LRO, pending mutable feature changes, неподдержанный GET/layout/driver или identity drift запрещают writes. Прямой одиночный sysctl и восстановление из JSON/journal не допускаются.

После независимого host+namespace guard выполняется одна fenced группа forwarding0→1. Global/all.forwarding, uplink и owned veth намеренно становятся1; default.forwarding/all.accept_redirects/forwarding остальных исходных интерфейсов восстанавливаются из актуальной памяти. Все остальные reviewed devconf/feature значения должны совпасть; каждая запись окружена точным readback, guard проверяется перед writes и после группы. Router semantics uplink меняются; сохранение реального SSH/кабинета требует отдельной native management проверки. Fixed GET ioctl имеет bounded buffers/context/scope checks, но generic driver callbacks и отсутствие hard kernel cancellation честно остаются ограничением.

`internal/netguard/docker*` вводит Foreign-only closed bridge NAT subset по actual interface kind/address/route inventories: private docker0/amn0 disjoint от transit; positive source MASQUERADE/SNAT и LOCAL-reachable UDP30759 DNAT. Названия Docker/Amnezia не являются attestation. RU whole-ruleset запрет сохраняется. Unknown rewrite/CT/marks/queue/offload, opaque nft xt и IPv6 NAT остаются blocked; actual Foreign backend ещё не принят.

Два exact leading shared `filter/FORWARD` ACCEPT ограничены owned veth и ставятся после обоих owned nft guards, пока оба veth DOWN. Остальные entries/order/policy не меняются. Перед первым UP и повторным check требуются точный head readback и unchanged semantic policy digest; независимый более поздний nft guard продолжает проверять original/current tuples и final drops. Fixed optional pinned legacy multicall читает обе семьи отдельно от nft; module autoload отключён, lock bounded. Docker API/socket не добавлены.

Network manifestformat2 хранит только safe source/expected fingerprints и closed supplement metadata. Stored hash не fresh observation, restoration command, ready или permission. Apply повторяет current inventory/pins/config/scope/baseline; неполный exclusive journal не replay-ится. Verify требует complete journal и fresh full readback, а не исторический success. Old network artifacts не autoupgrade; original RU/Foreign private core staging не переписывается. Public/admin HTTP, API generation и DB schemas6/4/1 unchanged.

Foreign GitHub bootstrap открывает `/dev/tty` read-only/unbuffered: non-seekable terminal не требует BufferedRandom seek. Ошибка отсутствующего terminal отделена от sanitized operator exec failure. Добавлен Linux controlling-PTY regression test с четырьмя non-secret вводами; он не запускает installers/network.

Runbook: [network-stand-runbook](network-stand-runbook.md), [ADR-0026](adr/0026-network-preservation.md), [VPN bootstrap](vpn-bootstrap-runbook.md).

## Проверки

Текущая среда Windows, Go1.27.1 и Node24.21.0. Linux runtime локально недоступен; Docker/WSL/service не запускались.

- Full `go test ./internal/netguard ./internal/netstand` и focused `cmd/vpnctl TestNetwork*` PASS. Meaningful tests проверяют exact owned head, semantic policy drift, NAT disjointness, module-only/unknown predicates, offload/LRO/identity/cancellation/write failures, manifest/phase boundaries и отсутствие readiness из stored metadata.
- Независимый review обоих срезов и интеграции: блокирующих дефектов после исправлений не обнаружено.
- `node --test scripts/release.test.mjs scripts/publish-release.test.mjs`: PASS20/20.
- Python bootstrap: PASS11, SKIP2 (Linux PTY/alarm); 13 total. Linux PTY из Windows не исполнен.
- `npm run check`: NOT PASS, `gcc` отсутствует для CGO/race; `build/check-v29-final.log`. Guards/ownership ради Windows не ослаблялись.
- Full Windows CGO0 regression: четыре известные platform-bound packages FAIL — cmd/vpnctl, adminauth, clientconfig, profilevault; причины private source/key ownership. Изменённые сетевые packages PASS; `build/go-regression-v29.log`. Это не успешный полный check.

- `npm run build`: PASS, frontend0 errors/0 warnings и все Windows binaries; `build/build-v29.log`.
- Full Windows CGO0 vet и Linux amd64/arm64 cross-vet: PASS. Linux binaries/test compilation не исполнялись; native packet acceptance не заявлена.
- API generation повторена: exact bytes unchanged; `build/api-generation-v29.log`.
- Demo desktop/mobile E2E через installed Chrome: PASS16/16; `build/e2e-v29.log`. Auth/admin suites v0.29 не исполнены: auth flow не менялся, Linux private-key acceptance остаётся отдельной проверкой.
- Linux amd64/arm64 runtime bundles собраны с CGO0/trimpath/buildvcs=false; оба содержат только closed release assets с checksum/manifest и false native/client/readiness flags. Source allowlist431 files + отдельный SOURCE-MANIFEST.sha256, secret/runtime state исключены. Независимая archive verification выполняется перед передачей; build/package-source-v29.py и build/verify-delivery-v29.py — локальные ignored tools, не production runtime.

## Статус требований и следующая граница

Canonical snapshot1.24: original63 IDs/criteria и252 normative fields сохраняются; 41 Backlog / 19 In progress / 3 Verification / 0 Done. NET-03/05 получили локальные subtask implementations; NET/QA, M1/G1 и KUK-5 не закрыты. Specification byte preservation и API/schema hashes проверяются перед упаковкой. Online Linear sync этой поставки не выполнялся.

Публичный v0.28 был опубликован владельцем, read-only GitHub сверка ранее подтвердила [checks run37836903063](https://github.com/jegchi7/family-vpn/actions/runs/37836903063) SUCCESS08.10 и prerelease v0.28. Это отдельные Linux CI результаты предыдущего source commit; они не доказывают v0.29 или packet/network acceptance Ubuntu20.04.

До первого полноценного подключения нужны native Ubuntu positive/negative packet/management/recovery tests, dedicated unprivileged core launcher с guard-before-start/restart/boot ordering, vault/current owner/device/profile/generation/revision bound issuance и actual Android import/REALITY/DNS/TCP/UDP/Foreign-loss/resource checks. AWG compatible/security readback и Hysteria backup/TLS остаются открыты. `native_acceptance`, `client_verified`, `ready` и profile delivery не включаются по текущей поставке.
