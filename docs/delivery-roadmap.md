# Итеративная цель владельца · 04.10.2026

Цель: довести обязательный backlog до принятой v1; выдавать самостоятельные проверенные архивы, поддерживать основной реестр и сохранять историю. Git/publish позже. Обязательные criteria исходной спецификации не сокращаются. WebAuthn/recovery codes/fresh auth остаются отложенными по прежнему решению владельца.

## Закрытые локальные подзадачи

| Поставка | Подзадача | Доказательство |
|---|---|---|
| v0.6 | DEV-06 request/rename/cancel/quota/ownership/revision | iteration-06 |
| v0.7 | DEV-07 encrypted profile vault/key lifecycle/atomic rekey | iteration-07 |
| v0.8 | DEV-08 trusted VLESS URI dry-run/apply/binding/conflicts | iteration-08 |
| v0.9 | DEV-08 pinned Xray configuration preflight без ready | iteration-09 |
| v0.10 | DEV-12/13 read-only admin users/device queue/safe audit | iteration-10 |
| v0.11 | DEV-10 versioned guides/portal scope/офлайн HTML | iteration-11 |
| v0.12 | DEV-14/15 strict contract/durable queue/fake observation, in-process crash/retry | iteration-12 (Unix transport acceptance pending) |
| v0.13 | DEV-15 foreground worker/durable backoff/queued cancel/safe CLI pages | iteration-13 (real runtime acceptance pending) |
| v0.14 | M1-01 AWG3.1 client-only importer/exact bytes/key uniqueness | iteration-14 (native/client compatibility pending) |
| v0.15 | M1-02 AWG readback contract/scoped metadata/audit/portal6 | iteration-15 (native positive/client/readiness pending) |
| v0.16 | KUK-5/M1-02 keyless readiness read model/current binding/TTL/blockers | iteration-16 (transition/native/client acceptance pending) |
| v0.19 | KUK-5/M1-02 partial Xray users/scoped read-only CLI/UUID wire aliases | iteration-19 (native core/revision/transport/client/transition pending) |
| v0.20 | KUK-5 bounded observer subprocess wait/process group cleanup | iteration-20 (native/core/client/transition acceptance still open) |
| v0.23 | KUK-5 protected Xray inventory/exact-byte pin/runtime binding | iteration-23 (responding core/client/transition acceptance open) |
| v0.24 | Review fixes, Linux stand bundle, TLS/frontend/stand diagnostics | iteration-24 (actual Linux/browser/native/client acceptance open) |
| v0.22 | KUK-5 Xray execution scope/shared AWG-Xray proc reader | iteration-22 (native/core/client/transition acceptance still open) |
| v0.21 | KUK-5 independently scoped AWG runtime target/boot/netns | iteration-21 (native/core/client/transition acceptance still open) |
| v0.18 | KUK-5/M1-02 trusted readiness preparation/writer-fenced recheck | iteration-18 (actual client/transition/native acceptance pending) |
| v0.17 | KUK-5/M1-02 AWG comparison security/modes/showconf hex format/full conflict metadata | iteration-17 (source contract checked; native/client/transition pending) |

Это отдельные завершённые части, не Done всех родительских задач. Snapshot match не является runtime evidence. Полный статус каждого PRE/DEV/NET/QA/ROL — в `vpn-platform-backlog-v1.0.md`.

## Последовательность следующих поставок

1. DEV-12/13 read-only часть завершена локально v0.10. Issuance остаётся trusted CLI; дальнейшие admin mutations идут после restricted intent boundary.
2. DEV-10 engine/offline завершены локально v0.11; actual client/format compatibility и catalogue installation links ждут PRE-04.
3. DEV-08/09: trusted runtime evidence + pinned core/client round-trip → owner download. Нельзя обойти эту зависимость checkbox.
4. DEV-14/15: restricted intents и serialized reconciler, revisions/idempotency/crash journal; сначала fake stand и trust tests, затем реальные adapters.
5. DEV-16…19/GW-01…08: AWG/Xray access adapters, pairing/pull/apply, rotation/revoke; неизвестные peers сохраняются, private hop material в control boundary.
6. DEV-20…23: authenticated foreign probe, TTL, failover/override и actionable UI. Только измеренные результаты; no DIRECT fallback.
7. DEV-25/26, NET/QA: recovery/backup/upgrade и полная приёмка. ROL: окна production, реальные пилотные устройства/операторы и наблюдение.

## Внешние входы для принятия

PRE-01/02/05 требуют actual inventory/recovery/deployment inputs. PRE-04/QA-07 требуют pinned AWG 3.1/Xray/sing-box, реальные iOS/Android/Windows клиенты и версии. NET/QA-02/04/05/09/10/11 требуют изолированный сетевой стенд и измерения. ROL требует отдельного operational scope/окна, пользователей и elapsed observation time. Локальная разработка продолжается по независимым задачам; отсутствие этих входов не заменяется fake success.

Текущий фокус M1/G1: milestone-m1.md. Current Linear карточки синхронизированы: KUK-5…8, KUK-18/19; mapping в linear-sync-plan.md.

v0.20: оба Linux observer ограничивают также ожидание inherited stdout/stderr: отдельная process group, SIGKILL при отмене, WaitDelay200ms и cleanup после раннего parent exit. Неполный/ошибочный readback очищается и не становится proof. Local helper-process regression tests не являются AWG/Xray native acceptance. Fixed descriptor/pin/args, pending gate, schemas6/4/1 и UI/API сохраняются. ADR-0018, iteration-20.

v0.21: immutable AWG runtime target связывает interface/endpoint/tool pin/current boot ID/netns device+inode с profile/exact bytes/revision/TTL. Observe сверяет fixed proc environment на locked OS thread до/между/после readbacks; storage/prepare/fenced recheck требуют independently expected target. Snapshot/JSON не превращаются в native scope. Ledger target не хранит; keyless runtime_target_verified:false и обязательный blocker. Local contracts/proc negative tests не закрывают native/core/client/transition acceptance. ADR-0019, iteration-21; схемы6/4/1 без миграции.

v0.22: partial Xray users Result теперь связывает independently expected boot ID/netns device+inode с API server/tag/tool pin/current profile/revision/exact bytes/TTL. Observe сверяет fixed proc environment на locked OS thread перед/между/после двух readbacks. Общий internal/runtimeenv используется AWG и Xray; AWG scope/guards сохранены. ExecutionScopeBound относится только к области исходного выполнения; Enumeration/CoreIdentity/Revision/Transport/Clients/Ready остаются false. Snapshot/JSON не приобретают native scope; storage read-only, blocked/exit1, profiles pending. Native/core/client/transition acceptance открыта; схемы6/4/1 без миграции. ADR-0020, iteration-22.

v0.23: Xray Observe требует exact-byte independently expected InventorySHA256 для fixed protected /etc/family-vpn/xray-inventory.json. Closed version1 JSON содержит expected boot/netns/kernel release и до16 API/tag/tool/core/config revision expectations. Linux descriptor walk проверяет root ownership/permissions/no symlink/hardlink/special files/64KiB bounds и metadata до/после чтения. CLI проверяет manifest до key/DB; observer повторяет inventory перед/между/после reads. Immutable Result/Check/store target связывает inventory pin; inventory_bound относится к исходному выполнению. Declared core/version/config/kernel metadata не observed core attestation: full Xray acceptance flags false, blocked/exit1, read-only/no ledger/state/audit writes. AWG contract и схемы6/4/1 сохранены; native/core/client/transition acceptance открыта. ADR-0021, xray-inventory-runbook, iteration-23.
