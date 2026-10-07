# Family VPN · карточки M1 для Linear · v0.23.0

05.10.2026. **Синхронизировано в Linear напрямую через подключённый плагин.** Проект [Впн](https://linear.app/kukin/project/vpn-d7991a20e59b), workspace/team «Кукин». Найдены существующие KUK-5…8: они обновлены с сохранением ID, исходных acceptance criteria, labels и priority. Созданы только отсутствовавшие KUK-18 и KUK-19. M1-03 остаётся двумя существующими карточками: download и QR. Исполнители не назначены.

Linear хранит текущие статусы milestone/task; этот файл — снимок синхронизации. Original63 PRE/DEV/NET/QA/ROL criteria не заменены этими локальными срезами. G1 открыт; Done KUK-18 относится только к локальному importer subset.

| Срез | Карточка Linear | Статус | Blocked by |
|---|---|---|---|
| M1-01 · Импорт (локальный срез) | [KUK-18](https://linear.app/kukin/issue/KUK-18/dev-08-m1-01-client-export-importer-lokalnyj-srez) | Done | — |
| M1-02 · Подтверждение доступа | [KUK-5](https://linear.app/kukin/issue/KUK-5/dev-08-m1-02-confirm-installed-access-flow-end-to-end) | In Progress | — |
| M1-03 · Download | [KUK-6](https://linear.app/kukin/issue/KUK-6/dev-09-m1-03-deliver-downloadable-client-config) | Backlog | KUK-5 |
| M1-03 · QR | [KUK-7](https://linear.app/kukin/issue/KUK-7/dev-09-m1-03-generate-and-verify-qr-delivery) | Backlog | KUK-6, KUK-5 |
| M1-04 · Полный путь кабинета | [KUK-19](https://linear.app/kukin/issue/KUK-19/dev-11-m1-04-full-desktopmobile-portal-path) | In Progress | KUK-6, KUK-7 |
| M1-05 · G1 | [KUK-8](https://linear.app/kukin/issue/KUK-8/qa-01-qa-03-m1-05-g1-acceptance-unixbrowser-and-real-clients) | Backlog | KUK-19, KUK-5, KUK-7, KUK-6 |

Обновлены description проекта и M1 milestone; baseline этой поставки v0.23.0. При исходной синхронизации проверены статусы, membership и зависимости всех шести M1 карточек. После поставки v0.16 повторно прочитаны KUK-5 и проект: baseline v0.16, snapshot1.11, KUK-5 In Progress, четыре native/runtime/client/transition пункта открыты; связи блокировок сохранены. Новых M2/M3 mutations, assignees, рассылок или deployment действий не было. Фактические AWG/native/client и browser/Unix критерии открыты. Верификация native read contract в v0.15 использовала injected reader.

## M1-01 · Импорт клиентских AWG/REALITY профилей

Клиентский private export поступает в trusted CLI, проверяется и сохраняется exact bytes в зашифрованный pending profile. Выполнены VLESS subset и AWG3.1 .conf allowlist, ownership/generation/revision, read-only dry-run, explicit apply, replay/conflicts, UUID/derived AWG public key uniqueness и atomic rotation. Доказательство: iteration-07/08/09/14; check/build/persistence/race PASS. Локальный срез завершён; не закрывать полные PRE-04/DEV-08 и не обещать native app compatibility.

## M1-02 · Подтверждение установленного доступа

Импортированный профиль должен соответствовать actual current runtime и пройти pinned client round-trip до готовности к выдаче. v0.15 добавляет AWG observer/metadata ledger, v0.16 — keyless current-target/TTL/source readiness diagnostics; полного readiness transition пока нет.

- [x] AWG bounded parser: selected derived peer key, server key, inventory endpoint/port, PSK/shared parameters, exact host addresses и overlaps.
- [x] Read-only native adapter написан: fixed independently pinned root-owned tool, bounded timeout/output, два одинаковых readbacks, safe errors. Тест контракта с injected reader.
- [x] Immutable scoped TTL60s result, atomic metadata+audit/replay, stale/foreign/bytes/revision rejection; pending/download gate сохранён.
- [x] Explicit portal5→6 migration с сохранением ciphertext и current binding; Go vet/race/check/build/persistence/intents/fuzz PASS.
- [x] v0.16: keyless read-only readiness report, latest conflict/TTL/source/binding blockers, no flag bypass или secret/client/ready permission.
- [ ] Native positive/negative acceptance на согласованном Linux AWG3.1 stand с manifest tool/core/kernel/interface/endpoint; исследовать actual showconf field compatibility.
- [ ] Независимый актуальный Xray runtime source/revision; existing config snapshot не считать runtime success.
- [ ] Pinned versions/export-import round-trip и работающий клиент для каждого принимаемого app/format; handshake/DNS/routing/network checks в разрешённом scope.
- [ ] Отдельный audited readiness transition с current binding и fencing; тесты drift/stale/revoked/foreign failures.

Критерий завершения: фактические доказательства runtime и клиента, привязка owner/device/generation, отсутствие secret leakage, безопасные отрицательные сценарии. `peer_matches`, snapshot, fake apply и checkbox не закрывают приёмку. Доказательства: iteration-15, ADR-0013, profile-observation-runbook; native/client пункты открыты.

## M1-03 · Выдача профиля владельцу и QR

После M1-02 реализовать download только authenticated owner для ready/current generation; pending/чужой/отозванный не выдаётся. No-store/no-referrer, локальный QR и fallback, без внешних QR сервисов. Критерий: exact export импортируется в подтверждённый клиент; IDOR/cache/revocation negatives проходят. Пока Backlog локального среза, DEV-09 по полной задаче остаётся In progress из-за прежнего demo/pending UI.

## M1-04 · Полный путь кабинета

Работают приглашение/login/recovery, request/rename/cancel, admin read views и versioned guides/offline HTML. Добавить delivery/result UX и verified client guide. Критерий: desktop/mobile invitation→device→import/evidence→download/QR→client→guide, корректные ошибки/пустые состояния, нет overflow. Auth extras Deferred по решению владельца. Реальный полный browser/client путь ещё не выполнен.

## M1-05 · Приёмка G1

На согласованном стенде принять management/TLS inputs и полный M1; проверить ownership/secret negatives, недоступный кабинет при продолжающемся установленном VPN, mobile UX. Сохранить original NET/QA criteria и записать auth exclusions владельца. G1 открытый; стенд/клиенты не заменяются Go или fake success. Production pilot и полный GW/NET/ROL backlog — отдельные gates.

## Правила дальнейшей синхронизации

Прочитать actual workspace/project/issues и workflow. Отобразить локальные статусы на реальные статусы команды; если нет Verification, сохранить смысл в описании и выбрать ближайший статус только после чтения. Доказательства можно прикрепить как несекретные отчёты/ссылки на проверенную поставку; sandbox path не считать доступной другим участникам ссылкой. Parent63 сохраняют45 Backlog/15 In progress/3 Verification/0 Done; эти пять M1 slices не заменяют их критерии. После каждой поставки обновлять текущие карточки Linear и сохранять настоящий issue URL/ID и результат sync. Этот снимок содержит проверенные записи от 05.10.2026.

## Поставка v0.16

KUK-5 In Progress: локальный diagnostic slice реализован и отмечен в существующей карточке. CLI report всегда blocked/nonzero и не выдаёт профиль; native/client/transition checklist остаётся открытым. Check (Go vet/race, API drift, Svelte), build, persistence и intents PASS; два Unix socket tests SKIP из-за запрета AF_UNIX, новый browser E2E не запускался, UI/API не изменены. Description проекта и M1 milestone обновлены и прочитаны обратно. Source/runbook/tests — iteration-16.md и profile-readiness-runbook.md. Original parent63 criteria сохранены.

## Поставка v0.17

В существующей KUK-5 закрыт только local comparator correctness slice: selected peer AdvancedSecurity off/missing и symmetric boolean omission conflicts; bounded hex FwMark readback, без расширения client management importer; общий vocabulary18 и полный17-field conflict round-trip через observation/audit/readiness. Check/build/persistence/intents PASS, snapshot fuzz10s/50 368 executions PASS; два Unix tests SKIP, UI/API без изменений и новый browser E2E не запускался.

KUK-5, description проекта и M1 milestone обновлены, прочитаны обратно: baseline v0.17, canonical snapshot1.12, KUK-5 In Progress, исходные acceptance и четыре native/runtime/client/transition пункта сохранены открытыми; прежние block relations KUK-6/7/8 сохранены. Все шесть M1 statuses/membership прочитаны из проекта: KUK-18 Done local-only; KUK-19 In Progress; KUK-6/7/8 Backlog. Новых issues/assignees/M2/M3 mutations нет.

Source-format research закреплено по upstream commit/hash в awg-showconf-contract.md. Inspected go UAPI не сообщает per-peer security flag: не подставлять missing=on, нужен verified core-specific evidence contract. Old ledger metadata не разрешает выдачу; после upgrade нужна новая actual observation. Native/core/client/runtime и audited readiness transition остаются KUK-5 acceptance. Original63 criteria/statuses45/15/3/0 и GW8Backlog сохранены, G1 открыт. Report/runbooks/source доставлены владельцу в архиве чата; sandbox paths не являются ссылками для других участников Linear.

## Локальный срез v0.18 · KUK-5

Trusted AWG readiness preparation: AEAD/AAD/format/uniqueness/current binding/exact bytes/immutable observation TTL guards. Opaque candidate с safe copied report; diagnostic JSON не восстанавливает его. Writer-fenced recheck повторяет guards и откатывается; fence освобождён при возврате. Не lease/permission/audited transition. Snapshot/conflict/ledger-only evidence не разрешают ready; actual client proof отсутствует.

Negative regression: rename/revision, generation, disabled/revoked, installed_revision, AEAD corruption, changed valid bytes, invalid field, duplicate credential, rotation/old-key rejection, foreign binding, ledger-only fake runtime. Два DB handles: recheck ждёт чужой writer commit и отвергает новую ревизию. Profiles pending; ключ и методы не добавлены в CLI/HTTP. Схемы6/4/1, UI/API unchanged. Original63 criteria/statuses45/15/3/0 и GW8Backlog сохранены в snapshot1.13.

Проверки v0.18: check (Go vet/race, API drift, Svelte0), build(frontend +6 binaries), persistence/intents PASS. Два native Unix tests подтверждённо SKIP/AF_UNIX. UI/API source unchanged; новый browser E2E не запускался; native/core/client positive acceptance не выполнялась.

Sync receipt v0.18: существующая KUK-5, project baseline и M1 milestone обновлены в Linear и прочитаны обратно. KUK-5 In Progress; четыре native/Xray/client/transition пункта unchecked и block relations KUK-6/7/8 сохранены. Snapshot1.13, оригинальные criteria/assignees не менялись.

## Локальный срез v0.19 · KUK-5

Partial Xray named-users observer/CLI: fixed pinned executable, numeric loopback API/tag, closed parser64KiB/users256, normalized double read, immutable current binding/exact bytes/API target/TTL60s. Repeat key/AEAD/format/uniqueness/current state/revision/bytes after API reads, DB read-only. No ledger/audit/state writes, blocked/exit1; snapshot/JSON/partial result не full readiness. Enumeration/CoreIdentity/Revision/Transport/Clients/Ready false. Source pin7da5dae6502b787fc6d903863e9a6c5043d107a2 не native binary/core acceptance.

UUID wire aliases bytes6/7 резервируются консервативно; исходный UUID/export unchanged. Snapshot/users readback reject duplicate wire identity; alias не exact match. GetAll email map пропускает unnamed users: unobserved не отсутствие/revoke. KUK-5 In Progress, четыре acceptance пункта unchecked; схемы6/4/1, UI/API unchanged, snapshot1.14 сохраняет original63 criteria/statuses45/15/3/0 и GW8Backlog. Нет VPS/deploy/assignee/messages действий.

Проверки v0.19: check (Go vet/race, API drift, Svelte0), build(frontend+6 binaries), persistence/intents PASS; users fuzz10s/124421 PASS. Two Unix tests SKIP/AF_UNIX; UI/API/tests22 unchanged, no new browser E2E. Injected reader и source inspection не native binary/API/core/client acceptance.

Sync receipt v0.19: KUK-5/project baseline/M1 milestone обновлены в Linear и прочитаны обратно. KUK-5 In Progress, четыре full acceptance пункта unchecked; original acceptance/relations и IDs сохранены, snapshot1.14. Native/core/client acceptance не закрыта partial users observer.

## Локальный срез v0.20 · KUK-5

v0.20: оба Linux observer ограничивают также ожидание inherited stdout/stderr: отдельная process group, SIGKILL при отмене, WaitDelay200ms и cleanup после раннего parent exit. Неполный/ошибочный readback очищается и не становится proof. Local helper-process regression tests не являются AWG/Xray native acceptance. Fixed descriptor/pin/args, pending gate, schemas6/4/1 и UI/API сохраняются. ADR-0018, iteration-20.

Проверки v0.20: check (Go vet/race, API drift, Svelte0), build(frontend +6 binaries), persistence/intents PASS; local helper subprocess regression/race PASS. Two Unix tests SKIP/AF_UNIX; UI/API/tests22 unchanged. Sync receipt: KUK-5/project/M1 обновлены в Linear и прочитаны обратно, baseline20/snapshot1.15. Original Acceptance/relations/IDs, четыре unchecked пункта и In Progress сохранены. Native/core/API/client/transition acceptance остаётся открытой.

## Локальный срез v0.21 · KUK-5

v0.21: immutable AWG runtime target связывает interface/endpoint/tool pin/current boot ID/netns device+inode с profile/exact bytes/revision/TTL. Observe сверяет fixed proc environment на locked OS thread до/между/после readbacks; storage/prepare/fenced recheck требуют independently expected target. Snapshot/JSON не превращаются в native scope. Ledger target не хранит; keyless runtime_target_verified:false и обязательный blocker. Local contracts/proc negative tests не закрывают native/core/client/transition acceptance. ADR-0019, iteration-21; схемы6/4/1 без миграции.

Проверки v0.21: check (Go vet/race, API drift, Svelte0), build(frontend +6 binaries), persistence/intents PASS. Target/environment/reader/storage/CLI regression и local read-only proc/native wrong-namespace rejection PASS. Two Unix tests SKIP/AF_UNIX; UI/API/tests22 unchanged. Sync receipt: KUK-5/project/M1 обновлены в Linear и прочитаны обратно, baseline21/snapshot1.16. Original Acceptance/relations/IDs, четыре unchecked пункта и In Progress сохранены. Native/core/client/transition acceptance остаётся открытой.

## Локальный срез v0.22 · KUK-5

v0.22: partial Xray users Result теперь связывает independently expected boot ID/netns device+inode с API server/tag/tool pin/current profile/revision/exact bytes/TTL. Observe сверяет fixed proc environment на locked OS thread перед/между/после двух readbacks. Общий internal/runtimeenv используется AWG и Xray; AWG scope/guards сохранены. ExecutionScopeBound относится только к области исходного выполнения; Enumeration/CoreIdentity/Revision/Transport/Clients/Ready остаются false. Snapshot/JSON не приобретают native scope; storage read-only, blocked/exit1, profiles pending. Native/core/client/transition acceptance открыта; схемы6/4/1 без миграции. ADR-0020, iteration-22.

Проверки v0.22: check (Go vet/race, API drift, Svelte0), build(frontend +6 binaries), persistence/intents PASS. Scope/reader/rebinding/cancellation/redaction/CLI/store no-mutation regressions PASS; actual local read-only proc и native entry wrong-namespace rejection PASS. Two Unix tests SKIP/AF_UNIX; UI/API/tests22 byte-identical. Sync receipt: existing KUK-5/project/M1 обновлены в Linear и прочитаны обратно, baseline22/snapshot1.17. Original Acceptance/relations/IDs, четыре unchecked пункта и In Progress сохранены. Native/core/client/transition acceptance остаётся открытой.

## Локальный срез v0.23 · KUK-5

v0.23: Xray Observe требует exact-byte independently expected InventorySHA256 для fixed protected /etc/family-vpn/xray-inventory.json. Closed version1 JSON содержит expected boot/netns/kernel release и до16 API/tag/tool/core/config revision expectations. Linux descriptor walk проверяет root ownership/permissions/no symlink/hardlink/special files/64KiB bounds и metadata до/после чтения. CLI проверяет manifest до key/DB; observer повторяет inventory перед/между/после reads. Immutable Result/Check/store target связывает inventory pin; inventory_bound относится к исходному выполнению. Declared core/version/config/kernel metadata не observed core attestation: full Xray acceptance flags false, blocked/exit1, read-only/no ledger/state/audit writes. AWG contract и схемы6/4/1 сохранены; native/core/client/transition acceptance открыта. ADR-0021, xray-inventory-runbook, iteration-23.

Проверки v0.23: check (Go vet/race, API drift, Svelte0), build(frontend +6 binaries), persistence/intents PASS. Inventory fuzz target5s/15965 executions PASS. Actual temporary-file descriptor/permission/link/FIFO/bounds/replacement/mutation/cancellation tests PASS; foreign owner policy проверена synthetic stat, chown to unmapped UID запрещён текущей средой, actual foreign-UID filesystem acceptance отдельно. Two Unix tests SKIP/AF_UNIX; UI/API/tests22 byte-identical. Sync receipt: existing KUK-5/project/M1 обновлены и read back, baseline23/snapshot1.18. Original Acceptance/relations/IDs, четыре unchecked пункта и In Progress сохранены; M2/M3 unchanged. Native/core/client/transition acceptance открыта.
