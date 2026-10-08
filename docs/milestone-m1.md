# Ближайший milestone M1/G1 · 05.10.2026

Цель владельца: закрывать пункты этого milestone небольшими проверенными поставками. Итоговый пользовательский путь: приглашение → вход → заявка устройства → ручной импорт и подтверждение доступа → скачивание/QR → импорт в VPN-клиент и подключение → инструкция/офлайн-памятка.

G1 остаётся открытым. Done ниже относится только к локальной подзадаче, не к полной карточке основного реестра. Пароль/TOTP сохраняются; WebAuthn, recovery codes и fresh auth остаются Deferred по решению владельца.

v0.24: review fixes и переносимый Linux стенд кабинета подготовлены, stand-check не выдаёт профили и не является runtime/client proof. Windows build/demo/user flows проверены частично; full Linux race/admin/import run и M1-02/03/05 остаются открыты. Перед параллельным использованием нужен согласованный Linux VPN стенд и реальные client inputs. Инструкция stand-runbook.md, отчёт iteration-24.md; canonical snapshot1.19, original criteria сохранены.

v0.25: владелец сообщил о рабочем входе в user/admin кабинеты на RU и двух серверах Ubuntu20.04/~1GiB с неподготовленным VPN; первый клиент Android. Это owner-reported smoke, не actual core/client/network acceptance. Добавлена read-only selected-peer AWG session диагностика: bounded handshake/counters, independently bound tool/boot/netns/exact bytes и повторные storage guards. Handshake не подтверждает import/DNS/Foreign routing и не открывает delivery. Runbook profile-awg-session-runbook.md; snapshot1.20, M1-02/03/05 открыты.

v0.26: по запросу владельца подготовлен operator bootstrap: pinned static Xray/sing-box/Hysteria installer и private Foreign primary REALITY pair с config-only check. Это инструменты подготовки до actual network stand, не автоматизация управления профилями M2. AWG install/native security contract, kernel netns/isolation, TLS backup и Android round-trip открыты. Snapshot1.21 сохраняет original63 criteria/statuses44/16/3/0; M1-02/03/05 и G1 не приняты. Runbook vpn-bootstrap-runbook.md, iteration-26.md.

| Срез | Родительские задачи | Статус | Критерий и доказательство |
|---|---|---|---|
| M1-01 · Client export importer | PRE-04, DEV-07/08 | Done локально, v0.14 | VLESS subset и AWG3.1 .conf, read-only dry-run, exact encrypted bytes, replay/conflicts/ownership/key rotation. iteration-08/09/14; native compatibility отдельно |
| M1-02 · Подтверждение установленного доступа | DEV-08, PRE-04 | In progress, v0.28 | Независимое чтение актуального runtime peer/core revision, привязка owner/device/generation, endpoint/address/параметры, явная версия клиента и round-trip. Session diagnostics, snapshot match и fake success не делают ready |
| M1-03 · Owner delivery | DEV-09 | Backlog локального среза | Только ready/current generation; owner auth, no-store/no-referrer; локальный QR и fallback без внешних сервисов; pending/чужой/отозванный профиль не выдаётся |
| M1-04 · Полный путь кабинета | DEV-10/11/12/13, QA-03 | Частично | Вход/устройства/admin views/guides готовы; добавить delivery/result UX, проверенный client guide; пройти desktop/mobile от приглашения до импорта |
| M1-05 · Приёмка G1 | DEV-01…13, NET-06, QA-01/03 | Открыт | Реальные management/TLS inputs, ownership/secret negative tests, недоступный кабинет не ломает установленный VPN, нет mobile overflow. Отложенные auth extras указаны как исключение владельца |

v0.15 реализовала локальный read-only AWG observer и scoped immutable metadata ledger, portal6. Проверены parser/read contract/TTL/ownership/revision/audit/migration; native positive execution и client round-trip ещё не выполнены. Следующая поставка продолжает M1-02: фактическая runtime/client acceptance, Xray runtime source и отдельный readiness contract. Эта работа не запускает изменение сети и не требует возвращения к автоматическим mutations M2.

Для фактического принятия M1-02/05 нужны версии и параметры работающих шлюзов/клиентов и разрешённый сетевой стенд. В текущей поставке серверы не обследованы, нативные VPN-клиенты не запущены. Отсутствие этих входов не заменяется checkbox или manually forced ready. M1 не включает завершение всей GW/NET/ROL очереди; полный v1 остаётся последующей целью.

Известные ограничения среды: AF_UNIX EPERM, Chromium startup SIGSEGV. Go/in-process/CLI checks могут завершаться локально; browser/native transport acceptance отдельно. Основные статусы — vpn-platform-backlog-v1.0.md; следующая поставка — next-iteration.md.

Current Linear mapping: `linear-sync-plan.md`; KUK-5…8 обновлены, KUK-18/19 созданы. KUK-5 In Progress. v0.16 добавляет keyless read-only current-target/TTL/source diagnostics и blockers; эта локальная часть не является audited readiness transition или native/client acceptance.

v0.17 продолжает KUK-5: исправлены selected peer security, omitted boolean и hex FwMark readback; полный17-field conflict проходит ledger/readiness без secret leakage и разрешения выдачи. Local comparator verification не принимает native core или клиентов. Недоступное AdvancedSecurity metadata блокирует этот subset до согласования core-specific observer contract.

v0.18: trusted readiness preparation/recheck с повторными AEAD/format/uniqueness/current binding/bytes/TTL guards и writer rollback проверены локально. Это не audited transition, lease или client attestation; четыре KUK-5 acceptance пункта остаются открыты.

v0.19: partial Xray users readback/CLI и UUID wire-alias uniqueness реализованы локально. Core identity/revision/transport/client acceptance не подтверждены, enumeration неполна, output blocked/exit1. Native Xray пункт KUK-5 целиком остаётся открытым; source contract не native acceptance.

v0.20: оба Linux observer ограничивают также ожидание inherited stdout/stderr: отдельная process group, SIGKILL при отмене, WaitDelay200ms и cleanup после раннего parent exit. Неполный/ошибочный readback очищается и не становится proof. Local helper-process regression tests не являются AWG/Xray native acceptance. Fixed descriptor/pin/args, pending gate, schemas6/4/1 и UI/API сохраняются. ADR-0018, iteration-20.

v0.21: immutable AWG runtime target связывает interface/endpoint/tool pin/current boot ID/netns device+inode с profile/exact bytes/revision/TTL. Observe сверяет fixed proc environment на locked OS thread до/между/после readbacks; storage/prepare/fenced recheck требуют independently expected target. Snapshot/JSON не превращаются в native scope. Ledger target не хранит; keyless runtime_target_verified:false и обязательный blocker. Local contracts/proc negative tests не закрывают native/core/client/transition acceptance. ADR-0019, iteration-21; схемы6/4/1 без миграции.

v0.22: partial Xray users Result теперь связывает independently expected boot ID/netns device+inode с API server/tag/tool pin/current profile/revision/exact bytes/TTL. Observe сверяет fixed proc environment на locked OS thread перед/между/после двух readbacks. Общий internal/runtimeenv используется AWG и Xray; AWG scope/guards сохранены. ExecutionScopeBound относится только к области исходного выполнения; Enumeration/CoreIdentity/Revision/Transport/Clients/Ready остаются false. Snapshot/JSON не приобретают native scope; storage read-only, blocked/exit1, profiles pending. Native/core/client/transition acceptance открыта; схемы6/4/1 без миграции. ADR-0020, iteration-22.

v0.23: Xray Observe требует exact-byte independently expected InventorySHA256 для fixed protected /etc/family-vpn/xray-inventory.json. Closed version1 JSON содержит expected boot/netns/kernel release и до16 API/tag/tool/core/config revision expectations. Linux descriptor walk проверяет root ownership/permissions/no symlink/hardlink/special files/64KiB bounds и metadata до/после чтения. CLI проверяет manifest до key/DB; observer повторяет inventory перед/между/после reads. Immutable Result/Check/store target связывает inventory pin; inventory_bound относится к исходному выполнению. Declared core/version/config/kernel metadata не observed core attestation: full Xray acceptance flags false, blocked/exit1, read-only/no ledger/state/audit writes. AWG contract и схемы6/4/1 сохранены; native/core/client/transition acceptance открыта. ADR-0021, xray-inventory-runbook, iteration-23.

v0.27: pinned generator/core versions и native config-only parser regression согласованы; visual user/admin diagnostics читают только safe portal metadata и никогда не подтверждают online/client/ready. Commit-bound GitHub build/bootstrap подготовлен локально; remote CI, Linux activation и Android proof не выполнены. Snapshot1.22/statuses44/16/3/0, M1-02/03/05 и G1 открыты; схемы6/4/1.


v0.28: локально реализованы RU ingress/private relay и closed IPv4 kernel guard с independently scoped native apply/readback code. Это необходимый задел сетевого стенда для M1-02, а не принятие NET-03/04/05 или G1. Empty clients до writer-fenced vault/current binding, unprivileged core runtime и host forwarding0 preservation ещё открыты; positive Linux nft/topology/failure acceptance и Android client proof отсутствуют. Snapshot1.23/statuses41/19/3/0; ready/download/QR остаются закрыты.
