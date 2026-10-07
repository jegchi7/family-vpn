# AWG readback · v0.21.0

`profile-observe-awg` — trusted Linux CLI для уже импортированного pending AWG-профиля. Default — read-only DB и dry-run; `--apply` записывает только результат сверки и audit. Команда не выдаёт профиль и не меняет устройство, installed_revision, сеть или peers. HTTP не получает profile key или новый privileged API.

## Обновление существующего стенда

Остановить local-auth/admin процессы, сохранить private backup DB и внешних ключей. После сборки выполнить explicit init:

```sh
./build/vpnctl auth-init --root var/auth
```

Portal v5→v6 добавляет `profile_observations`; ciphertext/context не меняются. Control/admin остаются v4/v1. Runtime/dry-run на старой schema завершаются безопасной ошибкой; observer не выполняет миграцию. Ключ профилей остаётся вне auth root.

## Входы и запуск

Получить owner/device/profile ID, generation и текущую revision из `profile-targets --login family-test`. Требуются active ordinary owner, pending device/profile, current generation и существующий ciphertext формата `awg-3.1-conf`.

Нужны независимо согласованные endpoint и SHA-256 конкретного `/usr/bin/awg`, а также имя существующего интерфейса в текущем network namespace процесса. `TOOL_SHA256` ниже — placeholder из доверенного inventory, а не значение, автоматически полученное с неизвестного бинарника. Команда не принимает исполняемый путь или snapshot file. `/usr/bin/awg` должен быть regular root-owned executable без group/other write и совпадать с pin; выполняется уже проверенный file descriptor.

```sh
./build/vpnctl profile-observe-awg \
  --root var/auth --profile-key var/profile-secrets/current.key \
  --owner-id OWNER_ID --device-id DEVICE_ID --profile-id PROFILE_ID \
  --generation 1 --expected-revision 2 \
  --interface awg0 --expected-endpoint VPN_HOST:VPN_PORT \
  --expected-tool-sha256 TOOL_SHA256 \
  --expected-boot-id BOOT_ID \
  --expected-netns-device NETNS_DEVICE --expected-netns-inode NETNS_INODE
```

Заменить все placeholders актуальными значениями. `--apply` добавляется только для записи metadata. Работа на VPS и подключение к нему требуют отдельного operational scope; эта поставка их не выполняет. Container/netns switching и установка AWG не реализованы.

Два вызова `awg showconf INTERFACE` должны вернуть byte-identical bounded readback. Каждый имеет timeout4s, общий CLI deadline12s; stdout ≤64KiB, максимум256 peers. Shell/PATH lookup, `setconf`, `awg-quick`, `ip` и сетевые probes не вызываются; stderr не публикуется. Снимки с private server key используются только в памяти, не записываются в файлы/DB/DTO/logs.

## Что сравнивается

Derived client public key выбирает peer; дубли selected key отклоняются. Derived server public key сравнивается с клиентским Peer.PublicKey. Inventory endpoint должен точно совпасть с клиентским endpoint, ListenPort — с портом. Проверяются PSK, HeaderProtectionKey, S1…4/H1…4, RandomTrailers/DisableCookies с omitted=off на обеих сторонах. Selected AdvancedSecurity должен быть явно on; off/missing дают advanced_security conflict в этом консервативном M1 subset. Selected AllowedIPs должны быть ровно host /32 или /128 для всех client Address; пересечение адресов с другими peers отмечается как conflict. Неизвестные peers сохраняются: команда ничего не удаляет.

J*, локальные padding/timers/CPS и keepalive не принуждаются быть равными серверным значениям. Readback имеет закрытую allowlist; unknown fields/hooks, неоднозначность, malformed values отклоняются. FwMark readback принимает off/decimal uint32 и 0x с1…8 hex digits; client import по-прежнему его запрещает. Mode не применяется к сети. Source contract закреплён в awg-showconf-contract.md; не подтверждает все варианты upstream showconf, pinned native execution или AWG3.1 client compatibility.

## Результат и ограничения

JSON содержит только observation ID, source, timestamps и имена несовпавших полей. `peer_matches:true` означает совпадение этой проверки; `runtime_observed:true` относится к двум native readbacks. `clients_verified:false`, `ready:false`, `network_changed:false` всегда. Native binary/kernel/core positive path в текущей среде не проверен; тест read contract использует injected reader.

Immutable result связан с owner/device/profile/generation/device revision, SHA-256 точных client bytes и independently expected interface/endpoint/tool pin/boot/netns device+inode в памяти; TTL60s начинается перед первым чтением. Apply повторно читает binding/plaintext в writer transaction. Expired/future/renamed/replaced/foreign result отвергается; audit failure откатывает metadata. Replay того же ID не добавляет второй audit. DB хранит historical safe metadata, а не reusable разрешение на выдачу; digest/plaintext/endpoints/keys туда не попадают.

Drift, unavailable runtime и stale binding требуют новой проверки. Совпавший readback не доказывает handshake, routing, DNS, UDP path, management isolation или пригодность конкретного клиента. Xray v0.19 имеет отдельный partial named-users read-only observer; он не подтверждает complete runtime identity/revision/transport и не пишет этот ledger. Следующий срез M1-02: native positive/negative acceptance, independent inventory/version record, Xray runtime source и pinned client round-trip; затем отдельный audited readiness transition и DEV-09 delivery.

v0.20: оба Linux observer ограничивают также ожидание inherited stdout/stderr: отдельная process group, SIGKILL при отмене, WaitDelay200ms и cleanup после раннего parent exit. Неполный/ошибочный readback очищается и не становится proof. Local helper-process regression tests не являются AWG/Xray native acceptance. Fixed descriptor/pin/args, pending gate, schemas6/4/1 и UI/API сохраняются. ADR-0018, iteration-20.

## Runtime target v0.21

Обязательные BOOT_ID/NETNS_DEVICE/NETNS_INODE берутся из отдельно согласованного current inventory разрешённого host/boot/netns. Нет fallback/autodiscovery ожидаемых значений. Самостоятельно скопировать текущие значения неизвестного процесса — не установление доверия к окружению. Read-only способы сбора для согласованного inventory: `cat /proc/sys/kernel/random/boot_id`; `stat -Lc '%d %i' /proc/thread-self/ns/net` в согласованном namespace. Это не инструкции подключения к VPS и не запуск здесь. После reboot или замены namespace заново проверить protected inventory и manifest.

Observer проверяет fixed proc paths на locked OS thread перед/между/после readbacks. Namespace switching не выполняется. Missing/malformed/unexpected/changed scope выдаёт sanitized error; snapshots/JSON не восстанавливают runtime target. Result summary добавляет только runtime_target_bound, не target values; flag не core/client/readiness acceptance. Apply повторяет expected target scope внутри writer transaction. Keyless metadata report не проверяет target и сообщает runtime_target_verified:false/blocker. ADR-0019, iteration-21.

В v0.22 fixed proc reader/boot validator выделены в internal/runtimeenv и используются обоими observer. AWG public Target, storage/prepare/recheck и keyless diagnostics сохраняют v0.21 contract.
