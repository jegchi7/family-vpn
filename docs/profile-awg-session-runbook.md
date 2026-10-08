# AWG selected-peer session diagnostics · v0.25.0

`profile-observe-awg-session` — отдельная trusted Linux CLI диагностика уже существующего AWG peer. Она нужна для проверки активности первого Android подключения на согласованном стенде. Команда не устанавливает ядро, интерфейс, peer или маршрут и не выдаёт клиентский конфиг.

## Что читается

Fixed independently pinned root-owned `/usr/bin/awg`, только текущий network namespace на locked OS thread. Команда выполняет `show INTERFACE latest-handshakes` и `show INTERFACE transfer`, ждёт две секунды с поддержкой отмены и повторяет обе команды. До, между и после чтений проверяются independently expected boot ID и netns device/inode. Нет shell, `setconf`, `awg-quick`, `dump`, выбора executable, discovery, setns или network mutations. Общий pinned descriptor/process-group/pipe timeout contract сохраняется; CLI имеет общий timeout12s.

Формат named-interface views подтверждён по [upstream show.c](https://github.com/amnezia-vpn/amneziawg-tools/blob/ee0f0a9aa34ff0a0da4b3433b9512781cfe02843/src/show.c#L481): ключ, TAB, Unix seconds либо ключ, TAB, received bytes, TAB, sent bytes. Это source inspection, не подтверждение установленного binary/core. All-interface prefix и неизвестные столбцы отвергаются. Parser ограничивает каждый output64KiB/256 peers, canonical nonzero32-byte keys, unsigned decimal numbers и допустимое время; duplicate peers, future timestamp, изменившийся набор peers и уменьшение handshake/counters дают ошибку. Unknown peers не удаляются и не изменяются.

Выбирается derived X25519 public key из валидированного сохранённого client-only `.conf`; clamping учитывается. В памяти observer фиксирует копию exact client bytes до чтений. Raw peer keys/counters не попадают в JSON, DB, audit или errors; входные buffers очищаются. Result immutable, JSON не восстанавливает его. Lifetime ограничен60s от начала чтения; measured_at фиксируется после последнего sample.

## Входы и запуск

До запуска должны существовать encrypted pending profile, отдельный purpose-tagged profile key и разрешённый AWG stand. Trusted operator должен иметь доступ к ключу/DB и право читать выбранный интерфейс в independently approved namespace. HTTP-процессам такие права не выдаются. Key owner/permissions не ослабляются, admin TOTP key не переиспользуется. Default кабинетный bootstrap не устанавливает VPN и не создаёт profile vault.

Owner/device/profile/generation/revision выбираются через `profile-targets`. Namespace/tool/interface/endpoint expectations происходят из независимого согласованного inventory, а не из результата этой команды или autopick. Ниже только пример аргументов для уже подготовленного стенда, не проверенный deploy:

```sh
./build/vpnctl profile-observe-awg-session \
  --root EXISTING_USER_STATE \
  --profile-key EXTERNAL_PROFILE_KEY \
  --owner-id OWNER_ID --device-id DEVICE_ID --profile-id PROFILE_ID \
  --generation CURRENT_GENERATION --expected-revision CURRENT_DEVICE_REVISION \
  --interface EXPECTED_INTERFACE --expected-endpoint EXPECTED_RU_ENDPOINT \
  --expected-tool-sha256 INDEPENDENT_TOOL_SHA256 \
  --expected-boot-id INDEPENDENT_BOOT_ID \
  --expected-netns-device INDEPENDENT_NETNS_DEVICE \
  --expected-netns-inode INDEPENDENT_NETNS_INODE
```

Команда открывает DB read-only. После native reads повторяет current owner/device/profile/generation/revision/pending/null-installed guards, active key, AEAD, format, credential uniqueness и sealed exact-byte/target/TTL binding в одной read transaction. Не записывает audit/observation ledger/state; SQLite WAL/SHM side effects возможны, как у других read-only diagnostics. `--apply`, `--input`, `--snapshot`, `--tool`, manual-client/ready flags отсутствуют. Keyless `profile-readiness` не меняется и не вызывает tools.

## Как читать результат

| Поле | Значение и ограничение |
|---|---|
| `peer_observed` | Выбранный key присутствует в согласованных samples. Отсутствие не доказывает revoke |
| `last_handshake` | Время последнего handshake либо null при0/неизвестном peer |
| `handshake_recent` | Возраст handshake не больше180s; это diagnostic policy, не гарантия активного клиента |
| `received_advanced`, `sent_advanced` | Соответствующий счётчик увеличился между samples; неподвижный счётчик сам по себе не означает отказ |
| `runtime_target_bound` | Result связан с independently expected execution scope; endpoint/core/config не удостоверены |

Даже при свежем handshake и росте обоих counters результат остаётся `status:blocked`, exit1. `stored:false`, `read_only:true`, `network_changed:false`, `ready:false`. Core identity, current revision, Android acceptance и DNS/routing verification всегда false. Это не readiness `Result`: его нельзя записать через `RecordProfileObservation` или передать в AWG readiness candidate.

Прежде чем выдавать профиль, нужны actual core/tool/version/config provenance, native parameter readback, установленный конкретный Android app/build с byte-exact export/import, DNS/TCP/UDP/IPv6 и Foreign-only egress tests. Отказ Foreign должен блокировать пользовательский трафик, сохраняя RU host management. Handshake/readback или ответ одного сайта «мой IP» не закрывают эти критерии. Native/tool/Android tests текущей Windows поставкой не выполнены.
