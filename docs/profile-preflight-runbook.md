# Сверка конфигурации · v0.9.0

`profile-preflight` — read-only DEV-08 preflight. Команда не ставит peer, не запускает core, не меняет сеть/БД/audit, не объявляет профиль ready и не разрешает скачивание. Успех означает только совпадение выбранных параметров импортированного клиента и файла конфигурации.

## Входы

- Существующий local-auth store; purpose-tagged profile key вне user state. Команду исполняет trusted оператор, а не публичный HTTP процесс.
- `profile-targets --login NAME`: взять owner/device/profile/generation и **свежую** device_revision после импорта. Не брать revision из прежнего dry-run.
- Полный Xray **JSON** snapshot ≤64 KiB, полученный по management каналу. Private file: текущий UID, родитель 0700 и файл 0600 без symlinks; либо stdin. Нельзя загружать его в кабинет. JSONC, merged config directories и sing-box не поддерживаются этим адаптером.
- Независимый ожидаемый SHA-256 exact bytes snapshot из доверенного inventory. При изменении хоть одного байта требуется новая ревизия. Вычисление hash от произвольного входа в этой же команде не доказывает provenance или свежесть.
- Explicit inbound tag и RU endpoint HOST:PORT из inventory; DNS не резолвится. Endpoint mapping — заявление оператора, runtime reachability ещё не проверена.

```sh
./build/vpnctl profile-preflight \
  --owner-id OWNER --device-id DEVICE --profile-id PROFILE \
  --generation 1 --expected-revision REVISION \
  --inbound-tag CLIENTS_TAG --expected-endpoint RU_HOST:443 \
  --expected-config-sha256 EXPECTED_DIGEST \
  --server-config /private/snapshot.json
```

`--root` и `--profile-key` имеют те же defaults, что importer. Конфигурацию, UUID, private/public keys не передавать аргументами, не включать shell tracing. `--apply` здесь отсутствует. При stdin передавайте байты приватным pipe без печати в терминал/лог.

## Ограниченный subset

В выбранном inbound поддерживаются: tag/listen/числовой port/protocol=vless/settings/streamSettings; sniffing не является частью credential-сверки. Settings: explicit decryption=none, clients с UUID/flow, optional email/level, пустой fallbacks. Stream: explicit tcp/raw + reality. REALITY: privateKey, serverNames, shortIds, ровно один target/dest, optional show и xver=0. Unknown selected fields, duplicate/case-alias JSON keys, duplicate tags/UUID, custom stream settings и malformed key отвергаются. Другие inbounds/root sections не удаляются и не переписываются.

Сверяются endpoint/port/listen mapping, binary UUID, flow, X25519-derived public key, serverNames и shortIds. Xray tcp/raw рассматриваются как совместимые названия транспорта для данного subset. SNI exact-case, short ID case-insensitive hex; endpoint DNS case/trailing dot normalised. Specific listen IP с DNS endpoint без доказанного mapping даёт listen_mapping conflict. Ни одного сетевого запроса.

Источники полей: [Xray VLESS inbound](https://xtls.github.io/en/config/inbounds/vless.html), [REALITY](https://xtls.github.io/en/config/transports/reality.html), [transport](https://xtls.github.io/en/config/transport.html); проверены 04.10.2026. Это parser/comparator проекта, не pinned native-core validator.

## Результат и границы

- Match: status=ok, configuration_matches=true; ready/runtime_verified/clients_verified/network_changed=false.
- Mismatch: status=conflict, только фиксированные названия mismatched_fields, exit nonzero.
- Invalid/unsupported JSON: INVALID_SERVER_SNAPSHOT; digest drift: SNAPSHOT_REVISION_CONFLICT; input/key/target errors — безопасные коды importer.
- Report не содержит пути, endpoint, tag, UUID, pbk/privateKey или plaintext. Snapshot не сохраняется в DB или audit. Bytes очищаются best effort; Go JSON/ecdh/string allocations не дают гарантированного memory zeroisation.

Повтор безопасен. Device rename/revision drift, disabled owner, другой generation, неверный key или другой binding отклоняются. Успех не резервирует состояние для будущего commit. Будущий adapter обязан повторить проверку под lock и подтвердить загруженную revision, актуальный runtime peer, endpoint/client round-trip. Snapshot может быть устаревшим даже при верном hash. Не выдавать готовность или сегодняшнюю online доступность по этому report.

Обновление v0.19: консервативная VLESS credential uniqueness учитывает UUID wire aliases bytes6/7 по pinned Xray contract, сохраняя exact UUID/export bytes. Snapshot/users readback отвергают duplicate wire identity; alias не exact match. Partial users CLI описан в profile-xray-users-runbook.md; enumeration/core identity/revision/transport/client/ready не подтверждены. Это не general VLESS compatibility acceptance.
