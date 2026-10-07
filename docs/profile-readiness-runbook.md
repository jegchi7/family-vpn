# Проверка перед выдачей · v0.19.0

`profile-readiness` — trusted CLI для диагностики причин, по которым current profile нельзя считать готовым. Команда читает существующую portal DB read-only, не получает ключ vault, не расшифровывает client export и не вызывает runtime/network. Новых миграций нет: portal/control/admin6/4/1. Это не readiness transition или разрешение на download.

## Запуск

Получить IDs/generation/revision из `profile-targets --login family-test`. После request или любого rename/import снова прочитать current revision; нельзя подставлять прежнюю.

```sh
./build/vpnctl profile-readiness \
  --root var/auth --owner-id OWNER_ID --device-id DEVICE_ID \
  --profile-id PROFILE_ID --generation 1 --expected-revision 2
```

Заменить placeholders реальными current targets. CLI не принимает `--apply`, `--profile-key`, snapshot file, `--ready` или `--client-verified`. Ошибочные flags/IDs не печатаются в stdout/stderr. Missing DB и старая schema не создаются и не обновляются. Demo store, foreign/disabled/admin owner не используются для current user report.

В v0.19 корректный диагностический ответ имеет `status:blocked`, `ready:false` и exit1. Ошибки чтения/входов имеют `status:error` и exit1. Exit0 не используется как неявный positive permission: в этой версии нет положительного readiness outcome. При ошибке вывода CLI также завершается ненулевым кодом.

## Как читать результат

Report содержит проверенные generation/device revision, device/profile state, protocol/формат, наличие ciphertext, safe metadata последней наблюдаемой сверки и список blockers. `stored_export:true` — наличие ciphertext, а не успешная AEAD/format/client проверка. `secret_verified:false` и `clients_verified:false` всегда; secret bytes, keys, endpoints, адреса, UUID и чужие IDs в вывод не входят.

| Observation status | Значение |
|---|---|
| null | Для данного owner/profile нет observation |
| fresh_match | Последняя AWG runtime metadata совпала, current generation/revision и TTL действуют |
| configuration_only | Совпавший snapshot не является runtime readback |
| conflict | Последняя свежая сверка зафиксировала несовпадение |
| expired | TTL60s истёк, включая точную границу expires_at |
| future | measured_at позже checked_at |
| stale_binding | Запись относится к другой generation/device revision |
| unsupported | Scope записи не подходит к текущему protocol/формату |

Latest запись выбирается по UTC timestamp с нормализацией fractional seconds; не искать более старое совпадение при новом conflict/stale/future/expired result. В SQL выбирается одна запись только для явного owner/profile. JSON field names имеют allowlist, ID/source/timestamps и TTL проверяются; повреждённые metadata дают INVALID_OBSERVATION без raw values.

`stored_runtime_readback_fresh:true` описывает только сохранённую metadata при current target. Это не повторное измерение ядра, не attestation версии core, не проверка bytes/secret и не fencing token. State/binding и observation читаются в одной read transaction, но последующее изменение делает report историческим снимком; его нельзя передавать в будущий transition как разрешение.

## Причины блокировки

| Blocker | Следующий шаг |
|---|---|
| client_import_missing | Импортировать client-only export в current pending target |
| client_format_unverified | Использовать поддерживаемый subset или сначала принять новый формат |
| device_state_blocked / profile_state_blocked | Разобрать current состояние, не выдавать профиль через этот read model |
| runtime_observer_unavailable | Full REALITY observer/attestation отсутствует; partial users CLI не пишет ledger и не подтверждает core/revision/transport |
| observation_missing / observation_expired / observation_binding_stale | Получить новое scoped runtime readback для current target |
| observation_time_invalid / observation_scope_unsupported | Проверить clock/inventory/source и получить новую сверку |
| observation_conflict | Разобрать несовпавшие safe fields; старое совпадение не заменяет новый conflict |
| snapshot_not_runtime | Получить actual current runtime readback |
| secret_verification_required | В будущем transition повторно открыть и проверить vault/client bytes |
| client_acceptance_missing | Принять pinned app/format export-import и соединение на разрешённом стенде |
| readiness_transition_unavailable | Реализовать и принять отдельный audited transition с current binding/fencing |

Последние три blockers нельзя убрать флагом или правкой checkbox. Current ready/installed_revision/network, observation ledger и audit не изменяются. Public/admin HTTP не получают новый endpoint, key или control/socket access. Test synthetic ledger rows проверяют классификацию read model, не native/client acceptance. Следующие шаги KUK-5 — runtime/client acceptance и scoped transition; KUK-6/7 delivery ждут их завершения.

В v0.17 comparator и diagnostics используют общий bounded vocabulary18 safe field names, включая advanced_security. Проверен полный результат comparator с17 несовпадениями через запись observation и read-only report; unknown/duplicate/null names и matched-with-fields отвергаются. Это metadata, не secret/native/client proof. Старые observation rows — история прежнего comparator; после обновления следует получить новую actual scoped сверку, не использовать старый match как разрешение.

## Trusted подготовка · v0.18

PrepareAWGReadiness и RecheckAWGReadiness — внутренние storage APIs; CLI выше и HTTP их не вызывают. Preparation открывает current encrypted export с active purpose key, проверяет AEAD/AAD, format, credential uniqueness и exact bytes/binding/revision/TTL immutable Result. Не читает ledger для авторизации. SecretVerified:true относится только к этому новому report и моменту его transaction; прежний keyless report остаётся secret_verified:false.

Candidate не хранит plaintext, сериализуется только в safe diagnostic JSON и не восстанавливается из него. Recheck получает writer fence, повторяет guards и откатывает tx. Изменение owner/generation/revision/state/key/bytes или duplicate credential отвергает подготовку. RuntimeMatches относится только к исходной scoped observation, не новому измерению core. Snapshot/conflict блокируют runtime gate. Client acceptance и transition остаются обязательными blockers; ready/client/state/network false.

Writer fence освобождён при возврате. Report/candidate не являются разрешением или reservation; будущий transition должен повторить guards и actual client proof в одной writer transaction вместе со state/audit. Native positive/core/client acceptance не выполнена. Детали: ADR-0016 и iteration-18.

В v0.19 отдельная trusted команда profile-observe-xray-users читает только partial named-users scope. Этот keyless report не получает её Result/key и не считает его complete runtime readiness. Snapshot/native-users comparison не подтверждает responding core identity/revision/transport/client. Details: profile-xray-users-runbook.md.

v0.21: immutable AWG runtime target связывает interface/endpoint/tool pin/current boot ID/netns device+inode с profile/exact bytes/revision/TTL. Observe сверяет fixed proc environment на locked OS thread до/между/после readbacks; storage/prepare/fenced recheck требуют independently expected target. Snapshot/JSON не превращаются в native scope. Ledger target не хранит; keyless runtime_target_verified:false и обязательный blocker. Local contracts/proc negative tests не закрывают native/core/client/transition acceptance. ADR-0019, iteration-21; схемы6/4/1 без миграции.

`stored_runtime_readback_fresh` описывает freshness/source/binding metadata и не подтверждает target. `runtime_target_verified:false` и `runtime_target_verification_required` нельзя устранить параметром keyless CLI. Prepare/Record принимают target явно; Recheck требует свежую independently selected expected target и сравнивает с private candidate. Recheck не выполняет новое native readback и не резервирует runtime/interface.
