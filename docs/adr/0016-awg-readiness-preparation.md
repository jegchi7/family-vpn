# ADR-0016 · Подготовка AWG readiness без выдачи доступа

05.10.2026 · локальный срез v0.18.0 · KUK-5 In Progress.

## Решение

PrepareAWGReadiness читает явный current pending owner/device/profile/generation/revision в read transaction. RecheckAWGReadiness получает SQLite writer fence, заново выполняет проверки и откатывается. Проверяются active purpose key, AEAD/AAD, allowlisted AWG format, credential uniqueness и привязка sealed profileobserve.Result к точным bytes, ревизии и TTL60s. Pending профиль с installed_revision, включая пустую строку, отвергается также существующими observation load/record методами.

AWGReadinessCandidate хранит только immutable observation, binding и safe report в памяти. Plaintext не сохраняется. JSON не восстанавливает candidate; String/GoString не печатают внутренние поля. Summary копирует blockers. Historical ledger не читается как доказательство или разрешение; snapshot/conflict получают blockers.

SecretVerified означает успешную AEAD/format/uniqueness проверку внутри данной транзакции. Это поле нового trusted report; keyless CLI по-прежнему выводит secret_verified:false. RuntimeMatches относится к исходному immutable observation в пределах TTL. Recheck не измеряет core заново; его изменения после observation требуют новой actual сверки и native drift acceptance.

ClientsVerified/Ready/StateChanged/NetworkChanged всегда false. Client_acceptance_missing и readiness_transition_unavailable обязательны даже при runtime match. Нет клиентского checkbox, произвольного attestor, CLI apply/ready или HTTP endpoint.

## Граница fencing

Fence действует внутри recheck transaction и освобождается до возврата. Candidate, JSON и writer_fenced:true не являются lease/reservation/authorization. Будущий transition обязан повторить helper и actual client proof, выполнить state change и audit в одной writer transaction; recheck → отдельная запись ready запрещена. Эта поставка не реализует такой переход и не создаёт audit event успешной установки.

## Проверки и ограничения

Generated in-memory keys и temporary encrypted DB. Проверяются изменённая ревизия/generation, revoked/disabled состояния, installed_revision, AEAD corruption, новые валидные bytes, неизвестное поле, key rotation, duplicate credential, foreign binding и ledger-only fake runtime row. Два DB handles проверяют ожидание чужой writer transaction и отклонение новой ревизии после commit. Native/core/client acceptance не выполнена; G1 открыт. Схемы6/4/1 без миграции, UI/API/CLI unchanged; сеть/VPS/deploy не затрагиваются.
