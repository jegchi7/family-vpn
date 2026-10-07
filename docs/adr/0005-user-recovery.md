# ADR-0005: восстановление пользовательского кабинета

Статус: реализовано локально в v0.4.0, часть DEV-05. Админский MFA, passkey и резервные recovery codes не входят в этот шаг. Дополняет ADR-0004; не разрешает production bind.

## Сценарий

Администратор с доступом к локальному CLI выполняет `vpnctl auth-recovery --login <login>`. Это привилегированная операция восстановления уже активного обычного пользователя: в одной transaction отзываются все его browser sessions и ещё действующие одноразовые токены, удаляется прежний password credential, создаётся новый recovery token hash и audit event. Никаких HTTP endpoints выдачи кода или анонимного сброса по login нет.

CLI выводит token один раз для ручной передачи после проверки личности человеком. Введённый ранее пароль перестаёт действовать **при выдаче**, а не при последующем использовании кода. Если код потерян/истёк, вход остаётся отключённым до нового кода и успешного восстановления. Повтор команды заменяет прежний код; автоматически вернуть старый пароль нельзя. Сбой вывода stdout после commit также требует нового кода.

Пользователь выбирает «Забыли пароль?», вставляет код, задаёт и подтверждает новый пароль. `POST /api/v1/auth/recovery/consume` атомарно проверяет token purpose/expiry/consumption/revocation и актуальный user role/state, сохраняет новый password hash, помечает код использованным, повторно отзывает сессии/другие токены и пишет audit. Ответ 204 очищает cookies; новой сессии нет. Следующий шаг — обычный login с новым паролем.

Аккаунт сохраняет прежний id и ownership устройств. Данные devices/profiles и VPN generation не изменяются; сброс кабинета не является отзывом VPN-доступа. Прекращение уже исполняющегося GET задним числом не обещается; последующие обращения с прежними сессиями отклоняются.

## Защита

- Token — 32 random bytes, base64url без padding; в БД SHA-256. По умолчанию 15 минут, positive TTL ≤1 часа через CLI. Token передаётся POST body; в URL/localStorage/logs он не попадает.
- Тот же HTTPS loopback, exact Origin, preauth double-submit CSRF, strict JSON ≤64 KiB, no-store и отсутствие доверия forwarded headers, что у login/accept.
- Rate limits: 5 попыток/5 минут на recovery token fingerprint и 30/5 минут на socket IP, persistent SQLite; тот же bounded KDF semaphore. Неправильный новый пароль тоже учитывается, но не потребляет код. Внешняя ошибка не раскрывает user/login или причину недействительности кода.
- Проверка транзакцией выполняется после KDF; случайные токены разного назначения не взаимозаменяемы. Invite нельзя использовать для recovery или наоборот.
- Полученный до reset password hash повторно проверяется внутри CreateSession transaction: начавшийся ранее login не обходит удаление/замену credential.
- Write lock сериализует выдачу, перевыдачу и consume. Два consume дают один успех; reissue делает старый code unusable. Ошибка credential/audit write откатывает все изменения конкретной transaction.
- Только active role=user с password-only credentials. Admin, disabled, ещё invited аккаунты и пользователи с passkey/TOTP credentials отклоняются. Нельзя использовать этот путь как обход будущего MFA. После появления новых credential kinds recovery нужно пересмотреть явно.
- Audit содержит actor/action/object id/outcome/time. Токен, пароль, hash пароля и session value туда не записываются. Полный failed-attempt audit и retention остаются DEV-22.

## Миграция и перевыпуск приглашений

Portal schema v3 добавляет `one_time_tokens.revoked_at`, отдельно от `consumed_at`. Миграция не отзывает существующие sessions/invites. Только CLI применяет migrations; HTTP требует уже актуальную схему.

`vpnctl auth-reissue-invite --login <login>` работает для ещё invited обычного пользователя без credentials. Сохраняет user id/login, отзывает предыдущие неиспользованные токены, создаёт один новый invite с TTL ≤24 часов и audit. Active user должен использовать recovery, повторное приглашение для него запрещено.

## Что остаётся

Нет email/Telegram или автоматической отправки кода, публичного recovery request, восстановления admin/MFA/passkey, self-service recovery codes, уведомления об инциденте и production deployment. Обладатель доверенного CLI имеет полномочия сброса, поэтому доступ к нему и к portal DB должен контролироваться ОС. Изоляция UID, real origin и независимая security QA ещё впереди.

Источники (проверены 2026-09-29):
- https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html — одноразовые ограниченные по времени токены, обычный login после reset, отзыв сессий.
- docs/vpn-platform-spec-v1.0.md, AUTH-03…06 — нормативные требования проекта. Момент немедленного отзыва при **trusted CLI issuance** намеренно отличается от анонимной заявки на восстановление: анонимной заявки здесь нет.
