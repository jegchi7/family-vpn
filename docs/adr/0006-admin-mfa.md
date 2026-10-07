# ADR-0006 — отдельный локальный admin auth с TOTP

Статус: принято для v0.5.0, Linux local stand. Не разрешает production deploy и не отменяет нормативную спецификацию.

## Граница хранения

В v0.4 пользовательский HTTP-процесс имеет write-доступ к portal DB ради сессий. Хранение admin credentials в той же БД оставило бы их доступными этому процессу. Поэтому admin authentication выделен в **третью SQLite DB** с собственным application_id, schema v1 и checksummed migration history. Portal v3 и control v2 не меняются. Это уточняет ADR-0002; исходная спецификация остаётся целевой, её Credential/Session модели для admin размещены отдельно.

| Процесс | Portal DB | Admin auth DB | Master key | Control DB / agent socket |
|---|---|---|---|---|
| portal local-auth | Read/write | Не открывает | Не загружает | Нет |
| admin local-auth | Read-only | Read/write | Читает при старте | Нет |
| trusted vpnctl | По конкретной команде | Для admin-* | Для MFA setup | Только прежние demo-команды |

Всё локально работает под одним UID: это граница зависимостей и открываемых файлов, **не доказанная изоляция ОС**. Разные Linux UID, ACL, systemd hardening и запрет доступа public UID к admin state обязательны перед production. Даже отдельные DB не защищают от root, компрометации admin process или копии DB вместе с master key.

## Ключ и TOTP

AES-256-GCM использует Go `crypto/cipher.NewGCMWithRandomNonce`: библиотека генерирует и помещает nonce в ciphertext. AAD связывает версию назначения `admin-totp/v1`, key ID и account ID; key ID — SHA-256 случайного 32-байтного master key. Ключ хранится вне root админской БД, создаётся отдельной командой O_EXCL, runtime ничего не генерирует. Проверяются private parent/file permissions, владелец, regular file и отсутствие symlink в пути. Неподдерживаемая проверка ownership на других ОС закрывает доступ; Windows admin MFA пока не поддержан. Symlink/ownership checks не заменяют защищённые от подмены предки каталогов.

При старте расшифровываются active/pending TOTP records для проверки ключа. Отсутствие, неправильный ключ или повреждение ciphertext запрещают запуск. Утеря ключа не приводит к password-only fallback. Ключ находится в памяти процесса до его завершения; безопасное стирание всех копий в Go не гарантируется. Ротация ключей и полная backup/restore процедура ещё впереди.

TOTP: `github.com/pquerna/otp v1.5.0`, 20 random bytes, SHA1/6 digits/30 sec, окно ±1 step. После успешной проверки сохраняется максимальный использованный step; код не принимается повторно в другой challenge, после restart или конкурентно. Clock rollback может временно запретить код; часы сервера и authenticator должны быть синхронизированы. При совпадении шестизначных кодов разных steps проверяется выбранный step, а не глобальная вечная уникальность числового кода.

## Bootstrap, reset, сессии

CLI enrollment принимает пароль через stdin JSON, хранит только Argon2id hash и encrypted TOTP, выводит setup secret один раз для ручного добавления в authenticator. Аккаунт pending на 10 минут, без возможности browser login. CLI confirm проверяет код, активирует аккаунт, потребляет step и не создаёт сессию. Setup URI/секрет не передаются через HTTP/URL. Для удобства есть Python getpass wrapper без эха.

Первый фактор создаёт random challenge на 3 минуты, привязанный к hash отдельной preauth cookie. В БД — только hash challenge. На аккаунт один текущий challenge: новая успешная password-проверка заменяет прежний. Persistent limiter ограничивает login/account, IP и challenge; БД дополнительно допускает максимум 5 проверок одного challenge. Argon2id ограничен двумя параллельными вычислениями на процесс.

Finish берёт SQLite writer lock, проверяет binding/TTL/account revision/state, проверяет TOTP, потребляет challenge, обновляет step, создаёт сессию и audit в одной транзакции. Неправильный код коммитит попытку, но не сессию. Ошибка записи audit откатывает выдачу. Reset между password и finish аннулирует challenge и старый password hash.

Admin cookie — `__Host-fvpn_admin_session`, Secure/HttpOnly/SameSite=Strict, отдельная от пользовательской. Сессия: 12h absolute, 30m idle, серверные timestamps. Auth POST требуют exact Origin, JSON и CSRF. GET не продлевают idle; frontend touch при видимой странице продлевает idle, в том числе без физического взаимодействия с формой. Поэтому это session activity policy, не детектор присутствия человека. Master key для user HTTP не нужен. Public router не регистрирует admin MFA endpoints и не принимает admin session даже при переименовании cookie.

CLI reset сохраняет admin ID и атомарно заменяет password/TOTP, возвращает pending, отзывает все сессии и challenges. Disable закрывает аккаунт и отзывает сессии/challenges; не требует master key. User recovery не работает с admin DB. Recovery codes, WebAuthn и fresh auth остаются отдельными задачами. Опасных HTTP mutations в этой версии нет.

## Проверенные первичные источники

- [Go cipher — NewGCMWithRandomNonce](https://pkg.go.dev/crypto/cipher#NewGCMWithRandomNonce).
- [pquerna/otp v1.5.0 TOTP API](https://pkg.go.dev/github.com/pquerna/otp@v1.5.0/totp).
- [Исходный проект pquerna/otp](https://github.com/pquerna/otp).

Эти источники описывают библиотеки. Корректность проектной границы оценивается собственными tests и дальнейшим review, не гарантируется выбором библиотеки.
