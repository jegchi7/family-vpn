# API contracts

`openapi.json` — реализованные локальные режимы v0.11.0; только из него генерируются frontend DTO. `planned-auth.openapi.json` — оставшийся draft admin invitation operation, без runtime. Прежние draft login/TOTP paths удалены: фактический contract имеет пути ниже. WebAuthn/recovery codes/fresh auth и полный production contract ещё впереди. `gateway/envelope-v1.schema.json` — metadata draft без parser/transport.

| Listener | Auth endpoints | Session |
|---|---|---|
| Portal HTTPS 8443 | bootstrap, login, invitations/accept, recovery/consume, logout, session/touch | User only, 30d absolute / 7d idle |
| Admin HTTPS 9443 | bootstrap, admin/password, admin/totp, logout, session/touch | Admin only, 12h absolute / 30m idle |
| Demo HTTP 8080/8081 | Нет настоящей аутентификации | Фиктивные read-only данные |

Все пути auth начинаются с `/api/v1/auth/`. Admin password возвращает challenge/expires_at без cookie сессии; TOTP принимает challenge/code и создаёт сессию. Public router отвечает 404 на `/api/v1/admin/*` и `/api/v1/auth/admin/*`, даже с admin cookie. На admin listener нет пользовательских invitation/recovery endpoints.

Bootstrap возвращает `mode` (`local-auth` или `local-admin`) и csrf_token, устанавливает отдельную preauth cookie. POST требует exact HTTPS Origin, JSON ≤64 KiB и X-CSRF-Token. До входа проверяется preauth double-submit; после входа — CSRF из `/me` или успешного auth result. Raw session находится только в Set-Cookie. Нет CORS и доверия forwarded headers. Query auth params запрещены.

User cookie `__Host-fvpn_session`: Secure/HttpOnly/Path=/, no Domain, SameSite=Lax. Admin cookie `__Host-fvpn_admin_session`: те же ограничения, SameSite=Strict. Preauth — отдельные имена, SameSite=Strict. Cookie ports не являются security boundary: разделение также обеспечивают разные DB/application_id и router validation.

GET не продлевает сессию. Touch — явный POST; UI отправляет его при видимой странице. `/api/v1/admin/overview` на защищённом admin listener отдаёт read-only данные из локальной пользовательской DB. Host management, agent RPC и real VPN mutations не реализованы. CLI enroll/confirm/reset/disable отсутствуют в HTTP API.

User recovery issuance — только trusted CLI. Consume token/new_password → 204, очистка cookies, без auto-login. Devices/profiles не меняются. См. ADR-0004…0006 и соответствующие runbooks. Этот контракт не разрешает production bind и не закрывает DEV-03/05 целиком.

Device request endpoints (user local-auth only): GET `/api/v1/devices/quota`, POST `/api/v1/devices`, POST `/api/v1/devices/{id}/rename`, POST `/api/v1/devices/{id}/cancel`. Session/Origin/CSRF/JSON required. Request ID is owner-scoped idempotency; same key/different normalized payload →409. Rename/cancel use expected_revision; foreign/missing device →404. Cancel only unissued pending requests. No key/address/peer provisioning. Profile format `""` means no format selected yet; `txt` remains demo only; `vless-reality-uri` means imported bytes awaiting installation verification. New device DTO includes revision.

Profile import v0.8 — trusted CLI dry-run/apply, без HTTP upload/real download. UI получает только metadata и pending format; UUID/pbk/config не входят в DTO. Imported pending download →409, отмена →409; в UI кнопка отмены для выбранного format скрыта.

`profile-preflight` v0.9 — trusted read-only CLI; HTTP endpoints/DTO не добавлены, ключи не передаются в портал.

Admin v0.10: GET `/api/v1/admin/users`, `/devices`, `/audit`. Только password+TOTP management session; default limit=25, max=100, keyset after cursor. Devices default state=pending. Public/demo routes404. Invalid/duplicate/unknown query400. No keys/configs/tokens/raw audit fields; no-store/no-referrer. См. admin-views-runbook.

Guides v0.11: authenticated local catalog, version/kind/verification_scope/verified_at/app metadata/offline_available. GET `/api/v1/instructions/{id}/offline` — attachment HTML, safe catalog ID/name, no query, no personalized values/resources/scripts. Unknown404, query400, anonymous401. Demo legacy DB guides offline_available=false. Portal verification does not imply client compatibility.
