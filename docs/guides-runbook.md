# Инструкции и офлайн-памятки · v0.11.0

В user local-auth кабинете открыть «Как подключиться», вручную выбрать iOS/Android/Windows/macOS/Linux/другое, затем «Скачать офлайн-памятку». Файл HTML открыть обычным браузером без доступа к кабинету/интернету. Он не устанавливает VPN и не содержит конфигов/ключей/URL вашей панели или личных данных. Admin local-auth также может читать общий каталог. Demo сохраняет старые draft DB instructions без offline endpoint.

## Версии и проверка

`internal/guides/catalog.json` schema1 встраивается в Go binary; HTTP не загружает/редактирует его. Каждая инструкция имеет stable allowlisted ID/OS, kind, content_version, steps, verified и verification_scope; проверенная — verified_at, future client guide — app_id/app_version/protocol/format. Текст/число шагов/размер/metadata ограничены. Get/List не дают менять catalog slices. Обновить content_version при содержательном изменении и пересобрать binary; no migrations/DB insert.

12 записей: 6 portal workflow и 6 client draft (AWG/REALITY для iOS/Android/Windows). Portal scope означает проверку локального кабинетного сценария в Chromium desktop/320px на Linux, **не** запуск native clients или всех ОС. Клиентская compatibility/доступность RU App Store, конкретные версии приложений и способы установки неизвестны; client verified=false, scope=none. Нет install/deep link buttons. Формат VLESS parser не превращается в обещание поддержки приложения.

Перед подтверждением client guide: pinned app/core/OS versions, explicit client-only format, factual install/export/import/round-trip на устройстве, контроль параметров и receipt в compatibility manifest. verified_at — дата фактической проверки, не пересборки. Catalog metadata не разрешает profile ready/download и не заменяет runtime binding/evidence.

## Offline API и безопасность

GET `/api/v1/instructions` — metadata/steps. GET `/api/v1/instructions/{id}/offline` — generated attachment `family-vpn-guide-ID-vN.html`, MIME `text/html; charset=utf-8`. Only authenticated local listener; anonymous401, missing404, query400. No query config/token/owner parameters. Catalog ID проверен; filename не зависит от user input. Headers no-store/no-referrer/nosniff, restrictive CSP.

HTML с charset/viewport и встроенным CSS; no JS/forms/images/iframes/fonts/external stylesheet/fetch. Template HTML escaping; request/session/user/device данные в renderer не передаются. CSP meta обеспечивает offline запрет источников. Памятка не шифруется — она non-secret; профиль будет храниться отдельно. Онлайн скачивание требует auth, открытие сохранённого файла — нет.

## Проверка

Go catalog validation/isolation, invalid verification claims/metadata и HTML escaping. HTTPS tests anonymous/download/query/missing + safe headers/no personal values. Browser flow приглашение → guide/OS selection → file download → отдельный offline browser context с нулём HTTP requests; desktop и320px, no overflow. Screenshots iteration11. Native iOS/Android/Windows VPN compatibility остаётся отдельным PRE-04/QA-07.

Build/check и browser tests выполнять последовательно для одного dist: Vite очистка output во время теста вызывает временный404, что не является результатом runtime acceptance. Приватные test credentials/downloads/DB остаются вне source/архива.
