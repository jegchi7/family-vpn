# Итерация 11 · v0.11.0 · 04.10.2026

## Результат

DEV-10: embedded versioned instruction catalog, schema1, metadata/claim validation, stable IDs, content versions и separate verification scopes. 6 portal guides для ручного выбора ОС; 6 explicit AWG/REALITY client drafts. Portal guides показываются первыми. App/core native compatibility остаётся неизвестной. Никаких installer/deep-link claims без фактического client test.

Authenticated offline endpoint выдаёт self-contained HTML attachment из fixed catalog, без session/user/device/URL/config/keys. HTML template escaping, restrictive CSP/meta, inline CSS без JS/шрифтов/картинок/сети. User/admin local-auth получают каталог; demo прежние DB guides без offline endpoint. Public HTTP mutations/catalog upload отсутствуют. Catalog не меняет профиль/ready и не вызывает agent. Схемы portal/control/admin5/2/1, без миграции.

## Фактические проверки

- npm run check PASS: Go vet/race all, generated OpenAPI/TS drift, Svelte0 ошибок/0 предупреждений, Vite. Финальный повтор после сортировки portal-first PASS.
- npm run build PASS: frontend+6 binaries. Persistence smoke PASS.
- Browser user/auth/device/import/preflight/guide10/10 + demo4/4 + admin2/2 — **16/16 PASS**. Final guide desktop/mobile повтор после portal-first PASS.
- Offline: реальный browser download с MIME/name/cache/referrer проверкой → saved file → отдельный context offline=true; все8 steps,0 HTTP requests,0 overflow. Нет token/password/login/cookie values в HTML.
- Catalog invalid metadata/verification claims, Get/List isolation, HTML injection escaping PASS. HTTPS anonymous401/missing404/query400/no personalization PASS.
- Guide desktop/offline-mobile screenshots visually inspected; source snapshots не содержат native VPN keys или credentials.

Первый общий browser прогон дал9/10: import reload попал на временный404, когда параллельный check очищал тот же Vite dist. Сборка и browser tests разведены последовательно, полный повтор10/10 PASS. Не считалось дефектом auth или оправданием flaky retry. Правило внесено в AGENTS/runbook.

Linux x86_64, Go1.27.1, Node24.19, npm11.9, Playwright1.63, Chromium153.0.8010.0. Local browser configs outside source, self-signedTLS test only. JS gzip~28.45kB. Реальные ОС/мобильные native apps не тестировались: verified portal scope описывает кабинетный workflow в Chromium/Linux, а не native app compatibility.

## Бэклог и пределы

Canonical backlog1.6 обновлён, delivery-roadmap хранит закрытые локальные подзадачи. Цель владельца — обязательная принятаяv1 с промежуточными версиями. Baseline spec и history01–10 byte-identical. Родительские DEV-08/09/10/12/13 не объявлены Done до полных criteria;63 задач имеют47Backlog/13Inprogress/3Verification, GW8Backlog.

Actual loaded core/current peer/client round-trip до download, AWG3.1 native format/field preservation, installed-client versions/availability, liveNET/QA/ROL остаются впереди. Runtime agents/controller/foreign probe placeholders. Нет VPS/Git/remoteCI/deploy. Следующий независимый срез — DEV-14/15 restricted intent transport/serialized queue и trust/crash tests на локальном fake stand; реальные adapter writes отдельно по проверенному стенду.
