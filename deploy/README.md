# Deployment boundary

`npm run release:linux` собирает переносимый Linux local-auth стенд кабинета для amd64; `-- --arch arm64` выбирает ARM64. Архив содержит portal/admin/vpnctl, frontend и read-only preflight/runbook; Node на runtime стенде не нужен. [Инструкция стенда](../docs/stand-runbook.md) описывает separate private state, explicit offline initialization и direct loopback HTTPS startup. Builder не выполняет deploy/network/init и не удостоверяет actual Linux/native/client acceptance.

Production deployment пока отсутствует. Systemd units, разделение service UID, реальные management/TLS inputs и проверенный rollback появятся после PRE/NET задач. Local-auth остаётся только numeric loopback; demo и локальный стенд не публиковать через reverse proxy/tunnel и не выдавать за production-пилот.

Будущий порядок: management recovery → firewall fail-closed → VPN cores → agent/control API → public portal. Текущий пакет не проверяет эти сетевые шаги. Готовность файлов/HTTP не делает VPN profiles ready; native/core/client/readiness и release/pilot gates остаются открытыми.
