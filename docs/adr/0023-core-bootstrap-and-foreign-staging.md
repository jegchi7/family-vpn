# ADR-0023 · Pinned cores и private Foreign staging

Статус: принято для локальной реализации v0.26.0; native deployment acceptance открыта.

08.10.2026 владелец попросил встроить установку VPN-ядер и инструменты настройки зарубежного сервера. Вход: два Ubuntu20.04/~1GiB, кабинет уже работает на RU, VPN не настроен, первый клиент Android. Эта поставка готовит реальные operator tools; из локальной задачи нет соединений к VPS, firewall/routes/SSH изменений или publication.

Выбран закрытый embedded каталог официальных Xray26.3.27, sing-box1.14.2 musl и Hysteria2.13.0 для Linux amd64/arm64. Archive и extracted binary имеют независимые SHA256/size pins. Static ELF подтверждён inspection официальных bytes; native execution/resources этим не подтверждаются. Download/extraction потоковые и bounded, установка fixed root-owned `/usr/bin`, no-overwrite atomic publish, default dry-run. Никаких arbitrary URL/hash/executable flags, curl-to-shell, runtime compiler или HTTP root action.

AWG installer пока blocked: официальный Ubuntu22.04 tools artifact не принят для20.04, go binary releases отсутствуют, selected AdvancedSecurity metadata в inspected UAPI не соответствует observer contract. Существующий AWG pin/security guard не ослабляется.

Foreign toolset генерирует только одну private primary REALITY pair: server Xray config и RU sing-box outbound fragment. Один credential, crypto/rand, protected fixed staging outside portal state, closed schema/exact regeneration validation. Optional fixed pinned Xray config-only check не запускает service. Secrets не выводятся, HTTP/API/schema/profile state не изменяются; ready/runtime/routing/client proof false.

До runtime activation нужен независимо принятый kernel guard/netns: domain routing и even destination finalRules не гарантируют отсутствие предварительного TCP handshake при изменении DNS. Foreign public egress является целевым окончанием двухсерверного маршрута; RU DIRECT fallback запрещён. Hysteria binary устанавливается без server запуска; backup config ждёт confirmed TLS inputs. Не выдавать staged config за принятый deploy или pairing protocol.

Operator workflow и зависимости: `../vpn-bootstrap-runbook.md`. Native/core/client acceptance, audited readiness transition, M1/G1 и full original63 criteria остаются открыты.
