# Подготовка VPN-ядер и Foreign · v0.29.0

Новый сетевой срез: [RU ingress и изоляция](network-stand-runbook.md). Он требует отдельного trusted operator запуска и real Linux/client acceptance; команды этой страницы подготавливают только cores/Foreign staging.

Это operator-run CLI для установки закреплённых бинарных файлов и подготовки приватной конфигурации. Запуск ядра, systemd, netns, nftables, routes, SSH и публикация кабинета сюда не входят. На VPS из локальной задачи никто не подключался. Подготовка не открывает выдачу профилей и не подтверждает работающий VPN.

## Из вручную обновлённого GitHub

Перед командами: загрузить исходники v0.29.0 в `jegchi7/family-vpn` и commit в main; дождаться зелёного workflow `checks` и опубликованного prerelease `v0.29.0` с четырьмя assets. Сам commit исходников без успешной сборки не создаёт Linux binaries. Workflow требует новую package version при конфликте старого release; assets не заменяет. Remote CI/release этой версии из локальной задачи ещё не запускались. Механика GitHub assets/digest: [официальный API](https://docs.github.com/en/rest/releases/assets).

Выполнять в root shell каждого VPS. На VPS ставятся только curl/Python/CA и нужные core binaries; Go/Node не нужны. Installer не перезаписывает существующий чужой binary. Это подготовка ядер/Foreign staging, не запуск VPN и не обновление уже работающего кабинета: UI обновляется из matching runtime по stand-runbook.

RU:

```sh
apt-get update && apt-get install -y ca-certificates curl python3 && (umask 077; b=$(mktemp /root/family-vpn-bootstrap.XXXXXX.py) && curl --disable --fail --silent --show-error --proto '=https' --tlsv1.2 --proxy '' --max-time 120 --max-filesize 65536 https://raw.githubusercontent.com/jegchi7/family-vpn/v0.29.0/scripts/bootstrap-github.py -o "$b" && test "$(stat -c %s "$b")" -le 65536 && printf '%s  %s\n' '97a4ea3785de0c9e62369c40978b3db0e12451257a1e73f33b3e8196caa711d4' "$b" | sha256sum -c - && python3 -I "$b" --role ru --apply)
```

Foreign:

```sh
apt-get update && apt-get install -y ca-certificates curl python3 && (umask 077; b=$(mktemp /root/family-vpn-bootstrap.XXXXXX.py) && curl --disable --fail --silent --show-error --proto '=https' --tlsv1.2 --proxy '' --max-time 120 --max-filesize 65536 https://raw.githubusercontent.com/jegchi7/family-vpn/v0.29.0/scripts/bootstrap-github.py -o "$b" && test "$(stat -c %s "$b")" -le 65536 && printf '%s  %s\n' '97a4ea3785de0c9e62369c40978b3db0e12451257a1e73f33b3e8196caa711d4' "$b" | sha256sum -c - && python3 -I "$b" --role foreign --apply)
```

Script SHA проверяется **до** Python execution. Bootstrap фиксирует current main SHA, package version и matching published prerelease/tag; проверяет оба architecture assets/digests, sidecar, streamed bounded tar, внутренний manifest/SHA и ELF target. Main ещё раз проверяется до запуска installer. Нет произвольных repo/URL/hash/path/tool flags или environment proxy. Приватный комплект остаётся в новом `/root/family-vpn-bundles/v0.29.0-*`; старые комплекты не удаляются.

RU устанавливает Xray/sing-box и проверяет integrity. Новый Foreign запрашивает четыре публичных параметра через terminal; existing private staging не перегенерируется, выполняется проверка. Ошибка не удаляет ранее установленное ядро/credentials, можно повторить matching команду. Ни один service/listener/route/firewall/SSH не активируется. Проверка синтаксиса не означает соединение или готовность профиля. Default `python3 -I scripts/bootstrap-github.py --role ru` — dry-run без загрузки/записи.

## Комплект и ограничения

Использовать соответствующий Linux amd64/arm64 runtime bundle v0.29.0. Проверить `.sha256` до распаковки, затем `sha256sum -c SHA256SUMS` внутри комплекта. В runtime не нужны Go, Node, C compiler или Docker; сборку выполнять на ПК/CI. Ubuntu20.04/~1GiB — вход владельца, а не результат native resource acceptance. Статический ELF снимает зависимость от установленной glibc, но не доказывает совместимость с конкретным kernel и работоспособность сети.

| Ядро | Закреплённая версия | Назначение |
|---|---|---|
| Xray | 26.3.27 | RU VLESS ingress; Foreign primary REALITY |
| sing-box | 1.14.2, musl | RU loopback SOCKS/camouflage relay → Foreign; TUN/selector позднее |
| Hysteria2 | 2.13.0 | Будущий Foreign backup UDP443 |
| AWG | Пока заблокирован | Нет принятого Ubuntu20.04 binary/native security subset |

Источник pins — официальные releases [Xray](https://github.com/XTLS/Xray-core/releases/tag/v26.3.27), [sing-box](https://github.com/SagerNet/sing-box/releases/tag/v1.14.2), [Hysteria](https://github.com/HyNetworks/hysteria/releases/tag/app/v2.13.0). Закрытый каталог с archive/binary SHA256 и размерами встроен в `internal/coreinstall`. Для sing-box выбран статический musl asset: обычный artifact имеет dynamic loader/libcronet. Installer не загружает `latest` и не принимает произвольные URL, digest, executable или install path.

AWG tools upstream Ubuntu22.04 нельзя обещать на20.04. Для amneziawg-go upstream release binaries не найдены; inspected UAPI не сообщает требуемый selected-peer `AdvancedSecurity`. Это отдельная задача сборки/observer contract/native acceptance. Не обходить её заменой pinned `/usr/bin/awg`, snapshot или manual ready.

## Foreign: подготовка одной командой

Из корня распакованного runtime bundle:

```sh
sudo ./scripts/bootstrap-foreign.sh --apply
```

При root shell `sudo` можно убрать. Скрипт запрашивает только публичные несекретные параметры: Foreign IP:443, RU public IP, IP:443 подходящего REALITY TLS target и его TLS hostname/SNI. Target оператор выбирает и проверяет независимо: поддержку TLS/REALITY и доступность эта команда не исследует. Documentation/benchmark/private IP и hostnames вместо literal endpoint не принимаются. Для IPv6 endpoint используются квадратные скобки. RU, Foreign и camouflage target должны быть разными публичными адресами.

Без `--apply` скрипт выполняет dry-run: не скачивает, не устанавливает, не генерирует credentials и не записывает файлы. С `--apply` устанавливает только Xray/Hysteria binaries, создаёт новый закрытый Foreign staging и проверяет Xray конфигурацию в режиме `run -test`. Ни один listener/service этим режимом не запускается. Hysteria `server` нельзя использовать как syntax check: он запускает runtime. Native Hysteria configuration/runtime acceptance отсутствует.

Первая конфигурация относится только к primary REALITY. Для Hysteria backup требуются отдельно подтверждённые hostname и certificate/key либо независимо принятый TLS pin; auto self-signed/Insecure не предлагаются. Private RU ingress и closed IPv4 network tools теперь готовятся отдельно по network-stand-runbook.md. Bootstrap по-прежнему не активирует сеть или cores; selector/TUN, current client issuance и real acceptance остаются открыты.

## Отдельные команды

```sh
./build/vpnctl core-plan --role foreign
./build/vpnctl core-plan --role ru
./build/vpnctl core-install --core xray
sudo ./build/vpnctl core-install --core xray --apply
sudo ./build/vpnctl core-install --core hysteria --apply
sudo ./build/vpnctl core-install --core sing-box --apply
sudo ./build/vpnctl core-status
```

Apply поддерживается только на Linux под root. Download/extraction ограничены по времени/размеру; archive и selected ELF binary проверяются независимо. Установка в фиксированный `/usr/bin` не перезаписывает другой бинарник. Повтор того же pin — идемпотентный результат. Если там уже есть отличающийся файл/линк или небезопасные permissions, команда останавливается; изучить existing installation отдельно, не удалять её автоматически. Установка нескольких ядер последовательная, не одна общая транзакция; успешное ранее установленное ядро сохраняется при следующем сбое.

`foreign-init` принимает те же четыре несекретных параметра, default dry-run. Только `--apply` создаёт новый private `/etc/family-vpn/foreign-staging` с `xray.json` и `ru-hop.json`. Credentials генерируются криптографически; файлы0600, каталог0700. Готовая пара не перезаписывается. После повторного запуска с существующим staging использовать `foreign-check`, а не создавать новую identity:

```sh
sudo ./build/vpnctl foreign-check
sudo ./build/vpnctl foreign-check --native-check
sudo ./build/vpnctl foreign-status
```

`ru-hop.json` — секретный fragment sing-box outbound для одного RU→Foreign primary hop. Это не user export, не pairing descriptor и не профиль кабинета. Его нельзя импортировать через `profile-import`, класть в portal DB, публичную папку, issue, чат, stdout или git. Переносить на RU только приватным operator workflow, согласованным отдельно; этот инструмент ничего не отправляет. Server private key остаётся только в Foreign config. Public/admin HTTP не читают staging; им не нужны root права, доступ к ядрам или новые ключи.

Проверка читает bounded fixed private pair и проверяет закрытую схему, exact generated bytes, соответствие private/public key и policy. Native check допускает только защищённый `/usr/bin/xray` с встроенным pin, фиксированные args `run -test`; ошибки subprocess не выводятся. Секреты, IP/SNI/config contents не попадают в JSON/error report. `native_syntax_validated` означает только успешный config-only parser invocation. Это не responding core/process/config revision, не установленный transport и не client proof; runtime/routing/client/ready остаются false.

## До запуска сети

Xray default outbound — blackhole; public egress Foreign разрешён только явным правилом для primary inbound и отдельным bounded DNS rule. Private/special/metadata и management addresses обоих VPS запрещены policy. Свободный Foreign egress — целевое окончание маршрута, не DIRECT fallback на RU. Domain routing/ForceIP не заменяют kernel guard при DNS rebinding. В pinned Xray26.3.27 `finalRules` ещё отсутствует, поэтому generator его не использует; even новые after-dial checks не доказывают отсутствие предварительного TCP handshake. Схема не принята для запуска на host namespace.

v0.28 подготовила RU ingress и закрытый IPv4 `vpn-data` kernel plan/native apply/readback code; отдельный workflow описан в [network-stand-runbook](network-stand-runbook.md). Следующий этап — реально проверить его на Linux: отсутствие доступа к SSH/кабинету/host/metadata и fail-closed при потере Foreign, включая IPv6. v0.29 реализует forwarding0 preservation и scoped Docker subset; их native acceptance, unprivileged core runtime/current client binding, selector backup, Android import/handshake/DNS/TCP/UDP и RAM/restart остаются открыты. Systemd/netns/firewall шаблоны не применять как проверенный deploy. Никакого fallback DIRECT или manual ready. После actual client/runtime proof переход состояния должен повторить все guards в одной audited writer transaction; core installation/config syntax этого не делают.

Результаты текущей локальной проверки и ограничения: `iteration-29.md`; история bootstrap: `iteration-26.md`. Production/pilot RC, native Linux execution и M1/G1 acceptance остаются открыты. Все generated credentials/private конфигурации исключены из source/runtime архивов.
