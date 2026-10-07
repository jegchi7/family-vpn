# PRE-01 / PRE-02: обследование перед интеграцией

Не заполнено: к действующим VPS в этой итерации не подключались. Секреты и полные клиентские конфиги в этот файл не вставлять.

| Поле | RU | Foreign |
|---|---|---|
| OS/kernel/architecture | UNKNOWN | UNKNOWN |
| SSH/console recovery проверен | UNKNOWN | UNKNOWN |
| Версии AWG/Xray/sing-box | UNKNOWN | UNKNOWN |
| systemd / Docker owners | UNKNOWN | UNKNOWN |
| Занятые TCP/UDP listeners | UNKNOWN | UNKNOWN |
| CIDR/routes/netns conflicts | UNKNOWN | UNKNOWN |
| Firewall owner + sanitized snapshot | UNKNOWN | UNKNOWN |
| Peer count + public fingerprints | UNKNOWN | UNKNOWN |
| Фактический egress IP | UNKNOWN | UNKNOWN |
| Backup + restore rehearsal | UNKNOWN | UNKNOWN |

Обследование выполняется read-only; результат sanitizer-reviewed. До network changes подтвердить management recovery и свежий backup. Добавить даты, исполнителя, версии и конфликты; отсутствие ошибки команды не означает приемку VPN.
