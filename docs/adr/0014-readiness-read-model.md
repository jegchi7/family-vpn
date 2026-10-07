# ADR-0014 · Read-only readiness diagnostics

Статус: принят для локального среза v0.16.0 · 05.10.2026. Родители: KUK-5/M1-02, DEV-08. G1 и readiness transition открыты.

## Решение

Сохранённый observation ledger из v0.15 остаётся историческими метаданными. Добавить keyless trusted CLI read model current owner/device/profile/generation/revision с явными blockers. Он не может выдавать положительное разрешение: profile secret/client acceptance не проверяются, immutable native Result и fencing не восстанавливаются из DB rows.

Явные target IDs — canonical32-byte IDs, ordinary owner active. Binding/state и observation читаются в одной read transaction, old expected generation/revision дают conflict. Latest owner/profile metadata выбирается независимо от результата; newest mismatch/expired/stale/future record не скрывается older match. UTC fractional ordering нормализуется. Unknown field names/invalid ID/source/timestamp/TTL и contradictory matched/fields отвергаются без raw output.

CLI не загружает profile key, не читает ciphertext bytes, не вызывает tool/network и не мигрирует DB. `stored_export` означает только наличие ciphertext; fresh stored readback не означает secret/runtime/client verification. Snapshot и native source различаются. Private values и arbitrary DB strings в DTO не переносятся. Нет HTTP/repository exposure.

## Последствия

Оператор получает повторяемый статус и next blockers при отсутствии native inputs. Это завершённый local diagnostic slice, не исполнение полного audited readiness transition. Healthy-looking ledger никогда не устанавливает ready/installed_revision и не делает download допустимым. Нативный/runtime/client путь, concurrent fencing, AEAD revalidation и atomic transition должны быть реализованы и приняты отдельно. Current schema6/4/1 без миграции; code tests с synthetic ledger не заменяют operational acceptance.
