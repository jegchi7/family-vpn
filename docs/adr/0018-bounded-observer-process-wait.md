# ADR-0018 · Ограничение ожидания observer subprocess

Статус: принято для локального KUK-5, v0.20.0. Native AWG/Xray/client acceptance открыта.

`exec.CommandContext` по умолчанию завершает только непосредственный процесс. `Cmd.Wait` ждёт EOF из каналов stdout/stderr; потомок может держать эти каналы открытыми даже после завершения родителя. Поэтому прежний timeout4s не ограничивал весь `Run`.

Оба Linux adapters используют общий internal observerexec.Run: verified executable descriptor через /proc/self/fd/3, прежние fixed commands/allowlisted args/environment, timeout4s, новая отдельная process group. Context cancellation посылает SIGKILL группе. WaitDelay200ms ограничивает ожидание каналов после context cancellation или выхода родителя. ErrWaitDelay также завершает оставшихся участников группы. Ошибка не становится успешным readback: caller очищает накопленный bounded buffer и возвращает прежний safe ErrRuntime.

Это ограничение ожидания и очистка обычных потомков, не sandbox/изоляция hostile root-owned executable. Потомки могут выйти из группы; WaitDelay всё равно закрывает родительские каналы и возвращает ошибку. Нельзя обещать real-time deadline или полное process containment. File ownership/hash pin, exact-byte scoped observation/TTL и отсутствие ready/client acceptance сохраняются.

Реальные локальные helper subprocess tests воспроизводят inherited stdout после успешного parent exit, отмену живой группы, descriptor execution/nonzero exit/cancelled start. Tests используют shell только как тестовую программу; production не вызывает shell/PATH lookup и не принимает arbitrary tool path. AWG/Xray binary/core/API/client в этих tests не запускаются.

Primary contract: [Go os/exec](https://pkg.go.dev/os/exec#Cmd), sections Cancel/WaitDelay; [standard-library implementation](https://go.dev/src/os/exec/exec.go). Checked with pinned project Go1.27.1.
