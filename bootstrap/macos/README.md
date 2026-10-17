# Резервные копии инфраструктуры на Mac

`backup.py` получает согласованный SQLite snapshot, Noise key, конфигурацию, ACL, DERP-карту и TLS identity активного Headscale через существующий SSH-алиас. SQLite копируется через Backup API в ограниченный `/run` tmpfs; tar передаётся потоком. На серверном SSD полный архив не создаётся. На Mac restic шифрует данные в `~/Backups/infra-unified`.

`export-node.py` работает только с новым кластером, у которого совпадают маркер `infra-flux/ansible/kubeadm` и SHA-256 CA. Для etcd он проверяет здоровье локального участника, выполняет `etcdctl snapshot save` через его pod, затем `etcdutl snapshot status`. Временно используется отдельный UUID-каталог в `/var/lib/etcd`; удаляется только этот каталог в `finally`, данные участника не затрагиваются. Snapshot, PKI с CA-ключами и сохранённая конфигурация kubeadm передаются потоком. Перед созданием проверяются размер БД и свободное место. Default limit — 256 MiB. При превышении лимита копия не объявляется успешной.

Для etcd источники пробуются последовательно: Москва, затем Финляндия. Частичный stream не считается копией. Отдельные jobs `node-msk`, `node-fin`, `node-home` сохраняют `/etc/infra-flux`, `/etc/infra-overlay`, `/etc/kubernetes` соответствующего узла. Они содержат ключи и учётные данные и хранятся только внутри шифрованного restic. Это конфигурации нового кластера, не копия всех пользовательских файлов серверов.

На standby с маркером `infra-flux/ansible/headscale-backup` node-config дополнительно включает ровно четыре файла из `/var/lib/infra-headscale-recovery`: `identity.age`, `pull_ed25519`, `pull_ed25519.pub`, `known_hosts`. Это позволяет восстановить шифрование и ограниченный transport key после потери standby. Каталог snapshots и другие данные `/var/lib` в этот job не входят; настройки recovery уже входят в `/etc/infra-*`.

Параметр `offline_restore_check: true` у job etcd дополнительно запускает `etcdutl snapshot restore` в новом подкаталоге того же UUID scratch. Проверяются встроенный hash snapshot, создание базы и WAL, число ключей и увеличение revision на миллиард с `--mark-compacted`. `etcd` не запускается, сетевые порты не открываются, membership действующего кластера не меняется. Проверочные файлы удаляются вместе с собственным scratch. На это требуется свободное место не меньше трёх лимитов snapshot. Это проверка восстановления структуры данных; отдельный запуск восстановленного Kubernetes в неё не входит.

Настройте локальную копию `config.example.json`. Включите `etcd` и node-config jobs после готовности нового кластера. Адреса и SSH-порты остаются в `~/.ssh/config`; конфигурацию с частными параметрами и секреты не добавляйте в Git. Установите закреплённый restic **0.19.1**, затем выполните от обычного пользователя Mac:

```sh
python3 bootstrap/macos/install.py --config /path/to/private-backup.json
python3 "$HOME/Library/Application Support/infra-flux/bin/backup.py" run --force
```

После успешной первой копии включите расписание:

```sh
python3 bootstrap/macos/install.py --config /path/to/private-backup.json --schedule
```

LaunchAgent запускается в 03:30 по времени Mac, при загрузке пользовательской сессии и каждый час для пропущенного запуска. В пределах одного суточного окна успешная копия повторно не создаётся. Mac должен быть включён, пользователь должен войти в систему, а SSH-ключ — работать без интерактивного запроса. Ноутбук автоматически не будится. При недоступном сервере или недостатке места сохраняются предыдущие копии и выполняется следующая попытка.

Пароль генерируется локально в `~/Library/Application Support/infra-flux/restic-password` с правами `0600`; каталог имеет права `0700`. Пароль не передаётся в командной строке. Отдельно сохраните этот файл в защищённом месте: потеря одновременно Mac и пароля делает архив недоступным. Копия на этом Mac переживает потерю VPS; потерю самого Mac она не переживает. Installer не меняет настройки FileVault и не покупает хранилище.

После каждого snapshot runner восстанавливает все файлы во временный приватный каталог и проверяет SHA-256, identity и комплектность. Для Headscale дополнительно выполняется `PRAGMA integrity_check`; для etcd при включённом `offline_restore_check` требуется запись об успешной проверке восстановления. Затем plaintext удаляется. Только такой snapshot получает тег `verified`. Ошибочные незавершённые проверки сохраняют тег `pending`; они не участвуют в retention. Restic отменяет создание snapshot, если SSH/exporter завершился ошибкой. Это использует [`--stdin-from-command`](https://restic.readthedocs.io/en/stable/040_backup.html#reading-data-from-a-command).

Хранятся 7 суточных, 4 недельных и 6 месячных проверенных snapshot на каждый источник. До удаления старых snapshot проверяется структура репозитория; раз в неделю дополнительно читаются все зашифрованные данные и освобождаются неиспользуемые блоки. Политика применяется только к тегам `infra-unified,verified`. Проверка содержимого репозитория описана в [документации restic](https://restic.readthedocs.io/en/stable/045_working_with_repos.html#checking-integrity-and-consistency).

Состояние находится в `~/Library/Application Support/infra-flux/backup-status.json`: отдельные время успеха и snapshot ID, последняя попытка, результат и тип ошибки. При ошибке runner пытается показать локальное уведомление macOS. Разрешение уведомлений и доступность пользовательской сессии влияют на его показ; JSON остаётся источником статуса. Репозиторий и старые snapshots не удаляются при ошибке.

## Проверка и восстановление

Для команд restic установите пути без вывода пароля:

```sh
export RESTIC_REPOSITORY="$HOME/Backups/infra-unified"
export RESTIC_PASSWORD_FILE="$HOME/Library/Application Support/infra-flux/restic-password"
restic snapshots --tag infra-unified,verified
python3 "$HOME/Library/Application Support/infra-flux/bin/backup.py" verify headscale --snapshot SNAPSHOT_ID
restic dump SNAPSHOT_ID /headscale.tar > /path/to/private-restore/headscale.tar
```

Каталог восстановления заранее создайте с правами `0700`, примените `umask 077`. Архив содержит приватные ключи. Перед восстановлением Headscale остановите и надёжно исключите запуск прежнего координатора. Сохраните прежнее DNS-имя, адресный префикс и Noise key. Восстановите `db.sqlite`, `noise_private.key`, TLS и конфигурацию на остановленный standby, проверьте владельцев и права, затем вручную активируйте один координатор и переключите DNS. Не запускайте одновременно два экземпляра с одной или разными базами. После переноса измените `ssh_aliases` в локальной конфигурации резервного копирования и повторите установку.

Для etcd выберите проверенный snapshot job `etcd` и извлеките `/etcd.tar`. Внутри находятся `etcd/snapshot.db`, PKI и сохранённая конфигурация. Восстановление потерянного etcd-кластера выполняется `etcdutl snapshot restore` соответствующей версии в новые каталоги с явно заданными именами и peer URLs всех новых участников; старые участники должны быть остановлены. Для Kubernetes требуется bump revision и mark compacted, чтобы сбросить старые watch-кеши. Точные параметры зависят от выбранной топологии восстановления: следуйте [официальной инструкции etcd](https://etcd.io/docs/v3.6/op-guide/recovery/). Не подменяйте live `/var/lib/etcd` файлом snapshot.

PostgreSQL и пользовательские файлы приложений здесь ещё не подключены. Их нельзя объявлять защищёнными этими jobs. Для PostgreSQL необходим согласованный exporter после развёртывания primary и проверка его восстановления.
