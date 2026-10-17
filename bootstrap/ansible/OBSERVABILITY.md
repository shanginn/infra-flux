# Подготовка PostgreSQL, Garage и секретов приложений

`observability.yml` запускается на полном inventory `unified` из трёх нод.
Изменения делает только при `observability_prepare_enabled: true`, вне check mode,
с явно указанными `observability_cluster_uid` и `observability_ca_sha256`.
Private inventory/vars и результаты исполнения хранятся вне Git.

```sh
ansible-playbook -i "$inventory" bootstrap/ansible/observability.yml -e "@$vars"
```

По умолчанию action `prepare`. Он проверяет три Ready-ноды, три готовых PG/Garage
и единственный PostgreSQL primary дома. Создаёт DB/роли `grafana` и `glitchtip`,
Garage bucket `glitchtip` с квотой 1 GiB/100000 объектов, ограниченный S3 key и
три runtime Secret. Даёт существующему backup key read-only доступ к новому bucket.
Роли не имеют superuser/CREATEDB/CREATEROLE/REPLICATION, лимиты соединений 12/32.
Первый пользователь GlitchTip создаётся отдельным migration Job, не этим playbook:
см. [error-tracking](../../clusters/unified/error-tracking/README.md).

## Повторный запуск и восстановление

Источник секретов — root-owned mode0600 `/etc/infra-flux/observability-runtime.json`
на MSK. Playbook сохраняет тот же bundle на остальных нодах для зашифрованных
бэкапов. Пароли, signing keys, S3 identity и PostgreSQL CA существующих копий
должны совпадать: разные данные не заменяются автоматически. При потере MSK
сначала восстановить исходный bundle из проверенной копии/backup. Нельзя просто
удалить state и повторить bootstrap: уже существующие Secrets запрещают новую
генерацию, а существующая копия на другой ноде блокирует пустой MSK.

Существующие DB/роли проверяются по owner/comment, привилегиям, connection limit
и соответствию сохранённого пароля SCRAM-верификатору. Пароль не сбрасывается.
Existing Secret должен точно соответствовать bundle; CA/key drift требует
отдельного согласованного обслуживания. Helper принимается только с точным
reviewed hash; строка owner внутри произвольного файла недостаточна.

Создание bucket/key сначала фиксирует intent. Если ответ потерян, playbook
останавливается: проверить точное имя/ID и собственный state, не создавать
дубликат. Аналогично незавершённое создание DB без ownership comment требует
разбора; чужие DB/роли не принимаются автоматически. Secret значения и полный
bundle никогда не выводятся в журнал; рабочие операции с ними используют `no_log`.

## Добавление только connect_timeout к существующему GlitchTip URL

Fresh bootstrap сразу задаёт `connect_timeout=5`. Legacy bundle сохраняет старый
URL до отдельного действия; обычный prepare не меняет существующий Secret.

1. С теми же private vars задать `observability_action: inspect-glitchtip-timeout`.
   Это только чтение, без установки helper или копирования bundle. Сохранить
   выданные `secret_uid`, `secret_resource_version`, `secret_data_sha256`.
2. После review задать `observability_action: reconcile-glitchtip-timeout` и:

   ```yaml
   observability_timeout_review:
     expected_secret_uid: <secret_uid из inspection>
     expected_secret_resource_version: <secret_resource_version из inspection>
     expected_secret_data_sha256: <secret_data_sha256 из inspection>
   ```

   Единственный JSON Patch проверяет UID, resourceVersion и **все** исходные data,
   затем меняет только `data.DATABASE_URL`. Пароль, hostname, CA, остальные query
   параметры, signing/S3 keys и другие Secrets остаются прежними.
3. Intent сохраняется до dispatch. При потере ответа повторный запуск с тем же
   review только читает результат и никогда не отправляет patch повторно.
   Если результат не подтверждён, intent остаётся; требуется отдельный разбор.
   Inspection возвращает `resume_review` исходного intent для такого продолжения.
4. После подтверждённого readback обновлённый bundle копируется на все три ноды.
   Pods не перезапускаются. Env уже запущенного GlitchTip остаётся прежним до
   отдельного контролируемого rollout; не считать изменение Secret доказательством
   применения таймаута работающим приложением.

DB/Secret preparation не доказывает доступность UI, отправку ошибок, SMTP или
свежесть backup. После развёртывания нужны native PostgreSQL TLS checks, S3 canary,
SDK→worker→DB→UI, проверка закрытой регистрации и реальное восстановление backup.
Локальные проверки: `python3 bootstrap/ansible/files/test_observability_prepare.py`
и `ansible-playbook --syntax-check` с private inventory.
