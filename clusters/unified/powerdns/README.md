# PowerDNS: локальное чтение DNS и отдельный API

Компонент использует PostgreSQL `unified-postgres` и не создаёт базу, роли,
секреты или публичные маршруты. Корневая Kustomization поддерживает его
как изолированный сервис; публичные зоны и legacy writers подключаются отдельно.

`powerdns-readers` запускается на каждой VPS и читает только её PostgreSQL
через отдельный Service в namespace `database`. `publishNotReadyAddresses`
сохраняет этот путь, даже когда Patroni исключил отстающую реплику из обычных
Service endpoints. Внешний CoreDNS сможет обращаться к `10.120.53.54:53`;
`internalTrafficPolicy: Local` сохраняет локальность на каждой VPS.

Две реплики `powerdns-api` размещаются на разных нодах, с предпочтением дома.
Они подключаются к существующему RW Service и проверяют `target_session_attrs=read-write`.
Предпочтительный PostgreSQL primary и fencing настраивает Patroni. Здесь
нет второго механизма выбора primary. API не опубликован через ingress,
hostPort или NodePort; DNS-порт API слушает только loopback.

## Подготовка базы и секретов

До первого применения нужны:

- База `powerdns`, владелец `powerdns_owner` без LOGIN; схема из официального
  [тега auth-5.1.4](https://raw.githubusercontent.com/PowerDNS/pdns/auth-5.1.4/modules/gpgsqlbackend/schema.pgsql.sql).
  Bootstrap должен сверить структуру и владельца, а не применять DDL к неизвестной базе.
- Ограничение `CHECK (type = 'NATIVE')` на `domains`: API не должен создавать
  режимы PRIMARY, SECONDARY или каталогов. Отключение `primary`/`secondary`
  в PowerDNS само по себе не ограничивает значения в таблице.
- `powerdns_reader`: CONNECT, USAGE схемы и SELECT только на `domains`,
  `records`, `domainmetadata`; без владельческих прав, DML, DDL, доступа к
  `cryptokeys`/`tsigkeys` и без членства в привилегированных ролях.
- `powerdns_api`: CONNECT, USAGE схемы, DML на семи таблицах официальной схемы,
  USAGE/SELECT последовательностей; без владельческих прав, CREATE и TRUNCATE.
- Небольшая зона `health.test` вида NATIVE с корректным SOA для readiness;
  она не предназначена для публикации в CoreDNS. Начальная установка должна
  содержать только эту зону до отдельной проверки переноса рабочих данных.
- Два Secrets в `dns-powerdns`, созданные вне Git:

| Secret | Ключи |
| --- | --- |
| `powerdns-reader-runtime` | `credentials.conf`, `ca.crt` |
| `powerdns-api-runtime` | `credentials.conf`, `ca.crt` |

Bootstrap резервирует для health-зоны domain ID `2000000000` и record IDs
`2000000000..2000000002`, не сдвигая последовательности. Импорт обязан отклонять
коллизии с этими идентификаторами, сверять полное содержимое seed и сохранять
исходные `last_value`/`is_called` каждой последовательности. Нельзя выставлять
`setval(MAX(id))` с учётом резервных строк или перематывать последовательность
назад после начала записи. Отрицательный domain ID использовать нельзя:
PowerDNS считает `-1` признаком неизвестной зоны.

В `credentials.conf` reader допускается только `gpgsql-password=...`.
У API дополнительно нужны `api-key=...` и `webserver-password=...`.
Для непрерывности старого writer переносится его действующий API key;
пароль webserver генерируется отдельно. Значения должны занимать одну строку,
без пробелов, `#` и обратной косой черты. Файл не надо выводить в терминал,
включать в команды, ConfigMap или коммитить. Secret не содержит полного
`pdns.conf`: параметры доступа, кэшей и безопасности остаются в Git.

TLS использует `sslmode=verify-full`. В существующем сертификате есть имя
`unified-postgres.database.svc`, но нет имён новых локальных Services.
Поэтому `gpgsql-host` сохраняет сертифицированное имя, а `hostaddr` получает
стабильный ClusterIP выбранного Service при старте. `ca.crt` — CA этого
PostgreSQL. Не заменять проверку на `require`/`verify-ca` и не использовать
Pod IP вместо стабильного Service. Пересоздание Service с другим ClusterIP
требует контролируемого перезапуска соответствующего PowerDNS.

### Запуск bootstrap

`bootstrap/ansible/powerdns-prepare.yml` запускается на всех трёх узлах,
без `--limit`. Он проверяет идентичность кластера, сохраняет одни и те же
креденциалы на всех узлах и создаёт namespace/Secrets до применения компонента.
Он не включает workloads, публичный DNS или перенаправление существующих writers.

Вне репозитория подготовить принадлежащие текущему пользователю обычные файлы
с правами `0600`: файл действующего legacy API key и private extra-vars.
API key передавать через файл, без значения в argv, shell history или выводе.
Extra-vars содержат явные проверенные значения:

```yaml
powerdns_prepare_enabled: true
powerdns_cluster_uid: '<UID namespace kube-system нужного кластера>'
powerdns_ca_sha256: '<SHA256 содержимого /etc/kubernetes/pki/ca.crt>'
powerdns_api_key_file: '/absolute/private/path/legacy-powerdns-api-key'
```

```sh
cd bootstrap/ansible
/tmp/infra-unified-venv/bin/ansible-playbook powerdns-prepare.yml --syntax-check
/tmp/infra-unified-venv/bin/ansible-playbook powerdns-prepare.yml -e @/absolute/private/path/powerdns-vars.yml
```

Recovery bundle: `/etc/infra-flux/powerdns-runtime.json`, root, `0600`, на
каждом узле. Это чувствительный файл: он нужен для восстановления исходных
паролей и API identity, его место — в зашифрованных копиях, не в Git.
Повторный bootstrap сохраняет существующую identity и останавливается при
несовпадении bundle/Secret/базы. При утрате исходного bundle сначала восстановить
его из доверенной копии; не генерировать новые пароли поверх работающей базы.
Три локальные копии этого файла не заменяют независимый backup базы и секретов.

## Проверка и включение

1. Проверить свободный `10.120.53.54` и единственный PostgreSQL endpoint
   правильного `member-site` у каждого локального Service. Их namespace
   должен остаться `database`; у этой Kustomization намеренно нет общего
   `namespace` override.
2. Применить подготовленный bootstrap базы/Secrets и отдельно компонент.
   Проверить readonly SQL-права reader, запрет изменения схемы API-роли,
   PostgreSQL TLS и реальные grants на точном образе. Если PowerDNS запросит
   лишнюю таблицу, сначала выяснить путь выполнения; не выдавать reader все права.
3. У каждой reader-реплики проверить SOA `health.test` с AA по UDP и TCP,
   отказ AXFR/UPDATE/рекурсии, отсутствие публичных портов и работающий `/metrics`.
   API readiness дополнительно выполняет read-only `pdnsutil zone list health.test`
   через новое соединение с требованием writable PostgreSQL.
4. Подключить разрешённый writer через private Service
   `powerdns-api.dns-powerdns.svc:8081`. NetworkPolicy требует одновременно
   label `infra.shanginn.io/powerdns-client: 'true'` на namespace **и** pod
   клиента; его собственная egress policy тоже должна разрешать TCP/8081.
   Старые writer/API остаются на прежнем пути до отдельного согласованного
   переключения источника записи.
5. Перенос рабочих зон должен сохранять все действующие изменения writer.
   Проверить полноту RRsets/TTL/метаданных, NATIVE, отсутствие LUA/ALIAS,
   DNSSEC/TSIG и непредусмотренных ключей. Разовая устаревающая копия базы
   не является завершённым переносом. Сделать canary ADD/DELETE через writer
   и подтвердить видимость и удаление на обоих reader по UDP/TCP.
6. Только затем добавить точные рабочие зоны в публичный CoreDNS и его
   egress policy на reader TCP/UDP5353. Не направлять весь неизвестный DNS
   suffix в PowerDNS и не публиковать `health.test`.

`powerdns-readers` использует OnDelete: обновлённый образ/ConfigMap не
перезапускает публичный DNS backend автоматически. Применять замену по
одной VPS с проверкой второй и последующей проверкой ответов. API обновляется
по одному pod; PDB сохраняет одну реплику при добровольном disruption.
PDB не предотвращает потерю ноды или принудительное удаление pod.

Временный [VPN-мост для старых клиентов](legacy-bridge/README.md) включён
в конфигурацию. Перед reconciliation нужен отдельный private ConfigMap
`flux-system/unified-legacy-dns`. API использует отдельный generated ConfigMap
`powerdns-api-config`, а reader сохраняет исходный `powerdns-config`. Изменение
разрешённых API-адресов сопровождается новым `POWERDNS_API_ACCESS_REVISION`:
Flux подставляет переменные после вычисления hash ConfigMap, поэтому одной
подстановки недостаточно для перезапуска процесса с новой конфигурацией.

## Наблюдение и ограничения

Все packet/query/negative/zone/metadata/key caches отключены. Новый объект
становится виден после PostgreSQL replay; кэши рекурсивных резолверов и TTL
записей остаются отдельными факторами. При разделении сети local reader
продолжает отвечать последним доступным состоянием, если локальная БД читается.
Это сознательно допускает устаревшие записи; readiness не доказывает свежесть.
При недоступной локальной БД reader становится NotReady и не перенаправляется
на другую VPS. Если оба локальных reader недоступны, сам этот компонент не
обеспечивает третий публичный DNS endpoint.

Асинхронная репликация может потерять последние подтверждённые API изменения
при потере primary. Защита от двух writable primary остаётся обязанностью
Patroni/fencing; `target_session_attrs` не заменяет её. Безопасное автоматическое
возвращение primary домой также не выполняется этим компонентом.

Ресурсы: каждый процесс PowerDNS запрашивает 25m CPU/64Mi RAM, мост метрик —
5m/16Mi. По кластеру четыре процесса с мостами: 120m/320Mi requests;
DB/cache нагрузку, фактическую RAM и число соединений надо проверить перед
публикацией и после переноса. Лимиты не являются оценкой необходимой ёмкости.

Метрики `pdns_auth_*` доступны через фиксированный `/metrics` на порту 9081.
Существующий job `application-metrics` обнаруживает label
`infra.shanginn.io/metrics: 'true'` и именованный порт `metrics` без отдельной
правки Prometheus. Мост не проксирует API/произвольные URL и не отдаёт ключи;
креденциалы HTTP нужны только для его локального обращения к native webserver.
Нужно проверить четыре targets, ошибки backend/SERVFAIL, очереди, UDP/TCP
запросы и ресурсы; отдельные PowerDNS alert rules и публичные пробы рабочих
зон добавляются при активации. Существующие PostgreSQL replication/WAL alerts
не доказывают DNS-паритет: нужны сравнение SOA/RRsets и canary.

## Версии и локальная проверка

Закреплён официальный `powerdns/pdns-auth-51:5.1.4` по digest multiarch manifest
`sha256:bb5b1c133bcca1dd455075321de7d55db4945a8d7f2ba23339e3c7bbe416b205`.
Источник — [реестр издателя](https://hub.docker.com/r/powerdns/pdns-auth-51/tags)
и [changelog 5.1.4](https://doc.powerdns.com/authoritative/changelog/5.1.html).
Образ содержит Python, `pdns_control` и `pdnsutil`; запуск идёт напрямую,
минуя wrapper, генерирующий конфигурацию из environment.

```sh
python3 -B clusters/unified/powerdns/test_runtime.py
kubectl kustomize clusters/unified/powerdns > /tmp/powerdns-rendered.yaml
```

Эти проверки не заменяют запуск точного образа с новой базой, проверку
разрешений, TLS, NetworkPolicy, API и отказов. Документация параметров:
[PostgreSQL backend](https://doc.powerdns.com/authoritative/backends/generic-postgresql.html),
[HTTP API](https://doc.powerdns.com/authoritative/http-api/index.html),
[официальный Dockerfile](https://github.com/PowerDNS/pdns/blob/auth-5.1.4/Dockerfile-auth).
