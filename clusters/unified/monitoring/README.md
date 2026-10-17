# Мониторинг unified — конфигурация подготовлена, ещё не применена

Нативные Kubernetes manifests без дополнительного оператора. Root Flux kustomization намеренно не изменён: подключить этот каталог отдельным шагом после Ansible prerequisites и runtime проверки приватных адресов. Все images закреплены тегом и manifest-list SHA256, полученным из официальных registries 2026-10-17.

| Компонент | Размещение | Memory request / limit на экземпляр | Хранение |
|---|---|---|---|
| Prometheus 3.15.0 | 2 VPS, required anti-affinity | 512 MiB / 1 GiB | По одному local PV 2 GiB, retention 7d **или** 1 GiB — что раньше |
| Alertmanager 0.34.1 | 2 VPS, required anti-affinity | 64 / 128 MiB | emptyDir 64 MiB, runtime retention 24h |
| kube-state-metrics 2.20.0 | 2 VPS, required anti-affinity | 64 / 192 MiB | Без persistent data |
| blackbox-exporter 0.29.0 | DaemonSet только на 2 VPS | 24 / 64 MiB | Без persistent data |
| node-exporter 1.12.1 | DaemonSet на всех 3 нодах | 32 / 128 MiB | Только чтение host metrics/textfile |

Сумма лимитов — около **1.5 GiB на каждой VPS**, домашняя нода — 128 MiB. Это лимиты, не измеренное потребление. Prometheus scrape раз в минуту, ограничение samples/body/labels, ограниченный набор kube-state/etcd metrics. Память, фактическую cardinality и рост WAL проверить после запуска. Два Prometheus независимо собирают те же targets: их local TSDB не реплицируются и не восстанавливают друг другу пробелы. Потеря VPS оставляет живой экземпляр; исчезнувшая локальная история сама не возвращается. PV Retain, данные не удаляются автоматически при удалении StatefulSet.

`bootstrap/ansible/monitoring.yml` с `monitoring_prepare_enabled=true` проверяет ownership, существующие listeners, реальные Node InternalIP против Tailscale IP, минимум 20 GiB свободного root reserve плюс 2 GiB для PV, затем создаёт каталоги. Не форматирует диски, не применяет Kubernetes manifests, не покупает storage. Local PV capacity 2 GiB — декларация для scheduler, **не filesystem quota**. Retention 1 GiB оставляет место для WAL, head и compaction, но не является строгим лимитом каталога; увеличение нагрузки требует повторного расчёта. Семь дней истории не гарантируются при достижении size retention. Root filesystem alerts защищают общий SSD наблюдением, не останавливают запись автоматически.

Все Services — внутренние, ingress/NodePort/public LB отсутствуют. node-exporter использует `hostNetwork` и bind **только `status.hostIP:9100`**, который prerequisite обязан подтвердить как VPN адрес. Для hostNetwork нельзя полагаться на обычную Kubernetes NetworkPolicy; проверить host firewall/Headscale ACL, private bind и невозможность подключения по публичному IP. В namespace обычные pod endpoints ограничены NetworkPolicy. Доступ к UI — через согласованный `kubectl port-forward`, не через публичный ingress.

Targets для нод обнаруживаются через Kubernetes API: разрешены имена `home`, `msk`, `fin`, используется их InternalIP. Адресов узлов и ключей в Git нет. Добавление четвёртой ноды требует изменения allowlist/target_limit и ожидаемого количества targets. Приватный Service CIDR в egress policy соответствует bootstrap `${SERVICE_CIDR}`; значение подставляет Flux. ServiceAccount Prometheus читает Node metadata и pods namespaces monitoring/garage через отдельные read-only Roles; не получает Secrets или полномочия писать в etcd.

etcd scrape идёт **HTTP GET `/metrics` на VPN IP:2381**, через отдельный HAProxy frontend bootstrap, который разрешает только этот метод и путь и обращается к local etcd metrics. WAN шифруется VPN. Здесь нет etcd client certificate: он мог бы давать избыточный доступ к данным. До включения scrape подтвердить frontend, firewall для Pod CIDR→2381 и недоступность 2381 с публичной сети. `up=0` этого endpoint означает отказ наблюдаемости, а не доказанную потерю etcd member. Метрики leader/fsync/quota — наблюдения; они не заменяют проверки quorum и реальные failover tests.

Каждый blackbox exporter на VPS проверяет Headscale `/health` и оба DERP `/derp/probe` с проверкой TLS и срока сертификата. Метка `probe_node` сохраняет источник, поэтому видны односторонние HTTPS блокировки. Успешный `/derp/probe` **не доказывает** пересылку DERP packets, STUN, прямой UDP путь, смену домашнего IP или переживание отказа coordinator. Эти тесты выполняются отдельно с согласованием; домашней точки blackbox здесь нет.

## Бэкапы, storage budgets и уведомления

Textfile collector читает `/var/lib/node_exporter/textfile_collector` без записи. Producer публикует файл атомарно и не вставляет секреты, filenames или object keys. Контракт для каждого реально настроенного backup:

```text
infra_backup_configured{component="headscale"} 1
infra_backup_last_success_timestamp_seconds{component="headscale"} <Unix timestamp>
infra_backup_last_attempt_success{component="headscale"} <0 or 1>
infra_backup_max_age_seconds{component="headscale"} 3600
```

Если один component имеет несколько направлений, producer добавляет ко всем четырём сериям одинаковый label `destination` (например, `macbook`); alert joins включают `instance,component,destination`. Отсутствующий label остаётся совместимым с первым standby producer.

`configured=1` устанавливается после настройки конкретного pipeline, не этим мониторингом. До первого успеха timestamp=0; неудача сохраняет прошлый timestamp и выставляет attempt=0. Headscale producer согласован отдельно на MSK, период 15 минут, допустимый возраст 1 час. Локальная coordinator recovery copy и offsite backup имеют разный смысл; успех копирования не подменяет проверку восстановления. **MacBook не публикует метрики в этот стек**: расписание и live status проверяются отдельным backup runner, этот каталог не создаёт для него метрики успеха. Для остальных компонентов до настройки pipeline метрики отсутствуют; это неизвестный статус, не успешный backup.

Аналогичный необязательный storage contract: `infra_storage_configured`, `infra_storage_used_bytes`, `infra_storage_budget_bytes` с одинаковыми `component` и target labels. Правило quota включается только при configured=1; producer здесь не создаётся. Нет предположения о развёрнутом Swift/Garage или о переносе данных.

Alertmanager сейчас использует **пустой receiver** `pending-user-destination`: события видны внутри UI, внешней доставки нет. Информационный alert явно показывает это состояние. После ответа пользователя добавить выбранную интеграцию с runtime/SOPS Secret, разрешённый egress и end-to-end тест доставки; тогда удалить `NotificationDeliveryNotConfigured`. Две Alertmanager реплики обмениваются состоянием, Prometheus отправляет в обе и удаляет replica label для deduplication. Одновременный restart обеих Alertmanager теряет silences/notification log из emptyDir; это принятый начальный компромисс малых SSD, не durable alert history.

При потере всего кластера этот мониторинг не сможет уведомить пользователя. Независимый внешний check/receiver пока не настроен. История метрик не является backup данных приложений.

## Проверка и оставшаяся приёмка

Локально проверены `kubectl kustomize`, Ansible syntax, Prometheus 3.15.0 `promtool check config --syntax-only`/`check rules`, Alertmanager 0.34.1 `amtool check-config`, структура manifests, закрепление images, размеры ресурсов и отсутствие public Services/Secrets. Validator binaries скачаны из официальных releases и проверены по SHA256. Это не server-side dry run и не runtime evidence.

После применения проверить: обе VPS имеют по Prometheus/Alertmanager/KSM/blackbox; все три node-exporter доступны только приватно; PVC Bound к разным VPS; Node/etcd targets 3/3; шесть blackbox probes; root filesystem labels; правила loaded; реальные Headscale counters; RAM/disk/WAL growth; Alertmanager mesh. Подтвердить невозможность POST и произвольных paths через etcd metrics frontend. Проверку отказа нод и доставки внешнего уведомления провести отдельным согласованным шагом; результаты фиксировать отдельно от конфигурации.

При подсчёте requests/limits сначала убрать дубли двух kube-state-metrics, например `sum by (node, resource) (max by (namespace, pod, container, node, resource) (kube_pod_container_resource_requests))`; для limits заменить имя метрики на `kube_pod_container_resource_limits`. Отсутствующий container limit означает отсутствие ограничения, а не нулевое потребление. Эти суммы не заменяют Kubernetes scheduler accounting для init containers/Pod overhead и фактический `MemAvailable` узла.

Источники: [Prometheus releases](https://prometheus.io/download/), [storage/retention](https://prometheus.io/docs/prometheus/latest/storage/), [kube-state-metrics 2.20.0](https://github.com/kubernetes/kube-state-metrics/releases/tag/v2.20.0), [DERP HTTP probe](https://github.com/tailscale/tailscale/blob/main/cmd/derper/derper.go).

Сервисная подсеть берётся из `${SERVICE_CIDR}` через обязательный root Flux `postBuild.substituteFrom` runtime ConfigMap `flux-system/unified-network`. Перед локальной проверкой NetworkPolicy подставить значение из защищённого inventory.

## PostgreSQL

Host timer каждые 120 секунд выполняет ограниченные read-only SQL/размерные проверки и атомарно публикует `infra_postgres_*` через node-exporter textfile. `collect_timestamp_seconds` относится к попытке, `last_success_timestamp_seconds` обновляется только после всей успешной выборки. При ошибке collector выставляет `collect_success=0` и не выдаёт прошлые SQL-значения за свежие; отсутствие/просрочка метрик требуют проверки независимо от состояния базы.

Порог physical data: предупреждение18GiB, critical21GiB при логическом бюджете24GiB. WAL6/8GiB, потерянные slots, запас retained WAL<1GiB, replay lag>16MiB и TLS<14days контролируются отдельно. `max_slot_wal_keep_size` действует с checkpoint и не является дисковой quota. Сумма наблюдаемых primary должна быть1; основной сервер должен видеть две streaming async replicas. Во время поэтапной начальной установки предупреждение о недостающих репликах ожидаемо; после включения всех трёх требует разбирательства. Эти метрики не доказывают отсутствие split-brain вне доступной наблюдателю части сети, успешный failover или нулевой RPO.

## Public DNS

Job `public-dns` читает CoreDNS9153 и health-agent9080 на двух VPS; namespace stack выдаёт Prometheus только read-only Pod discovery. Проверяются актуальность probes и синхронизации zone, serial divergence, API errors и доступность обоих targets. Проверка отсутствия двух агентов включается только при существующем desired DaemonSet. HTTP/metrics success не доказывает делегирование публичного домена, прохождение внешнего DNS-трафика или переключение ingress: это отдельные внешние проверки.
