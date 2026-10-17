# Мониторинг unified

Нативные Kubernetes manifests без дополнительного оператора. Каталог подключается через root Flux после Ansible prerequisites и проверки приватных endpoints. Новые прямые kubelet/cAdvisor jobs требуют завершённой выдачи serving TLS на всех трёх узлах до применения этого изменения. Host detail collector также устанавливается на все три узла до включения его missing-metrics alert. Все images закреплены тегом и manifest-list SHA256, полученным из официальных registries 2026-10-17.

| Компонент | Размещение | Memory request / limit на экземпляр | Хранение |
|---|---|---|---|
| Prometheus 3.15.0 | 2 VPS, required anti-affinity | 512 MiB / 1 GiB | По одному local PV 2 GiB, retention 7d **или** 1 GiB — что раньше |
| Alertmanager 0.34.1 | 2 VPS, required anti-affinity | 64 / 128 MiB | emptyDir 64 MiB, runtime retention 24h |
| kube-state-metrics 2.20.0 | 2 VPS, required anti-affinity | 64 / 192 MiB | Без persistent data |
| blackbox-exporter 0.29.0 | DaemonSet только на 2 VPS | 24 / 64 MiB | Без persistent data |
| node-exporter 1.12.1 | DaemonSet на всех 3 нодах | 32 / 128 MiB | Только чтение host metrics/textfile |

Сумма лимитов — около **1.5 GiB на каждой VPS**, домашняя нода — 128 MiB. Это лимиты, не измеренное потребление. Prometheus scrape раз в минуту, ограничение samples/body/labels, ограниченный набор kube-state/etcd metrics. Память, фактическую cardinality и рост WAL проверить после запуска. Два Prometheus независимо собирают те же targets: их local TSDB не реплицируются и не восстанавливают друг другу пробелы. Потеря VPS оставляет живой экземпляр; исчезнувшая локальная история сама не возвращается. PV Retain, данные не удаляются автоматически при удалении StatefulSet.

`bootstrap/ansible/monitoring.yml` с `monitoring_prepare_enabled=true` проверяет ownership, существующие listeners, реальные Node InternalIP против Tailscale IP, минимум 20 GiB свободного root reserve плюс 2 GiB для PV, затем создаёт каталоги. Не форматирует диски, не применяет Kubernetes manifests, не покупает storage. Local PV capacity 2 GiB — декларация для scheduler, **не filesystem quota**. Retention 1 GiB оставляет место для WAL, head и compaction, но не является строгим лимитом каталога; увеличение нагрузки требует повторного расчёта. Семь дней истории не гарантируются при достижении size retention. Root filesystem alerts защищают общий SSD наблюдением, не останавливают запись автоматически.

Все Services — внутренние, ingress/NodePort/public LB отсутствуют. node-exporter использует `hostNetwork` и bind **только `status.hostIP:9100`**, который prerequisite обязан подтвердить как VPN адрес. Для hostNetwork нельзя полагаться на обычную Kubernetes NetworkPolicy; проверить host firewall/Headscale ACL, private bind и невозможность подключения по публичному IP. В namespace обычные pod endpoints ограничены NetworkPolicy. Доступ к Prometheus UI — через согласованный `kubectl port-forward` либо Grafana из namespace observability; сам Prometheus не имеет публичного ingress. Mac poller через SSH читает локальный Ready Prometheus Pod на выбранной VPS после проверки API identity, namespace/labels/nodeName и Pod IP внутри runtime Pod CIDR; широкое разрешение ingress для VPN или всех Pods ему не требуется.

Targets для нод обнаруживаются через Kubernetes API: разрешены имена `home`, `msk`, `fin`, используется их InternalIP. Адресов узлов и ключей в Git нет. Добавление четвёртой ноды требует изменения allowlist/target_limit и ожидаемого количества targets. Приватный Service CIDR в egress policy соответствует bootstrap `${SERVICE_CIDR}`; значение подставляет Flux. ServiceAccount Prometheus читает Node/Pod metadata для discovery во всех namespaces, `get nodes/metrics` и API `/metrics`. Он не получает Secrets, `nodes/proxy`, полномочия изменять Pods/CSR или писать в etcd. Pod discovery раскрывает спецификации Pod (включая literal env values); секреты приложений необходимо хранить в Secret, а не в plain env.

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

`configured=1` устанавливается после настройки конкретного pipeline, не этим мониторингом. До первого успеха timestamp=0; неудача сохраняет прошлый timestamp и выставляет attempt=0. Headscale producer согласован отдельно на MSK, период 15 минут, допустимый возраст 1 час. Локальная coordinator recovery copy и offsite backup имеют разный смысл; успех копирования не подменяет проверку восстановления. Метрики MacBook публикует отдельный backup runner после включения его `metrics_publication`; этот каталог не создаёт для него метрики успеха. До настройки pipeline метрики отсутствуют; это неизвестный статус, не успешный backup.

Аналогичный необязательный storage contract: `infra_storage_configured`, `infra_storage_used_bytes`, `infra_storage_budget_bytes` с одинаковыми `component` и target labels. Правило quota включается только при configured=1; producer здесь не создаётся. Успешная метрика бюджета не доказывает перенос данных или наличие файловой hard quota.

Alertmanager использует **пустой receiver** `pending-user-destination`: внешнюю доставку сам Alertmanager не выполняет. [Локальный Mac poller](../../../bootstrap/macos/MONITORING.md) независимо читает Prometheus через SSH и показывает macOS notifications для warning/critical, пока Mac бодрствует, имеет сеть и пользователь вошёл в GUI. Информационный alert указывает отсутствие внешнего receiver и ограничение локального канала. После выбора пользователем внешнего адресата добавить интеграцию с runtime/SOPS Secret, разрешённый egress и end-to-end тест доставки; тогда удалить `NotificationDeliveryNotConfigured`. Две Alertmanager реплики обмениваются состоянием, Prometheus отправляет в обе и удаляет replica label для deduplication. Одновременный restart обеих Alertmanager теряет silences/notification log из emptyDir; это принятый начальный компромисс малых SSD, не durable alert history.

При потере всего кластера серверный мониторинг не сможет отправлять события. Работающий Mac poller после трёх неуспешных опросов через обе VPS сообщает, что состояние кластера неизвестно; если Mac спит или offline, этот канал также недоступен. Независимый круглосуточный внешний receiver этим стеком не создаётся. История метрик не является backup данных приложений.

## Проверка изменений

Локально проверены `kubectl kustomize`, Ansible syntax, Prometheus 3.15.0 `promtool check config --syntax-only`/`check rules`, Alertmanager 0.34.1 `amtool check-config`, структура manifests, закрепление images, размеры ресурсов и отсутствие public Services/Secrets. Validator binaries скачаны из официальных releases и проверены по SHA256. Это не server-side dry run и не runtime evidence.

После применения проверить: обе VPS имеют по Prometheus/Alertmanager/KSM/blackbox; все три node-exporter доступны только приватно; PVC Bound к разным VPS; Node/etcd targets 3/3; шесть blackbox probes; root filesystem labels; правила loaded; RAM/disk/WAL growth; Alertmanager mesh. Подтвердить невозможность POST и произвольных paths через etcd metrics frontend. Проверку отказа нод и доставки внешнего уведомления провести отдельным согласованным шагом; результаты фиксировать отдельно от конфигурации.

При подсчёте requests/limits сначала убрать дубли двух kube-state-metrics, например `sum by (node, resource) (max by (namespace, pod, container, node, resource) (kube_pod_container_resource_requests))`; для limits заменить имя метрики на `kube_pod_container_resource_limits`. Отсутствующий container limit означает отсутствие ограничения, а не нулевое потребление. Эти суммы не заменяют Kubernetes scheduler accounting для init containers/Pod overhead и фактический `MemAvailable` узла.

Источники: [Prometheus releases](https://prometheus.io/download/), [storage/retention](https://prometheus.io/docs/prometheus/latest/storage/), [kube-state-metrics 2.20.0](https://github.com/kubernetes/kube-state-metrics/releases/tag/v2.20.0), [DERP HTTP probe](https://github.com/tailscale/tailscale/blob/main/cmd/derper/derper.go).

Сервисная подсеть берётся из `${SERVICE_CIDR}` через обязательный root Flux `postBuild.substituteFrom` runtime ConfigMap `flux-system/unified-network`. Перед локальной проверкой NetworkPolicy подставить значение из защищённого inventory.

## PostgreSQL

Host timer каждые 120 секунд выполняет ограниченные read-only SQL/размерные проверки и атомарно публикует `infra_postgres_*` через node-exporter textfile. `collect_timestamp_seconds` относится к попытке, `last_success_timestamp_seconds` обновляется только после всей успешной выборки. При ошибке collector выставляет `collect_success=0` и не выдаёт прошлые SQL-значения за свежие; отсутствие/просрочка метрик требуют проверки независимо от состояния базы.

Порог physical data: предупреждение18GiB, critical21GiB при логическом бюджете24GiB. WAL6/8GiB, потерянные slots, запас retained WAL<1GiB, replay lag>16MiB и TLS<14days контролируются отдельно. `max_slot_wal_keep_size` действует с checkpoint и не является дисковой quota. Сумма наблюдаемых primary должна быть1; основной сервер должен видеть две streaming async replicas. Во время поэтапной начальной установки предупреждение о недостающих репликах ожидаемо; после включения всех трёх требует разбирательства. Эти метрики не доказывают отсутствие split-brain вне доступной наблюдателю части сети, успешный failover или нулевой RPO.

## Public DNS

Job `public-dns` читает CoreDNS9153 и health-agent9080 на двух VPS; namespace stack выдаёт Prometheus только read-only Pod discovery. Проверяются актуальность probes и синхронизации zone, serial divergence, API errors и доступность обоих targets. Проверка отсутствия двух агентов включается только при существующем desired DaemonSet. HTTP/metrics success не доказывает делегирование публичного домена, прохождение внешнего DNS-трафика или переключение ingress: это отдельные внешние проверки.

## Покрытие и добавление приложений

| Слой | Метрики |
|---|---|
| ОС | CPU, RAM, swap, диски/inodes, сеть, pressure stall и textfile producers |
| Kubernetes | Node/Pod/workload/PVC состояния, requests/limits, OOM/restarts, CSR pending |
| Kubelet/cAdvisor | CPU/RAM контейнеров, CPU throttling, I/O, сеть, volume stats и serving TLS expiry |
| Control plane | API rate/errors/latency/inflight; etcd leader/fsync/database/proposals/peer failures |
| Сетевой путь | CoreDNS, два ingress Traefik, public-DNS agents/CoreDNS; HTTPS Headscale и обоих DERP с каждой VPS |
| Рабочие данные | PostgreSQL replication/WAL/data/TLS из read-only collector; Garage topology/S3/resync/disk |
| Наблюдаемость | Prometheus/Alertmanager/KSM, cert-manager certificates, Loki discard/rate limits, Alloy delivery, GlitchTip capacity guard |
| Восстановление | Реальные timestamp/status настроенных Mac и coordinator recovery backups |

Job kubelet/cAdvisor использует Node InternalIP с CA/SAN проверкой. [TLS maintenance](../../../bootstrap/ansible/KUBELET-SERVING-TLS.md) подписывает только проверенный CSR каждого узла; будущие renewals требуют такого же явного review. Нет insecure TLS или API proxy для доступа к kubelet. Scheduler/controller-manager имеют loopback metrics endpoints: этот каталог их не открывает. Headscale и DERP blackbox проверяет HTTPS доступность/сертификат; приватные daemon counters включаются отдельным bounded host collector, описанным ниже. Grafana `/metrics` намеренно выключены, чтобы они не оказались открыты через UI ingress; её CPU/RAM/Pod health видны через cAdvisor/KSM.

Для приложения добавить **Pod template label** `infra.shanginn.io/metrics: "true"`, один именованный container port `metrics`, HTTP endpoint `/metrics` и ingress NetworkPolicy только от `namespace=monitoring, app=prometheus` к этому порту. Job не принимает произвольные адреса/paths из annotations; max64targets, max5000samples/target и body5MB. Приложение отвечает за имена и ограниченные labels: нельзя user IDs, URL query strings, request IDs, emails или тексты исключений в metric labels. Для событий ошибок и stack traces использовать отдельный error-tracking stack. Метрики могут работать и без общего opt-in через отдельный reviewed job, например GlitchTip.

У cAdvisor сохраняется уникальный cgroup `id`, чтобы старые и новые container instances не стали дублирующими samples; удаляются image и произвольные container labels. Recording rules агрегируют usage по namespace/pod/container и отдельно deduplicate два KSM. `node_resource:container_requests:sum` и limits — сумма обычных контейнеров, **не** точное scheduler accounting для init containers/overhead. Отсутствующий memory limit не считается нулевым лимитом.

`rules.test.yml` проверяет dedup requests, pending/approved CSR, возраст OOM и guard/error-storage сигнализацию. Перед публикацией: `promtool check config --syntax-only prometheus.yml`, `promtool check rules rules.yml`, `promtool test rules rules.test.yml`, `kubectl kustomize`. После применения проверить `up`, scrape errors/limits, loaded rules, series cardinality, Prometheus RAM и retention growth. Limits и период60s сохраняются; 7 дней истории при росте series не гарантированы. Новые метрики не означают HPA: metrics-server этим стеком не устанавливается.

Метрики cert-manager описаны в [официальной документации](https://cert-manager.io/docs/devops-tips/prometheus-metrics/); serving CSR метрики сверены с [KSM v2.20.0 source](https://github.com/kubernetes/kube-state-metrics/blob/v2.20.0/internal/store/certificatesigningrequest.go); потери доставки логов — с [Alloy loki.write](https://grafana.com/docs/alloy/latest/reference/components/loki/loki.write/).

## Детальные метрики внешних ОС-служб и GPU

`bootstrap/ansible/monitoring-detail.yml` сначала читает identity каждого узла. Для установки нужны `monitoring_detail_apply: true` и `monitoring_detail_expected_identity` из inspection всех трёх узлов. Новый root-owned timer раз в минуту запускает только собственный bounded collector; существующие службы не перезапускаются. Он не устанавливает драйверы, пакеты, публичные listeners или маршруты. Для повторной установки все прежние owned files должны совпадать с сохранёнными SHA; неизвестные файлы/units/drop-ins не присваиваются.

Collector через `nsenter` делает только `GET /metrics` Headscale на loopback9090 и TLS-проверенный `GET /debug/varz` DERP из loopback source в уже существующей namespace. DERP hostname проверяется публичной CA; публичные debug restrictions сохраняются. Ответ ограничен1MiB, выбираются конкретные числовые counters/gauges; node/user/IP/path labels удаляются, histogram сохраняет только numeric `le`. Эти агрегаты публикуются как `infra_headscale_*`/`infra_derp_*` через существующий node-exporter textfile. Нет доступа к debug GC, profiling, client lists или сырым логам. Источник пути DERP — [pinned Tailscale debug handler](https://github.com/tailscale/tailscale/blob/v1.104.1/tsweb/debug.go).

Systemd allowlist покрывает SSH, Tailscale, containerd, kubelet, API proxy, Patroni watchdog, overlay/DERP/Headscale и существующий домашний GPU worker/UVM helper/watchdog. `infra_service_expected_active=0` для standby Headscale: его неожиданный запуск тоже вызывает alert. GPU query разрешён только дома, если `nvidia-smi` уже установлен и драйвер уже загружен; собираются utilization, VRAM и температура без процессов/serial/UUID. Никаких modprobe, persistence mode, power controls или новых CUDA задач.

Timeout единичных запросов4–10s, весь oneshot45s, memory128MiB, CPU20%. Выходной файл<=64KiB пишется атомарно; сбой компонента выдаёт `infra_detail_collect_success=0`, сохраняет предыдущий success timestamp и не публикует старые численные данные как свежие. Таймер не гарантирует сбор при отказе самого узла. Scheduler/controller-manager loopback metrics остаются отдельной задачей; их приватные TLS endpoints здесь не раскрываются.
