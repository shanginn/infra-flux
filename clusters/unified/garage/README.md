# Garage в едином Kubernetes

S3 endpoint внутри кластера: `http://garage.garage.svc.cluster.local:3900`, region `garage`, path-style, SigV4. Внешнего ingress нет. RPC 3901 доступен только Garage Pods; admin/metrics 3903 — только Prometheus и локальные проверки kubelet. Для разрешения S3 доступа namespace приложения должен иметь label `infra.shanginn.io/garage-client=true`, а приложение — отдельный S3 key с правами только на нужные buckets. Admin token и RPC secret приложению не выдавать.

Garage 2.4.1, официальный chart 0.10.2, source commit `268334bd2530fa99f8b06c7383b2e9f776691edd`. Image и init image закреплены digest. Три StatefulSet Pods имеют required anti-affinity: один на home, msk, fin. Каждый получает **data PV 30 GiB и meta PV 1 GiB на той же физической ноде**. Параметры: RF3, `consistent` (R2/W2), три разные layout zones, SQLite metadata, metadata/data fsync, buffer 64 MiB, request 256 MiB и memory limit 1 GiB на ноду.

Успешная запись подтверждается двумя нодами; третья копия может появиться позже. При одном отказе R2/W2 остаётся доступным, но временно живы только две копии. При разделении 2+1 меньшинство теряет quorum. RTT WAN и fsync влияют на задержку, фактический throughput/latency измеряется тестами; лимит RAM не является гарантией достаточности под нагрузкой.

**Bucket versioning, ListObjectVersions, delete-marker history, AWS bucket policies и Object Lock не поддерживаются Garage.** Перед переносом versioned buckets отдельно выберите способ сохранения истории; эта установка существующие хранилища не изменяет. Для bucket permissions используется Garage key/bucket модель.

## Первоначальный запуск

1. Выполнить `bootstrap/ansible/garage.yml` с private extra-vars `garage_prepare_enabled: true`. Подготавливаются каталоги и runtime Secret; Kubernetes workload этим этапом не создаётся. На каждой ноде требуется 31 GiB бюджета плюс минимум 20 GiB свободного root reserve. Чужие каталоги, изменённые node identity или несовпадающие secrets останавливают процесс. Форматирования диска нет.
2. Создать runtime ConfigMap `unified-network` в `flux-system` с `POD_CIDR` и `SERVICE_CIDR`; root Flux Kustomization должен обязательно подставлять их через `postBuild.substituteFrom`. Значения сетей не хранятся в этом каталоге. Подключить `clusters/unified/garage` в корневой Flux kustomization. Появятся CRD, PV, HelmRelease и три Pods. У Helm install timeout 15 минут. Pod readiness `/health` может быть false до первого layout; ждать Running с запущенным контейнером `garage`, не ждать Ready перед шагом 3.
3. Повторить playbook с `garage_initialize_enabled: true`, `garage_prepare_enabled: false` и декларативным списком `garage_buckets` (по умолчанию пуст). Initializer запускается только на msk, блокирует параллельный запуск, сверяет Pod→Node→Garage node ID, назначает zones home/msk/fin и применяет только исходный layout version 1. Затем читает layout со всех трёх Pods и проверяет все partitions. Существующий layout не перестраивается автоматически. Durable `layout-apply-intent.json` записывается до первого apply; после неоднозначного timeout нельзя удалять intent и повторять apply, сначала сверить layout на всех узлах. Если Helm timeout истёк до bootstrap, после исправления причины выполнить обычный reconcile HelmRelease; не удалять StatefulSet/PVC.
4. Проверить HelmRelease Ready, Pods Ready, все PV Bound к нужным физическим нодам, layout и resync queue. Затем выполнить небольшие PUT/GET/checksum/delete и тесты приложений. Отказные тесты согласовываются отдельно. Kubernetes Ready и `cluster_partitions_all_ok` сами по себе не доказывают, что конкретный объект уже имеет три физические копии.

Ключи создаются runtime в `/etc/infra-garage/secrets.json` на msk, копируются root-only на остальные ноды и в Secret `garage-runtime`. Их нет в Git, аргументах shell или Ansible output. Не удалять Secret для «починки»: новый RPC secret создаст другую идентичность связи. Исходный файл нужен для recovery. Секреты, layout marker и metadata включить в согласованное зашифрованное резервное копирование на MacBook; до настройки pipeline такое копирование не считается работающим.

## Бюджет и buckets

Local PV `capacity` и layout capacity — **не файловая quota**. Физические каталоги находятся на общем root SSD. Начальный layout выделяет по 24 GiB полезной ёмкости, оставляя 6 GiB в data budget для временных блоков/overhead. Sum bucket quotas не должен превышать **24 GiB**, одинаковые полные копии занимают место на каждом из трёх серверов.

```yaml
garage_buckets:
  - name: example-app
    maxBytes: 1073741824
    maxObjects: 100000
```

Initializer создаёт только объявленные buckets, задаёт quota и читает её обратно. Он откажется продолжать при чужом bucket или уменьшении quota ниже текущих данных; ничего не удалит. Новые S3 keys не получают права создавать buckets. Не создавать unlimited buckets вручную и не выдавать приложению Garage admin API/RPC credentials. S3 keys выпускаются отдельно root runtime и предоставляются через защищённые Kubernetes Secrets.

Quota checks распределённые и не дают атомарной защиты root от всех concurrent uploads, multipart staging, metadata growth или других служб. Перед большим импортом заново проверить место и оставить запас. Мониторинг получает реальные `garage_local_disk_avail`, quorum/storage node counts и resync errors; при root free <20 GiB остановить клиентскую запись и расширить ёмкость либо освободить место согласованным способом. Не удалять block files вручную. Автоматическая очистка данных, lifecycle expiration и накопление полных локальных snapshot архивов не включены.

В pinned [коде обычного PUT](https://git.deuxfleurs.fr/Deuxfleurs/garage/src/commit/268334bd2530fa99f8b06c7383b2e9f776691edd/src/api/s3/put.rs) `check_quotas` вызывается после передачи блоков, а [multipart](https://git.deuxfleurs.fr/Deuxfleurs/garage/src/commit/268334bd2530fa99f8b06c7383b2e9f776691edd/src/api/s3/multipart.rs) — при завершении upload. Проверка читает распределённые счётчики, а не резервирует физическое место. Поэтому клиенту нужны ограничение размера object/частей и числа параллельных uploads; неизвестный или недоверенный workload нельзя пускать на root SSD, опираясь только на bucket quota. Для строгой изоляции ёмкости потребуется отдельный filesystem с quota либо отдельный том; эта установка не форматирует и не переразмечает root.

## Замена ноды и расширение

При потере машины сохранять данные оставшихся двух. Восстановить новый сервер и VPN, создать свежие отдельные data/meta каталоги и соответствующие local PV. Не переиспользовать PVC/PV от потерянной ноды без проверки содержимого и identity. Восстановленная metadata сохраняет node ID; пустая metadata создаёт новый ID — initializer специально откажется принять такую замену как повтор первого запуска.

Новый server/диск сначала добавить как отдельный Garage node с тем же RPC secret, версией и fsync settings; объявить реальную zone и проверенную capacity. Проверить предлагаемое распределение через `garage layout show`/JSON preview, применить следующий version только после review, дождаться block resync без ошибок. Удаление старой ноды из layout и её данных — отдельный шаг после доказанной репликации. Не делать `layout skip-dead-nodes` обычной заменой узла.

Для четвёртой ноды расширить replicas/affinity/PVs и явный список ожидаемых узлов в automation; RF3 означает три копии, а не копию на каждом из четырёх серверов. Kubernetes static local PV не поддерживает автоматическое расширение filesystem: изменение `30Gi` в YAML не создаёт диск и не добавляет места. Новый диск/новая zone и плановое изменение layout позволяют расширяться без удаления действующих данных.

## Проверки конфигурации

Перед применением: Ansible syntax, Helm render pinned upstream chart, Kustomize и post-render patches, TOML parsing, Python initializer проверки на фикстурах. Это не runtime приёмка. Операционное состояние смотреть через HelmRelease/Pods, `garage status`, `garage layout show`, `garage json-api GetClusterHealth` и Prometheus job `garage`. S3 tests и проверку фактических копий выполнить отдельно после запуска.

Документация: [Kubernetes chart](https://garagehq.deuxfleurs.fr/documentation/cookbook/kubernetes/), [настройки/quorum/fsync](https://garagehq.deuxfleurs.fr/documentation/reference-manual/configuration/), [S3 совместимость](https://garagehq.deuxfleurs.fr/documentation/reference-manual/s3-compatibility/), [layout](https://garagehq.deuxfleurs.fr/documentation/operations/layout/).
