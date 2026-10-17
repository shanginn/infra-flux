# Единый kubeadm-кластер

Конфигурация Kubernetes находится в `clusters/unified`. Старые каталоги кластеров не подключены к этому Flux. Автоматизация ОС, VPN и первоначального kubeadm bootstrap находится здесь; адреса VPN, SSH, токены и исходные пароли передаются приватными файлами вне Git.

## Установка

После `phase1.yml`, `overlay.yml` и `enroll.yml` подготовьте private extra-vars с непересекающимися `unified_pod_cidr`, `unified_service_cidr`, `overlay_tailnet_prefix`. Для первого bootstrap задайте `unified_cluster_bootstrap_enabled: true`. `unified_allow_swap_disable: true` разрешает отключить только неиспользуемый swap после повторной проверки; файлы swap не удаляются.

```sh
ansible-playbook cluster.yml -e @/path/to/private-cluster.yml -e @/path/to/private-overlay.yml
# Домашний узел с GPT swap: сначала inspect, затем после проверки CA/fstab SHA — apply.
ansible-playbook swap-maintenance.yml -e @/path/to/private-swap.yml
ansible-playbook swap-maintenance.yml -e @/path/to/private-swap.yml -e unified_swap_maintenance_apply=true
ansible-playbook monitoring.yml -e monitoring_prepare_enabled=true
ansible-playbook garage.yml -e @/path/to/private-storage.yml
ansible-playbook gitops.yml -e @/path/to/private-cluster.yml -e @/path/to/private-overlay.yml -e unified_gitops_enabled=true
```

Проверьте имена флагов и обязательные значения соответствующего playbook перед запуском. Подготовка storage не создаёт его workload. [Garage](../../clusters/unified/garage/README.md) требует отдельного первоначального layout после появления трёх работающих контейнеров. PostgreSQL имеет отдельные prepare/activate этапы; его режим fencing выбирается до активации.

Для домашнего узла с GPT swap порядок воспроизведения: первоначальный `cluster.yml` → проверенный [swap-maintenance.yml](SWAP-MAINTENANCE.md) → первая перезагрузка. Простое комментирование swap в `fstab` не подавляет GPT auto-discovery; maintenance сохраняет явную запись `noauto`. Inspect сам не меняет состояние: перед apply передайте проверенные идентификаторы раздела, CA и SHA256 текущего `fstab`.

После завершения первоначальной установки применяйте отдельные maintenance playbook и Flux. Уберите одноразовые `unified_cluster_bootstrap_enabled: true` и `unified_allow_swap_disable: true` из рабочего набора private extra-vars. Не запускайте полный bootstrap как периодический reconcile: его managed `noauto` guard завершает preflight ошибкой даже при `unified_allow_swap_disable=true`, чтобы повторная обработка не закомментировала maintenance-запись. Этот отказ не является запросом удалить marker или вернуть старую настройку swap.

`cluster.yml` предназначен для первоначальных трёх нод, не для upgrade, reset или автоматического ремонта. Он сохраняет CA и fingerprint всей конфигурации, шаблонов и самого playbook. Изменение fingerprint существующей установки требует отдельного проверенного перехода; нельзя удалять маркер или ослаблять проверку, чтобы обойти отказ.

`gitops.yml` сначала выделяет Calico маску `0xff000000`: стандартная маска пересекается с policy-routing mark Tailscale. Только затем он запускает Flux и подключает `./clusters/unified`. При ручном bootstrap примените `clusters/unified/networking` до запуска приложений. Не меняйте VPN fwmarks для обхода этой проблемы.

На каждой ноде локальный HAProxy слушает `127.0.0.1:7443` и проверяет все три API. Имя `api.unified.internal` разрешается в loopback этой ноды. Клиентский TLS проходит до API; сертификат проверяет клиент. Скопированный kubeconfig с этим endpoint требует собственного SSH tunnel или локального proxy, а не публичного DNS A record.

После первого bootstrap и до испытаний отказов выполните проверенное [обслуживание endpoint kubelet](KUBELET-MAINTENANCE.md), чтобы kubelet использовал этот локальный HAProxy. После kubeadm upgrade заново проверьте адрес и совместимость версий всех API.

Для отключения автозапуска неиспользуемого штатного `haproxy.service` предусмотрен отдельный [service-maintenance.yml](service-maintenance.yml): `ansible-playbook service-maintenance.yml -e unified_disable_stock_haproxy=true`. Он требует все три исходные ноды, проверяет ownership markers, общий CA, работающие собственные прокси и неизменённые пакетные конфигурацию/unit штатной службы. Активная штатная служба или её overrides останавливают процедуру. Playbook меняет только автозапуск штатного unit; процессы API/overlay не останавливает и не перезапускает, bootstrap fingerprint не меняет.

Ingress включается после готовности Traefik на обеих VPS:

```sh
ansible-playbook ingress-edge.yml -e @/path/to/private-overlay.yml -e ingress_edge_enabled=true
```

Headscale/DERP продолжают обслуживаться отдельными SNI-маршрутами. Публичное переключение приложений описано в [public-dns](../../clusters/unified/public-dns/README.md). Для внутренних приложений не создавайте публичный ingress автоматически.

## Добавление вычислительной ноды

1. Добавьте SSH alias локально, новый host и `site` в inventory; первоначальные три control-plane остаются прежними. Проверьте диски, RAM, существующие службы и отсутствие пересечений сетей.
2. Примените `phase1.yml --limit NEW_NODE`, затем `enroll.yml --limit NEW_NODE`. Проверьте постоянный VPN IP и связь с каждым control-plane в обе стороны. Не клонируйте `tailscaled.state` работающей машины.
3. Подготовьте на новой ноде те же containerd/cgroup, kubelet reservations, VPN startup ordering, локальный API proxy и firewall из шаблонов kubeadm. Для worker не добавляйте etcd и не запускайте трёхнодовый `cluster.yml`. Расширение OS automation оформляется отдельным review в Git с учётом существующих ownership markers.
4. Создайте на действующем control-plane короткоживущий kubeadm token. Передайте join-конфигурацию приватно, с проверенным CA discovery hash, `node-ip` VPN и `nodeRegistration.name`; выполните `kubeadm join --config ...`. Не сохраняйте join token в Git или shell history. После успешного join отзовите только созданный токен и удалите его временный файл.
5. Проверьте Ready, адрес/MTU, Pod-to-Pod/DNS/API со всех площадок и resource reservations. Добавьте labels/affinity нужным приложениям. Новая worker-нода не становится автоматически репликой Garage или PostgreSQL: их размещение и ёмкость изменяются отдельно.

Обычно наращивают workers при трёх etcd voters. Переход control-plane с 3 на 4 не увеличивает допустимое число отказов; для следующего уровня устойчивости рассматривают 5 независимых voters, предварительно измерив WAN/fsync. Изменение состава выполняют по одному участнику с проверкой здоровья quorum после каждого шага.

## Замена потерянной VPS при живом quorum

1. Подтвердите отключение старой машины. Сетевая недоступность не доказывает fencing. Сохраните данные оставшихся нод и свежую зашифрованную копию etcd; не восстанавливайте snapshot поверх живого quorum.
2. Через аутентифицированный `etcdctl member list` сопоставьте имя, peer URL и ID потерянного участника. Удаляйте только этот member после проверки двух здоровых оставшихся voters. Удалите соответствующий Kubernetes Node; не удаляйте его PVC автоматически.
3. Подготовьте чистую замену, VPN и локальный proxy. При восстановлении прежней VPN identity сначала fenced прежняя машина; при новом адресе обновите firewall/backend list и API SAN в отдельном review. Не копируйте старый etcd member data-dir на новый независимый узел.
4. Выполните kubeadm control-plane join с краткоживущими token/certificate key и CA pin. Дождитесь завершения добавления etcd learner и проверьте три здоровых voting members, одинаковый cluster ID, Ready и API через каждый proxy. Отзовите временные credentials.
5. Восстановите отдельные replicas PostgreSQL/Garage из живых источников по их процедурам. Не запускайте старый PG primary или прежний Garage node ID одновременно с заменой. Для VPS с Headscale используйте отдельную [процедуру координатора](README.md#восстановление-координатора-на-standby).
6. Обновите публичные DNS/glue, ingress и monitoring после проверки новых endpoints. Старый сервер остаётся fenced до отдельной очистки или нового назначения.

## Восстановление etcd после утраты quorum

Это отдельная аварийная операция с остановкой всех прежних etcd/API; сначала исключите их самопроизвольный возврат. Выберите проверенную копию на Mac, восстановите CA/PKI и snapshot в приватное место по [инструкции резервного копирования](../macos/README.md). Пароль restic нужен отдельно от каталога repository.

Проверьте snapshot через соответствующий `etcdutl snapshot status`. Восстанавливайте **один и тот же snapshot** на все новые члены в новые пустые data directories с одинаковыми initial cluster/token и правильными уникальными name/peer URLs. Для Kubernetes используйте revision bump и mark-compacted, чтобы старые informer watches не продолжили работу с неверным состоянием. Размер bump выбирайте больше возможного прироста revision с момента snapshot; проверочный backup restore не заменяет этот расчёт.

После проверки восстановленных каталогов переключите static manifests на них, затем запустите etcd и API, проверьте cluster ID/health/число voters, Secrets и ресурсы. Только потом возвращайте controllers и приложения. Состояние etcd не содержит данные local PV: PostgreSQL и S3 восстанавливаются отдельно. Не выполняйте `kubeadm reset`, не перезаписывайте `/var/lib/etcd` и не удаляйте прежние каталоги как часть проверки архива.

## Размещение приложений

Для тяжёлых задач задавайте preferred node affinity к `infra.shanginn.io/site=home` и явные requests/limits. Если работа должна выполняться только дома, используйте required affinity и примите остановку этой работы при его потере. Для критичных stateless приложений задавайте минимум две replicas, required anti-affinity по hostname и размещение на `msk|fin`; перед переносом проверьте их реальные requests и пиковую память. Сам факт свободной RAM не доказывает, что произвольное будущее приложение переживёт отказ.

Local PV привязан к физическому серверу. Его capacity в Kubernetes не создаёт файловую quota. Не увеличивайте размер YAML без реального диска и не считайте backup дополнительной рабочей репликой. Проверки с отключением машины, WAN partition и перезапуском watchdog требуют согласованного окна.
