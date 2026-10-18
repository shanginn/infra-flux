# Подготовка узлов

`phase1.yml` устанавливает containerd, kubeadm, kubelet, kubectl, cri-tools и клиент Tailscale на Debian 13 amd64. Версии закреплены в `group_vars/unified.yml`; пакеты устанавливаются из официальных подписанных репозиториев и удерживаются от автоматического обновления. Конфигурация containerd использует `SystemdCgroup = true`.

## Настройка и запуск

В `inventory.yml` задаются SSH-алиасы и группы `control_plane` и `workers`. Адреса, порты и ключи SSH настраиваются локально в `~/.ssh/config`. Проверка ключей серверов включена.

Из корня репозитория:

```sh
python3 -m venv /tmp/infra-unified-venv
/tmp/infra-unified-venv/bin/pip install -r bootstrap/ansible/requirements.txt
cd bootstrap/ansible
/tmp/infra-unified-venv/bin/ansible-playbook phase1.yml --syntax-check
/tmp/infra-unified-venv/bin/ansible-inventory --graph
/tmp/infra-unified-venv/bin/ansible-playbook phase1.yml
```

Для одного узла добавьте `--limit <имя-из-inventory>`. Узлы обрабатываются последовательно; ошибка останавливает запуск. Достаточно закреплённого `ansible-core`; внешние Galaxy-роли не нужны.

## Повторное применение

Playbook отклоняет существующую установку Kubernetes, работающий kubelet и конфликтующие runtime. Уже установленные containerd и Tailscale принимаются только с маркером этого playbook в `/etc/infra-flux/phase1.json`. Контрольная сумма конфигурации containerd должна совпадать с сохранённой: так можно обновить управляемый шаблон, сохраняя защиту ручных изменений.

После регистрации Tailscale или создания Kubernetes повторный запуск запрещён. При остановленном tailscaled с сохранённым состоянием сначала требуется проверить регистрацию отдельно.

## Результат и проверка

containerd и tailscaled включены и запущены. kubelet остановлен и исключён из автозапуска. Playbook только подготавливает пакеты: он не выполняет `tailscale up` или `kubeadm init/join`, не меняет маршруты, DNS, sysctl, swap, firewall и SSH, не перезагружает узлы.

Из корня репозитория выполните проверку на нужном узле:

```sh
ssh <SSH-алиас> python3 - < scripts/unified/verify-phase1.py
```

Проверка только читает версии и состояние управляемых компонентов. Она выводит JSON и возвращает ненулевой код, если подготовка не завершена. Синтаксическая проверка Ansible не подключается к серверам; режим `--check` не заменяет проверку установленного runtime.

## Headscale и DERP вне Kubernetes

`overlay.yml` устанавливает Headscale, два отдельных DERP и STUN-only службы. Координатор запускается только на узле `headscale_active_host`; на другом узле служба выключена и новая база не создаётся. Версии и публичные DNS-имена задаются в `vars/overlay.yml`.

Приватные значения передаются отдельным YAML-файлом вне репозитория:

| Переменная | Значение |
| --- | --- |
| `overlay_ns_host_address` | Адрес host-конца отдельной свободной IPv4 `/30` сети |
| `overlay_ns_service_address` | Второй адрес той же `/30` сети для namespace |
| `overlay_tailnet_prefix` | Свободная подсеть внутри диапазона CGNAT, поддерживаемого Tailscale |
| `headscale_policy` | Обязательный объект политики с явным списком `acls` или `grants`; правила доступа и тесты задаются целиком |
| `headscale_active_public_ipv4` | Публичный IPv4 активного координатора для первоначальной настройки standby; IP-литерал, не VPN-адрес и не DNS-имя |
| `overlay_acme_email` | Необязательный контакт для ACME; без значения аккаунт создаётся без email |

Оба DNS-имени DERP должны указывать на соответствующие серверы, имя координатора — на активный сервер. На серверах должны быть свободны TCP 80/443 и UDP 3478. Из `bootstrap/ansible`:

```sh
/tmp/infra-unified-venv/bin/ansible-playbook overlay.yml --syntax-check
/tmp/infra-unified-venv/bin/ansible-playbook overlay.yml -e @/path/to/private-overlay.yml
```

HAProxy передаёт TLS по SNI; HTTP-01 обслуживает отдельный постоянный webroot. На активном сервере маршрут Headscale ведёт в локальный namespace на `8443`, на standby — на публичный `443` активного сервера. TLS завершается у единственного координатора, его DNS-имя и ключи сохраняются. Этот транспорт не зависит от VPN и не создаёт второго координатора. Сертификаты продлеваются таймером `infra-overlay-renew.timer`. Headscale и отдельный DERP работают в изолированном network namespace без default route и NAT; STUN остаётся на host. HAProxy обращается к DERP через veth с нелокальным адресом источника: служебный `/debug/` остаётся запрещён, а защита loopback в kube-proxy не блокирует relay. DERP проверяет клиентов через файловый Unix socket host tailscaled, доступный из этого namespace. Встроенный DERP и публичная DERP-карта Tailscale отключены. Собственная карта содержит обе службы. Секретные ключи создаются на серверах и в Git не попадают.

DERP принимает только узлы, известные локальному tailscaled. До регистрации клиентов relay отвергает подключения. `overlay.yml` не регистрирует клиентов. Проверка membership использует локальную netmap; после перезапуска tailscaled доступность зависит от восстановления этой карты.

`overlay.yml` предназначен только для первоначальной установки. Если `/etc/infra-flux/overlay.json` уже существует, запуск завершается до изменения пакетов, файлов и служб. Не удаляйте маркер для обхода проверки: после прерванной установки сначала исследуйте частичное состояние. Работающие узлы обслуживаются отдельным ограниченным playbook; полный bootstrap не используется для смены ACL или маршрута. Проверка также отклоняет конфликтующие службы/порты и пересечения адресов. Перенос координатора требует выключенного прежнего экземпляра и восстановления согласованной SQLite-базы, Noise-ключа, конфигурации и TLS-файлов под тем же DNS-именем; простое включение резервной службы запрещено.

Политика не имеет запасного значения «разрешить всё». Отсутствие `acls` и `grants` отклоняется: [Headscale трактует такую политику как полный доступ](https://headscale.net/stable/ref/policy/). Перед изменением действующей политики нужны `CheckPolicy` на работающем координаторе и положительные тесты существующих узлов. После атомарной замены применяется `SIGHUP`, затем проверяются принятая политика, прежний PID и связность. Новый клиент регистрируется только после применения ограничения; затем фактически проверяются его разрешённые и запрещённые подключения. Исходная политика и действующие подключения сохраняются до проверки результата; восстановление выполняется из точной прежней конфигурации, без подстановки открытых правил.

Маршрут standby сохраняется в `/etc/infra-overlay/coordinator-relay.json` (`root`, `0600`). Формат содержит `owner: infra-flux/ansible/coordinator-relay`, `format: 1`, имена `standby_host` и `active_host`, прежний `server_url`, `upstream_ipv4` и `upstream_port: 443`. `ingress-edge.yml` читает эту запись до любых изменений. Несовпадение владельца, роли, DNS-имени или явно переданного адреса останавливает запуск; отсутствующая запись не заменяется маршрутом в выключенный локальный Headscale. Запрещены локальные адреса, VPN, namespace и DNS-имена в качестве upstream. Изменение ingress сохраняет уже настроенный транспорт координатора.

Порядок изменения действующей политики и маршрута, проверки и таймер отката описаны
в [OVERLAY-MAINTENANCE.md](OVERLAY-MAINTENANCE.md).

После запуска проверяются HTTPS Headscale, TLS DERP и закрытый публичный `/debug/`. Работу relay и переключение между регионами следует проверять зарегистрированными клиентами. Журнал конкретной службы доступен через `journalctl -u infra-headscale`, `journalctl -u infra-derper` или `journalctl -u infra-overlay-renew`.

## Регистрация клиентов

`enroll.yml` создаёт пользователя `infra`, если его ещё нет, и регистрирует подготовленные узлы. Сначала зарегистрируйте VPS, затем остальные узлы:

```sh
/tmp/infra-unified-venv/bin/ansible-playbook enroll.yml --syntax-check
/tmp/infra-unified-venv/bin/ansible-playbook enroll.yml -e @/path/to/private-overlay.yml --limit 'fin:msk'
/tmp/infra-unified-venv/bin/ansible-playbook enroll.yml -e @/path/to/private-overlay.yml --limit home
```

Для каждого незарегистрированного клиента создаётся отдельный одноразовый ключ сроком на 10 минут. Он передаётся через временный файл root с правами `0600`; файл удаляется после попытки, ключ отзывается. Чувствительные задачи скрыты через `no_log`, факты не записываются в постоянный кэш. Узлы постоянные: `ephemeral=false` относится к узлу, а не к сроку регистрации.

Клиент получает имя `k8s-<site>`, использует только собственный login server и не принимает DNS или маршруты VPN. Tailscale SSH, exit node и объявления подсетей не включаются. Уже работающий клиент только проверяется: login server, имя, настройки и IPv4 должны соответствовать конфигурации. Несовпадение останавливает запуск без сброса регистрации.

## Состояние резервного координатора

`headscale-backup.yml` отдельно включает согласованные зашифрованные копии активного Headscale на standby. В private extra-vars добавьте `headscale_backup_ssh_port` — действующий SSH-порт активного сервера. Оба участника должны быть зарегистрированы в VPN. Playbook запускается сразу для обоих VPS, поскольку передаёт между ними только публичные ключи:

```sh
/tmp/infra-unified-venv/bin/ansible-playbook headscale-backup.yml --syntax-check
/tmp/infra-unified-venv/bin/ansible-playbook headscale-backup.yml -e @/path/to/private-overlay.yml
```

Standby получает отдельный SSH-ключ с `restrict`, ограничением `from` его VPN-адресом и единственной forced command — созданием шифрованного snapshot. Ключ шифрования age создаётся только на standby, с правами `0600`. SSH host key активного сервера переносится через уже доверенное соединение Ansible. Существующий административный доступ сохраняется.

Копия SQLite создаётся Backup API, затем вместе с Noise key, конфигурацией, TLS и DNS identity проверяется и шифруется потоком. Открытый временный snapshot хранится только в `/run`. На standby проверяются дешифрование, SHA-256, integrity SQLite, соответствие DNS, префикса и TLS-ключа; только после этого файл атомарно становится доступной копией. Таймер выполняется каждые 15 минут, хранится 96 последних успешных копий. Ограничение snapshot — 128 MiB. Увеличивайте лимит и retention явно после проверки свободного места. Неисправная попытка не заменяет последнюю успешную копию.

Статус: `/var/lib/infra-headscale-recovery/status.json`; последняя копия: `latest.json`; журнал: `journalctl -u infra-headscale-backup`. Textfile-метрики публикуются в `/var/lib/node_exporter/textfile_collector/headscale-backup.prom`, срок свежести — один час. Ключ `/var/lib/infra-headscale-recovery/identity.age` нужен для дешифрования: его утрата делает эти копии недоступными. Отдельные [копии на Mac](../macos/README.md) настраиваются независимо и не требуют включать этот таймер.

## Восстановление координатора на standby

Сначала подтвердите fencing прежнего активного сервера: выключение питания либо остановка, отключение автозапуска Headscale и удаление его activation fence при подтверждённом административном контроле. Недоступность по сети и переключение DNS сами по себе не подтверждают fencing. Скрипт требует явное подтверждение оператора; он не может самостоятельно доказать, что выключенный от сети сервер не запустится вновь.

На остановленном standby выберите файл из `/var/lib/infra-headscale-recovery/snapshots`. Существующие `db.sqlite*` или Noise key не перезаписываются. После подтверждённого fencing выполните от root:

```sh
python3 /usr/local/lib/infra-overlay/headscale-backup.py restore --snapshot SNAPSHOT.age --fenced-source PREVIOUS_ACTIVE_INVENTORY_NAME --confirm-server-url https://vpn.shanginn.io
python3 /usr/local/lib/infra-overlay/headscale-backup.py promote --fenced-source PREVIOUS_ACTIVE_INVENTORY_NAME --confirm-server-url https://vpn.shanginn.io
```

`restore` проверяет архив и восстанавливает прежние identity, базу и конфигурацию, оставляя службу выключенной. `promote` отдельно проверяет восстановленные файлы, выключает standby backup timer и активирует один координатор. При прерывании restore не пытайтесь обходить проверку существующих файлов: исследуйте частичное восстановление и `before-restore`, затем повторите подготовку остановленного standby.

Переключите прежнее DNS-имя на новый активный VPS и измените `headscale_active_host` в декларативной конфигурации. Для новой роли отдельно согласуйте сохранённый маршрут, SNI-конфигурацию и обработчик продления сертификата; полный `overlay.yml` над существующей установкой не запускается. Запись standby relay на новом активном сервере должна быть удалена только как часть проверенного promotion, после fencing прежнего координатора. Проверьте HTTPS `/health`, подключение клиента к прежнему login server и сохранение его VPN-адреса. Прежний координатор должен оставаться fenced до очистки его старого состояния и отдельной подготовки как standby. Автоматического promotion нет.
