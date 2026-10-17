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
| `overlay_acme_email` | Необязательный контакт для ACME; без значения аккаунт создаётся без email |

Оба DNS-имени DERP должны указывать на соответствующие серверы, имя координатора — на активный сервер. На серверах должны быть свободны TCP 80/443 и UDP 3478. Из `bootstrap/ansible`:

```sh
/tmp/infra-unified-venv/bin/ansible-playbook overlay.yml --syntax-check
/tmp/infra-unified-venv/bin/ansible-playbook overlay.yml -e @/path/to/private-overlay.yml
```

HAProxy передаёт TLS по SNI; HTTP-01 обслуживает отдельный постоянный webroot. Сертификаты продлеваются таймером `infra-overlay-renew.timer`. Headscale работает в отдельном network namespace без default route и NAT. Встроенный DERP и публичная DERP-карта Tailscale отключены. Собственная карта содержит обе службы. Секретные ключи создаются на серверах и в Git не попадают.

DERP принимает только узлы, известные локальному tailscaled. До регистрации клиентов relay отвергает подключения. `overlay.yml` не регистрирует клиентов. Проверка membership использует локальную netmap; после перезапуска tailscaled доступность зависит от восстановления этой карты.

Защита останавливает установку при конфликтующих службах/портах, пересечениях адресов и смене владельца или роли координатора. Повторное применение сохраняет сетевые адреса и роль. Перенос координатора требует выключенного прежнего экземпляра и восстановления согласованной SQLite-базы, Noise-ключа, конфигурации и TLS-файлов под тем же DNS-именем; простое включение резервной службы запрещено.

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
