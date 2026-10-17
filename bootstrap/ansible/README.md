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
