# Локальные аварийные уведомления на Mac

Независимый LaunchAgent `io.shanginn.infra-flux.monitor` каждые 60 секунд читает firing alerts severity `warning`/`critical` из приватного Prometheus через SSH. Сначала используется первая VPS, при ошибке — вторая. Команда удалённо только читает Kubernetes API и использует имеющийся root admin kubeconfig; это не отдельный ограниченный service account. Внешние порты, SSH keys, Alertmanager receivers и backup jobs не изменяются.

Перед чтением проверяются root ownership и права remote kubeconfig/CA, SHA256 DER сертификата CA, совпадение встроенного CA kubeconfig и ожидаемый UID namespace `kube-system`. Host keys проверяются обычным SSH `StrictHostKeyChecking=yes`; существующий канал SSH должен уже работать. Не копировать UID/CA из непроверенного кластера и не заменять pin автоматически после ошибки. Из проверенного Kubernetes API выбирается единственная control-plane нода, чей InternalIP реально присутствует на локальном интерфейсе `tailscale0`; имя kubeadm ноды может отличаться от hostname ОС. Затем выбирается ровно один Running/Ready Pod: namespace `monitoring`, label `app=prometheus`, controller StatefulSet `prometheus`, `nodeName` совпадает с этой нодой. Его IPv4 должен входить в фактический `POD_CIDR` ConfigMap `flux-system/unified-network`. HTTP GET идёт только к этому локальному Pod IP:9090, путь `/api/v1/alerts`; redirects и proxy environment отключены. Service proxy со случайным endpoint на другой VPS не используется: host traffic через Calico VXLAN может иметь tunnel source IP, и открывать для него весь Pod CIDR не требуется.

Скопировать `monitor.example.json` в приватный файл `0600`, записать проверенные UID/CA и выполнить:

```sh
python3 bootstrap/macos/monitor-alerts.py --config /private/path/monitor.json --dry-run
python3 bootstrap/macos/install-monitor.py --config /private/path/monitor.json --schedule
```

Состояние и принятая конфигурация находятся в `~/Library/Application Support/infra-flux/monitor/`, каталог `0700`, JSON `0600`. Конфигурация и код runner копируются из проверенного checkout. Installer отказывается менять существующий cluster identity. Изменение identity требует отдельной проверки и ручного согласованного обновления private config, а не удаления состояния наугад. При обновлении runner повторить installer с прежним private config.

Дедупликация использует labels, игнорируя только replica labels двух Prometheus. Новое событие, изменение его summary и завершение сообщаются по одному разу. Изменение `activeAt`, metric value и description не создаёт повтор. Принятое системой уведомление не повторяется при следующем успешном опросе; ошибки уведомления видны в `status.json` и повторяются позже. После трёх подряд неуспешных опросов выдаётся сообщение о недоступности мониторинга; старые alerts при этом не помечаются завершёнными. Восстановление связи — отдельное событие, не утверждение, что все службы исправны.

Два SSH attempts ограничены 23 секундами каждый, keepalive включён, ответ не более 4 MiB, stderr не более 64 KiB. Параллельные экземпляры блокируются lockfile. Журнал stdout/stderr не накапливается; актуальное состояние хранится атомарно в одном JSON. `notification_error` и `last_notification_accepted` разделяют успешное чтение метрик и принятие уведомления macOS.

Оповещения показываются только локально через `osascript display notification`, без почты/Slack/webhooks. Принятие AppleScript не доказывает, что баннер был виден: Focus, настройки уведомлений и права GUI могут его скрыть. LaunchAgent работает только в пользовательской GUI-сессии; спящий, выключенный или лишённый сети Mac не опрашивает кластер и не будит себя. Это не независимый круглосуточный канал оповещения. Удалённый Alertmanager может по-прежнему показывать отсутствие своего внешнего receiver — локальный poller не меняет его конфигурацию.

Проверить job и актуальность `last_success`:

```sh
launchctl print gui/$(id -u)/io.shanginn.infra-flux.monitor
python3 bootstrap/macos/monitor-alerts.py --config "$HOME/Library/Application Support/infra-flux/monitor/config.json" --dry-run
```

Остановить только этот poller: `launchctl bootout gui/$(id -u)/io.shanginn.infra-flux.monitor`. Чтобы он не запускался при следующем входе, убрать только его plist из `~/Library/LaunchAgents/` после остановки; backup LaunchAgent не затрагивать. Сначала сохранить private status/config, если нужна история последнего состояния.

Проверки parser/dedup/fallback limits выполняются `python3 -m unittest discover -s bootstrap/macos -p 'test_monitor_alerts.py'`. Они не заменяют live poll и проверку уведомлений на этом Mac.
