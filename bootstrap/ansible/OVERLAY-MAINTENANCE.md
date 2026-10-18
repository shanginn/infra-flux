# Ограниченное обслуживание работающей VPN

`overlay-maintenance.yml` меняет одну настройку на одном существующем VPS: маршрут
TLS к единственному координатору либо первоначальную политику трёх узлов перед
подключением старых DNS-серверов. Полный `overlay.yml` для этого не запускается.
Автоматизация не регистрирует клиентов и не переключает координатор.

Входные JSON-файлы и результаты храните вне Git с правами `0600`. Общие поля:
`node`, `cluster_uid`, `ca_sha256`. Для `apply` также нужны SHA256 текущих файлов
`helper_sha256`, `settings_sha256`, `expected_before_sha256` и `kind`.
Хеши helpers вычисляются по точным байтам файлов из `files/`.

Для `kind: relay` задайте `active_host`, прежний HTTPS `server_url` и
`relay_record` формата, описанного в README. Меняется только единственная строка
`server coordinator` внутри `backend headscale`: локальный неактивный `8443`
заменяется проверенным публичным адресом активного координатора на `443`.
Другие маршруты остаются побайтно прежними. Запись relay становится обязательной
для следующих обновлений ingress. Сертификат и база остаются у одного Headscale.

Для `kind: policy` передайте объект `policy`. Поддерживается только ограниченная
подготовительная схема: три существующих Kubernetes-адреса полностью связаны;
тег `legacy-pdns-reader` имеет UDP/TCP `5354` к двум VPS, тег
`legacy-pdns-writer` — TCP `18081` к тем же VPS. Владельцем тегов является
`infra@`. Обязательны положительные тесты существующих узлов. Привязка проверяется
по действующему кластеру и Headscale, политика — через живой `CheckPolicy`.
Поле `expected_headscale_config_sha256` привязывает операцию к проверенному
`headscale.yaml` с `policy.mode: file` и прежним путём политики. Исполняемый файл
координатора закреплён по версии и хешу; процессы и unit-файлы проверяются повторно.
После появления дополнительных клиентов этот первоначальный режим завершается;
дальнейшие изменения требуют отдельной проверенной ограниченной политики отката.

Пример запуска из каталога `bootstrap/ansible`:

```sh
ansible-playbook -i /private/path/inventory.yml overlay-maintenance.yml \
  --limit msk -e overlay_maintenance_action=apply \
  -e overlay_maintenance_input_file=/private/path/relay-apply.json
```

Перед атомарной заменой helper сохраняет точные прежние байты, сверяет процесс,
владение и кластер, проверяет три API и etcd и включает отдельный таймер отката
на 180 секунд. Для HAProxy используется graceful reload; для файловой политики
Headscale — SIGHUP. Изменение PID считается ошибкой. Таймер переживает потерю SSH,
но transient systemd timer не переживает перезагрузку сервера; незавершённая запись
операции остаётся на диске и требует проверки перед продолжением.

После `apply` немедленно проверьте результат извне: прежние DNS/DERP/ingress,
TLS координатора через новый маршрут, фильтры всех существующих Tailscale-клиентов,
API/etcd и реальную двустороннюю доставку UDP между Pod. `policy get` в файловом
режиме читает файл и сам по себе не доказывает загрузку политики клиентами.
Затем создайте отдельный JSON с общими полями, `operation` и
`expected_after_sha256` из результата и выполните тот же playbook с
`overlay_maintenance_action=confirm`. Подтверждение сначала записывается на диск,
затем таймер отключается; оба действия сериализованы с откатом.

При неизвестном результате не повторяйте `apply`. Проверьте запись
`/etc/infra-flux/overlay-maintenance/<operation>.json`, текущий хеш и соответствующие
`infra-overlay-rollback-<operation>.timer/.service`. Helper отказывается затирать
независимые изменения. Ручной запуск того же проверенного отката:

```sh
python3 /etc/infra-flux/overlay-maintenance.py rollback --operation OPERATION_ID
```

Откат политики допускает временно отключившихся прежних клиентов, но запрещён при
смене их идентичности или регистрации нового клиента. **Не регистрируйте старые
серверы, пока ограниченная политика не подтверждена и таймер возврата к прежним
широким разрешениям не отключён.** Обновите политику неактивного standby и резервную
копию после проверки активного координатора. Standby не запускается.

Для точного копирования подтверждённой политики используйте
`overlay-policy-standby.yml --limit msk` с
`overlay_policy_standby_input_file=/private/path/mirror.json`. Приватный JSON
содержит `node`, `active_host`, `cluster_uid`, `ca_sha256`,
`expected_standby_policy_sha256`, `active_operation_id`, `helper_sha256`.
Playbook сверяет подтверждённую операцию и текущие байты на активном сервере,
отключённый таймер отката и неактивность standby. Меняется только файл политики;
служба остаётся выключенной. После этого обновите зашифрованные копии.

Существующие helper-файлы принимаются только при совпадении хеша. При проверенном
обновлении версии можно передать `overlay_maintenance_previous_hashes` с точными
прежними SHA256 двух имён файлов; обновление всё равно запрещено при незавершённой
операции. Не удаляйте записи операций для обхода защиты.

## Alternate TLS path to an existing DERP relay

`derp-transports.json` is an optional root-owned `0600` record on both VPS nodes:
`owner: infra-flux/ansible/derp-transports`, `format: 1`, and `transports` entries
with `region_host`, `via_host`, `via_ipv4` and `upstream_ipv4`. Public addresses
belong in private inputs. The shared routing preflight validates actual site
addresses, rejects loops and conflicting overrides, and preserves the saved
record during ingress maintenance. Initial bootstrap can accept the same list
through `headscale_derp_transports`; later changes require bounded maintenance.

A transport adds an SNI passthrough on the other VPS and a second map entry in
its existing region. `HostName` retains the original TLS identity; `IPv4` changes
only the TCP destination. Both paths reach the **same** DERP process. STUN is
disabled on the extra path. This does not make the remote DERP process redundant.
Headscale 0.29.5 shuffles entries, so direct-path priority is not guaranteed.
Tailscale 1.104.1 tries each TCP dial for up to 1.5 seconds within the overall
10-second connection budget. A TLS failure after TCP connects does not fall
back; HTTP proxy and forced-WebSocket modes require separate validation.

Apply with exact file/service identities, durable preimages and independent
rollback timers: validate and gracefully reload the proxy first, check the
original SNI certificate through it, then install matching maps/records on both
VPS nodes. With the current `auto_update_enabled: false`, Headscale needs a
bounded restart after a fresh verified encrypted coordinator snapshot; SIGHUP
reloads only its ACL policy. Keep the standby inactive. Check all existing node
identities, restricted policy, received client maps and real allowed/denied
traffic before confirming. Never modify an in-flight client's owned hosts file,
helper or deadline to make the new path pass.

The current coordinator snapshot includes `derp.yaml` but not this optional
transport record or HAProxy configuration. The Mac node-configuration export covers their directories `/etc/infra-overlay`
and `/etc/infra-flux`; refresh and verify that export after activation. Also
preserve node-local preimages in the maintenance recovery bundle and restore
them before any future shared-router render. Do not claim the coordinator
snapshot alone restores this alternate path.
