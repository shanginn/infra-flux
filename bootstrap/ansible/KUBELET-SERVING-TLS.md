# Приватные метрики kubelet с проверкой TLS

`kubelet-serving-tls.yml` включает `serverTLSBootstrap: true` отдельно от неизменяемого kubeadm bootstrap. Prometheus обращается к приватному Node InternalIP:10250 с Kubernetes CA и своим ServiceAccount token. Его право — `get nodes/metrics`; `nodes/proxy`, клиентский ключ администратора и `insecure_skip_verify` не нужны.

Требования: все три control plane/API/etcd здоровы, Kubernetes v1.36.5, завершено [обслуживание kubelet HA endpoint](KUBELET-MAINTENANCE.md), активен собственный API proxy. На узлах нужны Python3, PyYAML и cryptography>=43; По умолчанию inspection ничего не устанавливает. Отдельный opt-in `kubelet_serving_tls_install_prerequisites: true` устанавливает только отсутствующие `python3-yaml`/`python3-cryptography` из настроенного Debian repository после stdlib ownership/CA/Debian13 guard, без обновления установленных пакетов и с `policy_rc_d: 101`. Это не включает TLS apply. Существующая конфигурация должна принадлежать root, использовать webhook authentication/authorization и не содержать альтернативных TLS-файлов/CLI overrides. Только Node Hostname и единственный InternalIP допускаются в SAN; добавление иных адресов требует отдельного review.

Сначала выполнить read-only inspection:

```sh
ansible-playbook -i /private/path/inventory.yml kubelet-serving-tls.yml
```

Сохранить вне Git для каждого узла `config_sha256` и identity ровно из пяти полей: `node`, `node_uid`, `machine_id`, `ca_sha256`, `bootstrap_sha256`. Передать их как `kubelet_serving_tls_expected_config_sha256` и `kubelet_serving_tls_expected_identity`; включить `kubelet_serving_tls_apply: true` только после review. Playbook требует полный inventory из трёх узлов и выполняет изменение последовательно (`serial: 1`). Проверенный preimage и bootstrap сохраняются root:root0600 под `/etc/infra-flux/kubelet-serving-tls`; исходный mode config сохраняется. Единственное изменяемое поле config — `serverTLSBootstrap`; immutable bootstrap fingerprint не меняется.

На узле helper удерживает общий CAS lock с fault tests/другим maintenance. До однократного restart kubelet сохраняются намерение, PID/lease и PID всех работающих контейнеров. Он не перезапускает Pods. После restart ожидается ровно один свежий serving CSR с authenticated requester `system:node:<node>`, группами `system:nodes`/`system:authenticated`, точным subject, адресами и допустимыми usages. Kubernetes `authentication.kubernetes.io/credential-id` должен точно совпасть с SHA256 DER текущего kubelet client certificate; иные extra fields или другой fingerprint отклоняются. Для стандартного ECDSA P256 это `digital signature` + `server auth`; RSA дополнительно требует `key encipherment`. Лишние SAN, client auth, CA extensions, неизвестные алгоритмы и неоднозначные запросы отклоняются.

Approval — один PUT точного CSR UID/resourceVersion после durable intent. Потеря ответа означает неизвестный результат: повторный запуск только читает этот CSR, подпись и restart повторно не отправляет. После выдачи проверяются CA, срок, SAN и EKU, совпадение SPKI CSR с локальным сохранённым keypair и сертификатом реального TLS10250 endpoint. Завершение требует новых lease renewals, неизменных PID контейнеров, трёх здоровых API/etcd и стабильных 30 секунд.

**Граница доказательства:** в Kubernetes v1.36.5 pending serving private key существует только в памяти kubelet до получения сертификата. До approval невозможно сравнить его с файлом на диске. Проверка опирается на authenticated node requester, свежий единственный CSR после собственного restart и свежую NodeUID/machine/CA identity; соответствие приватному ключу и реальному endpoint проверяется после подписи. Это не независимая аттестация незломанного узла.

При timeout lock остаётся активным. Не запускать следующий узел и не снимать lock вслепую. Read-only inspection всего inventory может встретить lock другого узла: возобновлять **точный helper apply только владельца lock** с исходными review/hash/source, затем повторять полный playbook. Ни restart, ни approval при unknown dispatch не повторяются. Частичный private каталог без `record.json` требует ручного сохранения/проверки содержимого; helper не присваивает его автоматически. Если CSR уже старше 15 минут, node перезагрузился или контейнеры изменились, нужен отдельный review — автоматического rollback TLS/чужой подписи нет.

## Продление

Kubelet сам создаёт запросы на продление; signer Kubernetes не утверждает serving CSR автоматически. Правила `KubeletServingCSRPending`, `KubeletServingCertificateExpiresSoon` (14 дней) и `KubeletServingCertificateCritical` (2 дня) требуют действий оператора. Нет постоянно работающего autoapprover.

Для конкретного узла вызвать helper `inspect-renewal --csr-name <exact-name>` через существующий SSH alias. Он читает CSR и выдаёт только identity/UID/request hash. После review вызвать `approve-renewal` с тем же CSR name, `--csr-uid`, `--csr-sha256`, `--ca-sha256` и `--review-json` из пяти полей identity. Обе команды принимают исходники pinned helpers через `--endpoint-source` и `--shared-source`, как исходный playbook. Для безопасной передачи аргументов без ручного shell escaping можно использовать локальный Python из корня repository:

```python
from pathlib import Path
import json, shlex, subprocess
root = Path('bootstrap/ansible/files')
review = json.loads(Path('/private/path/review.json').read_text())
args = ['python3', '-c', (root/'kubelet-serving-tls.py').read_text(),
        'inspect-renewal', '--node', review['node'], '--csr-name', review['csr_name'],
        '--endpoint-source', (root/'kubelet-endpoint-maintenance.py').read_text(),
        '--shared-source', (root/'etcd-probe-maintenance.py').read_text()]
# После review заменить действие на approve-renewal и добавить точные
# --csr-uid/--csr-sha256/--ca-sha256/--review-json; никаких wildcard/list approvals.
subprocess.run(['ssh', '-o', 'BatchMode=yes', review['ssh_alias'], shlex.join(args)], check=True)
```

Approval renewal не перезапускает kubelet и не меняет config. Он снова проверяет свежий NodeUID/CA/machine, владение cluster lock и три здоровых узла, подписывает только один выбранный запрос, затем проверяет сохранённый ключ и действующий TLS endpoint. Per-CSR proof находится в `renewals/<csr-name>/record.json`. Не утверждать старый CSR вместо нового запроса после истечения его 15-минутного окна.

Перед включением прямых Prometheus jobs проверить реальный scrape всех трёх узлов от ServiceAccount monitoring/prometheus, отсутствие `nodes/proxy` и public10250. Метрики ресурсов не требуют metrics-server; он нужен отдельно для Kubernetes resource metrics API/HPA и здесь не устанавливается.

Официальные источники: [kubeadm serving certificates](https://kubernetes.io/docs/tasks/administer-cluster/kubeadm/kubeadm-certs/#kubelet-serving-certs), [kubelet authentication/authorization](https://kubernetes.io/docs/reference/access-authn-authz/kubelet-authn-authz/), [kubelet v1.36.5 CSR templates](https://github.com/kubernetes/kubernetes/blob/v1.36.5/pkg/kubelet/certificate/kubelet.go), [client-go v0.36.5 key generation and persistence](https://github.com/kubernetes/client-go/blob/v0.36.5/util/certificate/certificate_manager.go).
