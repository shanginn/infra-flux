# Установка
## Токен GitHub
https://github.com/settings/tokens?type=beta

- Actions Access: Read-only
- Administration Access: Read and write
- Commit statuses Access: Read-only
- Contents Access: Read and write
- Environments Access: Read-only
- Metadata Access: Read-only
- Variables Access: Read-only

## Установка flux
```bash
export GITHUB_USER=shanginn
export GITHUB_TOKEN=*token*
brew install fluxcd/tap/flux
flux check --pre

flux bootstrap github \
    --owner=$GITHUB_USER \
    --repository=infra-flux \
    --branch=main \
    --path=./clusters/contabo \
    --personal
```

## Required Secrets

The following secrets need to be manually created in the cluster:

### Monitoring Namespace
- `grafana-admin-credentials`
  ```bash
  kubectl create secret generic grafana-admin-credentials \
    --namespace monitoring \
    --from-literal=admin-password='your-secure-password'
  ```
  
## Minio

Нужно создать секрет с переменными окружения для Minio:
```bash
kubectl create secret generic main-storage-env-config \
  --namespace storage \
  --from-literal=config.env='export MINIO_ROOT_USER="ROOT_USERNAME"
export MINIO_ROOT_PASSWORD="ROOT_PASSWORD"'
```

### Пользователь Primerochka
Для работы бакета `primerochka` необходимо создать секрет пользователя (остальная настройка выполняется автоматически через Job):
```bash
kubectl create secret generic primerochka-user \
  --namespace storage \
  --from-literal=CONSOLE_ACCESS_KEY=primerochka-user \
  --from-literal=CONSOLE_SECRET_KEY='your-secure-password'
```

## База данных и Temporal

Для работы Temporal и автоматического создания пользователей в БД необходимо создать следующие секреты:

### 1. Пользователь БД для Temporal
Этот секрет используется CloudNativePG для создания пользователя в БД и Temporal для подключения.
Необходимо создать его **в двух неймспейсах**: `database` (для оператора БД) и `temporal` (для приложения).

```bash
# В неймспейсе database
kubectl create secret generic temporal-db-user \
  --from-literal=username=temporal_user \
  --from-literal=password='YOUR_SECURE_PASSWORD' \
  -n database

# В неймспейсе temporal
kubectl create secret generic temporal-db-user \
  --from-literal=postgresql-password='YOUR_SECURE_PASSWORD' \
  -n temporal
```

### 3. Пользователь и БД для Primerochka
Этот секрет используется CloudNativePG для создания пользователя в БД.
Необходимо создать его в неймспейсе `database`.

```bash
kubectl create secret generic primerochka-db-user \
  --from-literal=username=primerochka \
  --from-literal=password='YOUR_SECURE_PASSWORD' \
  -n database
```

Базу данных необходимо создать вручную (CloudNativePG не поддерживает декларативное создание дополнительных БД):

```bash
kubectl exec -it -n database main-db-1 -- psql -U postgres -c "CREATE DATABASE primerochka OWNER primerochka;"
```

### 2. Basic Auth для Temporal UI (Traefik)
Для защиты веб-интерфейса Temporal используется Basic Auth через Traefik Middleware.
Секрет должен содержать файл `users` в формате htpasswd (сгенерировать можно через `htpasswd -nEb user password`).

```bash
kubectl create secret generic temporal-basic-auth \
  --from-literal=users='admin:$apr1$r4H2C8k6$D1/...' \
  -n kube-system
```

## Squid Proxy

Squid proxy разворачивается в namespace `squid-proxy` и требует создания секрета с аутентификацией.

### Создание пароля для прокси

Сгенерируйте htpasswd hash в формате **MD5** (требуется пакет `apache2-utils`):

```bash
# Установка htpasswd если нужно (Ubuntu/Debian)
# sudo apt-get install apache2-utils

# Генерация пароля в формате MD5 (ВАЖНО: используйте -m, НЕ -B)
htpasswd -nbm username your-secure-password
```

**Важно:** Используйте флаг `-m` (MD5), а не `-B` (bcrypt). Squid `basic_ncsa_auth` не поддерживает bcrypt.

### Создание секрета

```bash
kubectl create secret generic squid-auth \
  --namespace squid-proxy \
  --from-literal=passwd='username:$apr1$xxxxx$xxxxx...'
```

### Использование прокси

#### Внутри кластера
- Адрес: `squid-proxy.squid-proxy.svc.cluster.local:3128`
- Аутентификация: Basic Auth с созданным пользователем

```bash
export http_proxy=http://username:password@squid-proxy.squid-proxy.svc.cluster.local:3128
export https_proxy=http://username:password@squid-proxy.squid-proxy.svc.cluster.local:3128
```

#### Вне кластера (NodePort)

Прокси доступен через NodePort на порту **31128** на любом узле кластера:

```bash
# Замените <node-ip> на IP-адрес одного из узлов вашего кластера
export http_proxy=http://username:password@<node-ip>:31128
export https_proxy=http://username:password@<node-ip>:31128
```

**Примечание:** Contabo не предоставляет нативную поддержку LoadBalancer для Kubernetes (в отличие от AWS/GCP/Azure), поэтому используется NodePort. Это стандартная практика для bare-metal/VPS кластеров.

**Важно:** Убедитесь, что порт 31128 открыт в firewall вашего сервера Contabo:
```bash
# Пример для UFW
sudo ufw allow 31128/tcp

# Или для iptables
sudo iptables -A INPUT -p tcp --dport 31128 -j ACCEPT
```

### Безопасность

- Прокси требует аутентификации (Basic Auth)
- Поддерживается только безопасный набор портов (80, 443, и др.)
- Включен NetworkPolicy для ограничения исходящих соединений
- Рекомендуется ограничить доступ по IP в firewall хоста

### Troubleshooting

#### Ошибка "Cache Access Denied" или "Authentication required"

Проверьте формат пароля - должен быть **MD5** (`$apr1$`), не bcrypt (`$2y$`):
```bash
# Правильно (MD5):
htpasswd -nbm user pass
# myuser:$apr1$xxxxx$xxxxx...

# Неправильно (bcrypt):
htpasswd -nbB user pass
# myuser:$2y$05$xxxxx...
```

#### Ошибка `setuid(0): Operation not permitted`

Эта ошибка в логах означает, что хелпер аутентификации не может прочитать файл паролей. Проверьте что файл смонтирован с правами 0444 (исправлено в deployment.yaml).
