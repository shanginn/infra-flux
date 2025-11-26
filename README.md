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
