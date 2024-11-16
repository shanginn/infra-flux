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