# Сертификаты приложений

cert-manager 1.21.2 установлен официальным OCI chart, закреплённым digest, с закреплёнными образами. По две реплики controller, webhook и cainjector распределены между VPS. Issuer создаётся отдельной Flux Kustomization только после готовности оператора и CRD.

`letsencrypt-production` выдаёт сертификаты через HTTP-01 и Traefik. Для нового приложения нужен обычный Ingress с `ingressClassName: traefik`, аннотацией `cert-manager.io/cluster-issuer: letsencrypt-production` и собственным `spec.tls[].secretName`. DNS имени должен указывать на рабочий ingress. Namespace NetworkPolicy должен разрешать Traefik доступ к временным solver Pods на TCP 8089. Cert-manager сам управляет продлением и ключами; не хранить их в Git.

Этот оператор не меняет существующие сертификаты Headscale/DERP на уровне ОС. ACME account и выданные сертификаты входят в зашифрованный snapshot etcd. Проверяйте `Certificate Ready`, срок действия и реальный HTTPS через обе VPS; готовый HelmRelease сам по себе не доказывает успешную выдачу сертификата.

Источники: [официальная установка](https://cert-manager.io/docs/installation/helm/), [HTTP-01](https://cert-manager.io/docs/configuration/acme/http01/).
