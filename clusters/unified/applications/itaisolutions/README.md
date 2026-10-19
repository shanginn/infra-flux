# ITAI static site

The base runs the pinned static-site image on HOME and FIN, one replica per site. Both serve the same port 80 Service; each requests 10m CPU and 32MiB memory, with a 128MiB memory limit. Ingress is restricted to Traefik Pods in `ingress-system`. The application has no persistent volume or environment configuration and does not receive a service-account token.

The unified root manages the dedicated `applications-itaisolutions` Flux owner through `../flux.yaml`. Before first publication, create the `itaisolutions` namespace and provision the `dockerconfigjson-github-com` registry Secret there through the private credential workflow. The application owner manages the workload and namespace; it does not manage the registry Secret. Verify the pinned digest can be pulled on both nodes.

Render with `kubectl kustomize clusters/unified/applications/itaisolutions`. Verify both Pods become Ready and the Service has both endpoints. `public-route.yaml` retains host `itaisolutions.ru` and `/` Prefix routing, uses Traefik HTTPS, and supplies an explicit HTTP redirect. Provision `itaisolutions-tls` privately with a valid certificate for the exact hostname before activating this route. The workload owner does not contain credential material.

`certificate.yaml` manages renewal through the same owner with the existing `letsencrypt-production` issuer and the same `itaisolutions-tls` Secret. Keep the valid bootstrap Secret while cert-manager adopts it or obtains a replacement. With `rotationPolicy: Always`, the serving key is replaced only after a signed certificate is available. Do not request a temporary certificate or delete the bootstrap Secret. Cached prior DNS addresses can delay HTTP01 validation; verify the actual Certificate status and continued trusted HTTPS separately.

Before changing public DNS, compare the old and new `/` response and referenced static assets, and check HTTP redirection and trusted HTTPS with the intended Host/SNI through both VPS edges. A direct-IP request with the wrong Host does not validate this route. Retain old endpoints for their measured DNS cache windows. This owner does not change DNS records or legacy Helm releases.
