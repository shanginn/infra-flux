# ITAI static site

The base runs the pinned static-site image on HOME and FIN, one replica per site. Both serve the same port 80 Service; each requests 10m CPU and 32MiB memory, with a 128MiB memory limit. Ingress is restricted to Traefik Pods in `ingress-system`. The application has no persistent volume or environment configuration and does not receive a service-account token.

The unified root manages the dedicated `applications-itaisolutions` Flux owner through `../flux.yaml`. Before first publication, create the `itaisolutions` namespace and provision the `dockerconfigjson-github-com` registry Secret there through the private credential workflow. The application owner manages the workload and namespace; it does not manage the registry Secret. Verify the pinned digest can be pulled on both nodes.

Render with `kubectl kustomize clusters/unified/applications/itaisolutions`. Verify both Pods become Ready and the Service has both endpoints. Public routing files are deliberately excluded from the base: `public-route.yaml` retains host `itaisolutions.ru` and `/` Prefix routing, uses Traefik HTTPS, and supplies an explicit HTTP redirect. `certificate.yaml` uses the existing `letsencrypt-production` issuer. Add these files to the same owner only once ACME reachability and a valid certificate are established; do not publish a hostname switch merely because the Pods are Ready.

Before external activation, compare the old and new `/` response and referenced static assets, check HTTP redirection and trusted HTTPS with the intended Host/SNI, and test through the FIN edge. A direct-IP request with the wrong Host does not validate this route. No legacy Helm release, DNS record or public endpoint is changed by the base.
