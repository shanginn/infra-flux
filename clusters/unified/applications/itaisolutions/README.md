# ITAI static site

The base runs the pinned static-site image on HOME and FIN, one replica per site. Both serve the same port 80 Service; each requests 10m CPU and 32MiB memory, with a 128MiB memory limit. Ingress is restricted to Traefik Pods in `ingress-system`. The application has no persistent volume or environment configuration and does not receive a service-account token.

The unified root manages the dedicated `applications-itaisolutions` Flux owner through `../flux.yaml`. Before first publication, create the `itaisolutions` namespace and provision the `dockerconfigjson-github-com` registry Secret there through the private credential workflow. The application owner manages the workload and namespace; it does not manage the registry Secret. Verify the pinned digest can be pulled on both nodes.

Render with `kubectl kustomize clusters/unified/applications/itaisolutions`. Verify both Pods become Ready and the Service has both endpoints. `public-route.yaml` retains host `itaisolutions.ru` and `/` Prefix routing, uses Traefik HTTPS, and supplies an explicit HTTP redirect. Provision `itaisolutions-tls` privately with a valid certificate for the exact hostname before activating this route. The workload owner does not contain credential material.

`certificate.yaml` is temporarily excluded until public DNS reaches this cluster's HTTP01 solver. After the address cutover, add it to the same owner to manage renewal with the existing `letsencrypt-production` issuer, and verify the resulting Certificate is Ready. Keep the valid bootstrap Secret throughout this transition.

Before changing public DNS, compare the old and new `/` response and referenced static assets, and check HTTP redirection and trusted HTTPS with the intended Host/SNI through both VPS edges. A direct-IP request with the wrong Host does not validate this route. Retain old endpoints for their measured DNS cache windows. This owner does not change DNS records or legacy Helm releases.
