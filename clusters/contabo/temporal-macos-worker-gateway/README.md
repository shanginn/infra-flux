# Generach Mac Temporal worker gateway

Flux owns the Kubernetes ConfigMap, Deployment, and NodePort Service that expose
the production Temporal frontend to the Generach Mac worker through mutual TLS.
The gateway preserves the Temporal gRPC stream and does not change Temporal
server configuration, namespaces, users, or authorization.

The existing `temporal/temporal-macos-worker-gateway-tls` Secret contains only
the CA certificate, server certificate, and server private key. It is kept out
of plaintext Git. The Mac client private key must never be copied to the cluster
or production host.

`host-forwarder.compose.yaml` is the source configuration for the persistent
Docker host forwarder from public TCP port 7233 to the minikube NodePort. Flux
reconciles the Kubernetes resources; the host process is updated from this
committed file only during host maintenance.

Application deployments must not apply these resources or require access to the
`temporal` namespace.
