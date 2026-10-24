# porkbun-arm64-webhook

A [cert-manager](https://cert-manager.io/) **DNS01 webhook for [Porkbun](https://porkbun.com/)**, built for **arm64 and amd64**.
It lets cert-manager issue Let's Encrypt certificates — including **wildcards** — for domains whose DNS is hosted at Porkbun, on clusters such as k3s on Raspberry Pi.

This is a maintained, hardened fork of [mdonoughe/porkbun-webhook](https://github.com/mdonoughe/porkbun-webhook), whose published image is amd64-only and was last released in October 2024.

| | |
|---|---|
| Image | `ghcr.io/captainmack/porkbun-arm64-webhook` (`linux/amd64`, `linux/arm64`) |
| Helm chart | `oci://ghcr.io/captainmack/charts/porkbun-webhook` (or `./deploy/porkbun-webhook`) |
| Solver name | `porkbun` |
| License | Apache-2.0 |

## How it works

cert-manager asks the webhook to *present* a DNS01 challenge. The webhook reads your Porkbun API keys from a Kubernetes Secret, creates the `_acme-challenge` TXT record through the [Porkbun API](https://porkbun.com/api/json/v3/documentation), and deletes it again on *cleanup*. That is all it does: it never sees your certificates or private keys, and it only talks to the Kubernetes API and `api.porkbun.com`.

```
cert-manager ──(APIService v1alpha1.<groupName>)──▶ webhook ──▶ api.porkbun.com
                                                       │
                                                       └─ reads Secret <credentials> (get, named only)
```

## Differences from upstream

- **Multi-arch image** (`linux/amd64`, `linux/arm64`), cross-compiled without emulation.
- **Hardened runtime:** distroless static base, runs as non-root UID 65532, read-only root filesystem, all capabilities dropped, `RuntimeDefault` seccomp, resource limits. Listens on 8443 (the Service still exposes 443).
- **Least-privilege RBAC:** the chart grants `get` on the named credentials Secret(s) only, in one namespace — upstream left this as a manual step.
- **Supply chain:** base images pinned by digest, GitHub Actions pinned by commit SHA, images ship an SBOM and SLSA provenance and are **signed with cosign** (keyless).
- **Up-to-date dependencies:** cert-manager v1.21, Kubernetes client v0.36, Go 1.27; `govulncheck` clean.
- **Fixes:** TXT records use Porkbun's minimum TTL (300 s — upstream's 60 s is below it), and record IDs are parsed as 64-bit (upstream's 32-bit parse breaks once IDs pass 2³¹).
- **Flow-control RBAC** that current cert-manager webhook libraries need.

## Requirements

- Kubernetes ≥ 1.29 and cert-manager ≥ 1.14 installed in the `cert-manager` namespace.
- A Porkbun domain with **API access enabled** for it (Domain Management → *API Access* toggle on the domain), and an API key pair from <https://porkbun.com/account/api>.
- Helm 3.8+ (for OCI charts).

## Installation

### 1. Store the Porkbun API keys

For a `ClusterIssuer`, cert-manager resolves secrets in its *cluster resource namespace* — `cert-manager` by default — so the Secret goes there:

```sh
kubectl -n cert-manager create secret generic porkbun-credentials \
  --from-literal=api-key='pk1_…' \
  --from-literal=secret-key='sk1_…'
```

### 2. Install the webhook

Pick a `groupName` that is unique to you — a domain you own, for example `acme.example.com`. It identifies the webhook's API group and must match the issuer.

```sh
helm install porkbun-webhook oci://ghcr.io/captainmack/charts/porkbun-webhook \
  --version 0.2.0 \
  --namespace cert-manager-webhook-porkbun --create-namespace \
  --set groupName=acme.example.com
```

From a checkout instead: `helm install porkbun-webhook ./deploy/porkbun-webhook …` with the same flags.

If your Secret has a different name, or you use a namespaced `Issuer`, set `credentials.namespace` and `credentials.secretNames` (see [Configuration](#configuration)).

Check that it is up and registered:

```sh
kubectl -n cert-manager-webhook-porkbun get pods
kubectl get apiservice v1alpha1.acme.example.com   # AVAILABLE should be True
```

### 3. Create an issuer

```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-porkbun
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: you@example.com
    privateKeySecretRef:
      name: letsencrypt-porkbun-account-key
    solvers:
      - selector:
          dnsZones: ["example.com"]
        dns01:
          webhook:
            groupName: acme.example.com   # same as the chart's groupName
            solverName: porkbun
            config:
              apiKeySecretRef:
                name: porkbun-credentials
                key: api-key
              secretKeySecretRef:
                name: porkbun-credentials
                key: secret-key
```

Try it first against Let's Encrypt **staging** (`https://acme-staging-v02.api.letsencrypt.org/directory`) to avoid production rate limits.

### 4. Request a certificate

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: example-wildcard
  namespace: default
spec:
  secretName: example-wildcard-tls
  issuerRef:
    kind: ClusterIssuer
    name: letsencrypt-porkbun
  dnsNames:
    - example.com
    - "*.example.com"
```

```sh
kubectl describe certificate example-wildcard   # Ready=True after a minute or two
```

## Configuration

| Value | Default | Description |
|---|---|---|
| `groupName` | — (**required**) | API group for the webhook; must match `groupName` in issuers. |
| `credentials.namespace` | `cert-manager` | Namespace of the credentials Secret(s). For a namespaced `Issuer`, use the issuer's namespace. |
| `credentials.secretNames` | `[porkbun-credentials]` | Secret names the webhook may read (`get` only). |
| `certManager.namespace` | `cert-manager` | Namespace cert-manager runs in. |
| `certManager.serviceAccountName` | `cert-manager` | cert-manager's ServiceAccount (granted access to the solver API). |
| `image.repository` | `ghcr.io/captainmack/porkbun-arm64-webhook` | Image repository. |
| `image.tag` | chart `appVersion` | Image tag. Pinning a digest via `image.repository@sha256:…` is also fine. |
| `securePort` | `8443` | Container HTTPS port (unprivileged). |
| `podSecurityContext`, `securityContext` | hardened (see `values.yaml`) | Pod/container security settings. |
| `resources` | 10m/32Mi requests, 200m/128Mi limits | Container resources. |
| `nodeSelector`, `tolerations`, `affinity` | empty | Scheduling. |

The solver accepts this `config` block in the issuer:

| Field | Description |
|---|---|
| `apiKeySecretRef` | `{name, key}` of the Porkbun API key (`pk1_…`). |
| `secretKeySecretRef` | `{name, key}` of the Porkbun secret API key (`sk1_…`). |

## Security

- **What it can access.** Kubernetes: `get` on the listed Secret names in one namespace, plus the standard delegated-auth permissions every cert-manager webhook needs (`system:auth-delegator`, reading the API server's authentication ConfigMap, and listing flow-control objects). Network: the Kubernetes API and `api.porkbun.com`.
- **What it does with your keys.** Sends them to Porkbun to create and delete `_acme-challenge` TXT records. Keys are never logged.
- **Scope your Porkbun key.** Porkbun keys are account-wide; enable API access only on the domains that need certificates.
- **Verify the image** before deploying it (cosign **v3+**; older versions don't see the new signature format, and the identity is case-sensitive):

  ```sh
  cosign verify ghcr.io/captainmack/porkbun-arm64-webhook:0.2.0 \
    --certificate-identity-regexp '^https://github.com/CaptainMack/porkbun-arm64-webhook/\.github/workflows/release\.yml@refs/(heads/main|tags/v.*)$' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com
  ```

To report a vulnerability, open a [private security advisory](https://github.com/captainmack/porkbun-arm64-webhook/security/advisories/new) rather than a public issue.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| Challenge stuck `pending`, `PresentError … is forbidden: … cannot create resource "porkbun" in API group "<group>"` | The issuer's `groupName` doesn't match the chart's, or `certManager.serviceAccountName`/`namespace` is wrong. |
| `APIService … AVAILABLE False` | Webhook pod not ready or its serving certificate not issued yet: `kubectl -n cert-manager-webhook-porkbun describe pod`, `kubectl -n cert-manager-webhook-porkbun get certificate`. |
| `get error for secret "cert-manager" "…": … forbidden` | The Secret name isn't in `credentials.secretNames`, or it's in another namespace than `credentials.namespace`. |
| `retrieve records error` / `create record error` with an auth message | Wrong keys, or **API access not enabled** on that domain in the Porkbun dashboard. |
| `exec format error` | You're running an amd64-only image on arm64 — use this image. |
| Challenge presented but never validates | DNS propagation; check `dig TXT _acme-challenge.example.com @curitiba.ns.porkbun.com`. cert-manager waits for propagation before asking Let's Encrypt. |

Webhook logs: `kubectl -n cert-manager-webhook-porkbun logs deploy/porkbun-webhook`. cert-manager logs: `kubectl -n cert-manager logs deploy/cert-manager`.

## Upgrading from mdonoughe/porkbun-webhook

The solver name and issuer `config` format are unchanged. Install this chart, point your issuers' `groupName` at it (or reuse your existing group name), make sure `credentials.secretNames` lists your Secret, and remove the old release.

## Development

```sh
go build ./... && go vet ./...
docker buildx build --platform linux/arm64,linux/amd64 .
```

**Conformance suite.** cert-manager's DNS01 conformance tests (`main_test.go`) run against a real Porkbun zone and a local control plane:

1. Copy `testdata/porkbun-solver/` and put real keys in `porkbun-secret.yaml` (never commit them).
2. Run `TEST_ZONE_NAME=example.com. make test` (downloads etcd/kube-apiserver test binaries).

## Credits

Original webhook by [Matthew Donoughe](https://github.com/mdonoughe/porkbun-webhook) (Apache-2.0); Porkbun API client by [nrdcg/porkbun](https://github.com/nrdcg/porkbun). This fork keeps the upstream history.
