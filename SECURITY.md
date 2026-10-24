# Security

## Reporting a vulnerability

Please report vulnerabilities privately through [GitHub security advisories](https://github.com/CaptainMack/porkbun-arm64-webhook/security/advisories/new), not in public issues. Include the affected version, a description and, if possible, steps to reproduce. You can expect an acknowledgement within a few days.

Only the latest release is supported with fixes.

## Threat model

The webhook holds a **Porkbun API key pair**, which Porkbun scopes to the whole account (limited only by which domains have *API access* enabled). Anyone who can make the webhook act can create or delete DNS records on those domains — enough to obtain certificates for them or to redirect traffic. The design therefore narrows who can reach it and what it does:

| Concern | Control |
|---|---|
| Who can call the solver | The webhook serves an aggregated API (`v1alpha1.<groupName>`) behind the Kubernetes API server, with delegated authentication and authorization. The chart grants `create` on the single resource `porkbun` in that group to cert-manager's ServiceAccount only. |
| Which secrets it can read | `get` on the Secret names listed in `credentials.secretNames`, in `credentials.namespace` only. No `list`/`watch`, so it cannot discover other secrets. |
| What it can change in DNS | Present creates one TXT record; CleanUp deletes only a TXT record whose name **and** content match the challenge. Record names outside the resolved zone are rejected before any API call. |
| Secret handling | Keys go to `api.porkbun.com` over HTTPS (10 s client timeout) and are never logged; error messages name the Secret, never its contents. Logged challenge tokens are public by design (they are published in DNS). |
| Container | Distroless static image, non-root UID 65532, read-only root filesystem, all capabilities dropped, `RuntimeDefault` seccomp, no shell or package manager, resource limits. |
| API server ↔ webhook TLS | Serving certificate from a chart-local cert-manager CA (5 y CA / 1 y leaf, auto-renewed), injected into the APIService `caBundle`. |
| Supply chain | Go modules verified by `go.sum`; base images pinned by digest; Actions pinned by commit SHA with least-privilege `permissions`; images published with SBOM + SLSA provenance and signed keyless with cosign (see README for `cosign verify`). |

### Residual risks

- **Account-wide Porkbun keys.** Porkbun has no per-domain keys; enable API access only on domains that need certificates and rotate keys if a cluster is compromised.
- **Namespaced Issuers.** If you list a namespace other than cert-manager's in `credentials.namespace`, anyone who can create Issuers there can point them at the webhook and make it use the credentials in that namespace — keep such namespaces trusted.
- **No NetworkPolicy shipped.** Egress could be restricted to the Kubernetes API, DNS and `api.porkbun.com:443`; the chart doesn't do this because API-server addresses differ per distribution. Add one for your cluster if you need it.

## Security review (fork, v0.2.x)

Findings from reviewing upstream `mdonoughe/porkbun-webhook` at `1d558a7` and the changes made here:

| # | Finding | Severity | Resolution |
|---|---|---|---|
| 1 | Published image is amd64-only and runs as root; Dockerfile used floating base tags | Medium | Multi-arch distroless non-root image, digest-pinned bases, signed with SBOM/provenance |
| 2 | Chart had no RBAC for reading the credentials Secret (left to a manual step) | Low | Name-scoped, `get`-only Role in one namespace |
| 3 | `domain-solver` ClusterRole granted `create` on `*` in the group (Trivy KSV-0046) | Low | Narrowed to the `porkbun` resource |
| 4 | Container listened on 443 (needs root / `NET_BIND_SERVICE`) | Low | Listens on 8443; Service still exposes 443 |
| 5 | Challenge FQDN not checked against the zone; a malformed request could target a record outside it | Low | `recordNames` rejects names outside the zone, before any API call |
| 6 | TXT TTL 60 s, below Porkbun's 300 s minimum | Bug | Uses `porkbun.DefaultTTL` |
| 7 | Record IDs parsed as int32; deletion fails once IDs pass 2³¹ | Bug | Parsed as int64 |
| 8 | Dependencies two years old (cert-manager v1.16, client-go v0.31, archived `pkg/errors`) | Medium | cert-manager v1.21, client-go v0.36, Go 1.27; `pkg/errors` removed |
| 9 | Missing flow-control RBAC required by current webhook libraries | Bug | Added (`list`/`watch` on flow-control objects) |

`govulncheck` reports no reachable vulnerabilities. It flags `golang.org/x/crypto/openpgp` (GO-2026-5932) in a required module, but the webhook never imports it.

## Continuous checks

Every push and pull request, and weekly, CI runs: `gofmt`, `go vet`, unit tests with the race detector, multi-arch builds, `golangci-lint` (including `gosec`), `govulncheck`, Helm lint plus schema validation (kubeconform) and assertions on the rendered hardening, hadolint, a container smoke test, Trivy image CVE and misconfiguration scans, and CodeQL (`security-extended`). Dependabot keeps Go modules, base images and Actions current.
