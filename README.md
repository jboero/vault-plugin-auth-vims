# vault-plugin-auth-vims

> **Disclaimer:** This project was vibe-coded by Claude (Anthropic) and John Boero
> as an early-stage proof of concept. It is **not recommended for production use**.
> No security audit has been performed. Use at your own risk.
>
> Source: [github.com/jboero](https://github.com/jboero)

A **Vault / OpenBao auth method plugin** that authenticates virtual machines
by verifying their identity through a [VIMS](../vims/) (VM Identity Metadata
Service) instance.

Built against the [OpenBao SDK v2](https://pkg.go.dev/github.com/openbao/openbao/sdk/v2),
which is wire-compatible with both OpenBao and HashiCorp Vault.

---

## How It Works

```
VM                     Vault/OpenBao              VIMS            Hypervisor
 │                          │                       │                 │
 ├─ vault write             │                       │                 │
 │  auth/vims/login ───────►│                       │                 │
 │  role=web-tier           │                       │                 │
 │                          ├─ GET /v1/identity ───►│                 │
 │                          │  ?source_ip=10.0.1.10 ├─ IP→VM lookup ►│
 │                          │                       │◄─ VM metadata ──┤
 │                          │◄─ {vm, attestation} ──┤                 │
 │                          │                       │                 │
 │                          ├─ Match VM against     │                 │
 │                          │  role bindings:        │                 │
 │                          │  folder, tags, cluster │                 │
 │                          │  attestation level     │                 │
 │                          │                       │                 │
 │  {auth: {client_token,   │                       │                 │
 │   policies, metadata}}   │                       │                 │
 │◄─────────────────────────┤                       │                 │
```

1. A VM calls `vault write auth/vims/login role=web-tier`
2. The plugin extracts the VM's source IP from the TCP connection
3. The plugin queries VIMS to verify the VM's identity (VIMS resolves the IP to a VM via the hypervisor management API)
4. The plugin matches the VM's attributes against the named role's binding constraints
5. If everything matches, Vault/OpenBao issues a token with the role's policies and TTL

**On token renewal**, the plugin re-queries VIMS to verify the VM still exists at the same IP and still matches the role. If the VM has been migrated, destroyed, or its tags changed, renewal is denied.

---

## Quick Start

### Build

```bash
go mod tidy
make build
# Produces: bin/vault-plugin-auth-vims
```

### With OpenBao

```bash
# Terminal 1: Start OpenBao dev server
bao server -dev -dev-root-token-id=root -dev-plugin-dir=./bin

# Terminal 2: Register and enable
export BAO_ADDR=http://127.0.0.1:8200
export BAO_TOKEN=root

SHA=$(sha256sum bin/vault-plugin-auth-vims | cut -d' ' -f1)
bao plugin register -sha256=$SHA auth vault-plugin-auth-vims
bao auth enable -path=vims vault-plugin-auth-vims
```

### With HashiCorp Vault

```bash
# Terminal 1: Start Vault dev server
vault server -dev -dev-root-token-id=root -dev-plugin-dir=./bin

# Terminal 2: Register and enable
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=root

SHA=$(sha256sum bin/vault-plugin-auth-vims | cut -d' ' -f1)
vault plugin register -sha256=$SHA auth vault-plugin-auth-vims
vault auth enable -path=vims vault-plugin-auth-vims
```

### Configure (same commands for both)

```bash
# Point the plugin at your VIMS instance
vault write auth/vims/config \
  vims_addr=http://127.0.0.1:8169

# Create a role for production web servers
vault write auth/vims/role/web-tier \
  bound_folder="/Production/Web/*" \
  bound_tags="env=production,role=web" \
  min_attestation_level=0 \
  token_policies="web-secrets-read" \
  token_ttl=1h

# Login (from a VM whose IP maps to a matching VM in VIMS)
vault write auth/vims/login role=web-tier
```

### End-to-End Test with VIMS Dev Mode

```bash
# Terminal 1: Start VIMS in dev mode (stub VMs, 127.0.0.1 = web-01)
cd ../vims && make dev

# Terminal 2: Start Vault/OpenBao with plugin
cd ../vault-plugin-auth-vims && make build
vault server -dev -dev-root-token-id=root -dev-plugin-dir=./bin

# Terminal 3: Configure and test
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=root

SHA=$(sha256sum bin/vault-plugin-auth-vims | cut -d' ' -f1)
vault plugin register -sha256=$SHA auth vault-plugin-auth-vims
vault auth enable -path=vims vault-plugin-auth-vims

vault write auth/vims/config vims_addr=http://127.0.0.1:8169

vault write auth/vims/role/web-tier \
  bound_folder="/Production/Web/*" \
  bound_tags="env=production,role=web" \
  token_policies=default \
  token_ttl=1h

# This should succeed — VIMS dev mode maps 127.0.0.1 → web-01
vault write auth/vims/login role=web-tier
```

---

## Configuration Reference

### `auth/vims/config` — Plugin Configuration

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `vims_addr` | string | yes | VIMS service address (e.g. `http://169.254.169.254:80`) |
| `tls_skip_verify` | bool | no | Skip TLS certificate verification for VIMS |
| `ca_cert` | string | no | PEM-encoded CA certificate for VIMS TLS |

### `auth/vims/role/:name` — Role Definitions

Roles define which VMs can authenticate and what token they receive.
All non-empty `bound_*` fields must match (AND logic).

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `bound_folder` | string | | Required inventory folder path (glob, e.g. `/Production/Web/*`) |
| `bound_tags` | map | | Required tags — all must be present on the VM |
| `bound_resource_pool` | string | | Required resource pool name |
| `bound_cluster` | string | | Required compute cluster name |
| `bound_datacenter` | string | | Required datacenter name |
| `bound_name_glob` | string | | VM name glob pattern (e.g. `web-*`) |
| `min_attestation_level` | int | `0` | Minimum attestation: 0=IP, 1=BIOS UUID, 2=vTPM |
| `token_policies` | list | | Vault/OpenBao policies attached to the issued token |
| `token_ttl` | duration | | Token TTL |
| `token_max_ttl` | duration | | Token maximum TTL |
| `token_period` | duration | | Token period (for periodic tokens) |

### `auth/vims/login` — Login (Unauthenticated)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `role` | string | yes | Name of the role to authenticate against |

---

## Security Model

- **Trust chain:** Vault/OpenBao → VIMS → Hypervisor management API. The plugin trusts VIMS to have performed source IP correlation, attestation, and policy evaluation.
- **Binding constraints:** Even after VIMS identifies a VM, the role's `bound_*` fields add a second layer of matching inside Vault.
- **Attestation levels:** `min_attestation_level` on roles can require BIOS UUID proof (Level 1) or vTPM cryptographic attestation (Level 2) before login succeeds.
- **Renewal re-verification:** Every token renewal re-queries VIMS. Stolen tokens become useless when the source VM is destroyed, migrated, or re-tagged.
- **Entity alias:** Keyed on the VM's managed object reference (globally unique, hypervisor-assigned, immutable from the guest).

---

## Project Structure

```
vault-plugin-auth-vims/
├── cmd/vault-plugin-auth-vims/main.go   # Plugin binary entrypoint
├── plugin/backend.go                     # Auth backend: config, roles, login, matching
├── Makefile
├── go.mod                                # OpenBao SDK v2 deps
└── README.md
```

---

## Known Limitations (PoC)

- The `?source_ip=` parameter on VIMS is not authenticated — in production, the plugin→VIMS path must be secured with TLS/mTLS or network isolation
- No built-in entity alias deduplication for VMs that change IP
- Tag matching uses exact string comparison (case-insensitive), no regex
- The plugin does not cache VIMS responses — every login and renewal hits VIMS
- `ca_cert` config field is accepted but not yet wired into the HTTP client's TLS config

---

## License

MPL-2.0
