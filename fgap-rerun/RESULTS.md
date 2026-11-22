# SOR-EC0RS7 — K1 re-proof with FGAP enabled (Keycloak 26.8.2)

Date: 2026-11-22. Target: official Keycloak 26.8.2 distribution, `start-dev`,
local instance only (127.0.0.1:8080), fresh server data + fresh realm per run.
Question answered (Sorona triage, 2026-11-22): why were FGAP / admin
permissions disabled in the original reproduction, and does the issue still
reproduce with the intended FGAP configuration enabled?

## VERDICT: CONFIRMED — the issue reproduces unchanged with FGAP enabled,
in two independent runs with identical results (run1 realm `k1fgap1`,
run2 realm `k1fgap2`).

## What changed vs. the original reproduction

| Aspect | Original runs (Nov 16/21) | These runs |
|---|---|---|
| Realm `adminPermissionsEnabled` | `false` (default) | **`true`** (set at realm creation) |
| Permission evaluator in effect | Legacy role-based path | **FGAP V2** (`ADMIN_FINE_GRAINED_AUTHZ_V2` is a default-enabled feature in 26.8.2; `AdminPermissions.evaluator()` selects `MgmtPermissionsV2` / `RolePermissionsV2`) |
| Delegated admin's authority | `manage-clients` realm-management role only | **No realm-management roles at all.** Authority comes only from an FGAP permission on the realm's `admin-permissions` client (see below) |

## FGAP configuration used (evidence: `run{1,2}/fgap-config.json`, `realm-rep.json`)

- Realm created with `adminPermissionsEnabled=true`; Keycloak auto-created the
  `admin-permissions` client holding the FGAP resource server with resource
  types `Clients`, `Groups`, `Organizations`, `Roles`, `Users` and the schema
  scopes (incl. `map-roles-client-scope`, `map-role-client-scope`).
- Delegated admin `delegated`: realm-management role mappings = `[]`
  (its token carries no `resource_access` at all).
- FGAP grant, created through the authorization API of the `admin-permissions`
  client by the trusted master admin:
  - User policy `delegated-admin-user-policy` → user `delegated`.
  - Scope permission `delegated-manage-clients` on the **Clients** resource
    type, scopes `view`, `manage`, `map-roles`, `map-roles-client-scope`,
    `map-roles-composite`, decision strategy UNANIMOUS — i.e. a
    client-management-only delegation expressed through FGAP itself, nothing else.
- Narrowness checks (both runs, delegated token): `GET /clients` → **200**
  (delegation works), `GET /users` → **403**, `GET /admin/realms/{realm}` →
  **403** (no authority beyond client management).

## Attack chain — identical outcome in run1 and run2

| Step | Run1 | Run2 |
|---|---|---|
| Baseline: victim token via `portal` — realm-management roles | `[]` (0) | `[]` (0) |
| Baseline: that token → `GET /admin/realms/{r}/users` | 401 | 401 |
| Legit step: delegated (FGAP) attaches built-in `kc-admin-api` client scope to `portal` | 204 | 204 |
| Victim token afterwards: admin audience present, realm-management roles | still `[]` (0) | still `[]` (0) |
| That token → `GET /admin/realms/{r}/users` | **403** (audience gate passed, role filter still holds) | **403** |
| CONTROL (guarded path): delegated adds `realm-admin` as composite child of `deleg-role` | **403** | **403** |
| Probe: delegated adds plain realm role `plain-role` to `portal2` scope mappings | 403 | 403 |
| Probe: delegated adds composite `innocent-bundle` (child `manage-realm`) to `portal2` scope mappings | 403 | 403 |
| **ATTACK**: delegated `POST /clients/{portal}/scope-mappings/clients/{realm-management}` body `[{"name":"realm-admin"}]` | **204** | **204** |
| Victim token via `portal` after attack: realm-management roles | **22 roles** (incl. `realm-admin`, `manage-realm`, `manage-users`, `manage-clients`, `impersonation`, all `view-*`/`query-*`) | **22 roles** (identical list) |
| IMPACT: that token → `GET /admin/realms/{r}/users` | **200**, 2 entries (`delegated`, `victim`) | **200**, 2 entries |
| IMPACT: that token → `GET /admin/realms/{r}` | **200** | **200** |

## Why FGAP does not stop it (code, tag 26.8.2)

`services/.../fgap/RolePermissionsV2.java`:
- `canMapRole` (:52) and `canMapComposite` (:77) special-case admin roles:
  `canMapRealmAdminRole` / `canMapRealmAdminComposite` return
  `root.isRealmAdmin()` when the realm has admin permissions enabled — a
  non-realm-admin is refused.
- `canMapClientScope` (:109-124) has **no equivalent admin-role check**: for a
  client role it returns `true` as soon as the caller may map client-scope
  roles on the role's container client (`clients().canMapClientScopeRoles(...)`,
  satisfied here by the FGAP Clients permission above) or holds an FGAP
  `map-role-client-scope` permission on the role — the target role being
  `realm-admin` is never inspected.

So the same asymmetry reported originally is present in the FGAP V2 evaluator:
the scope-mapping write path is the one mapping path that does not guard admin
roles, regardless of whether the caller's authority comes from the legacy
`manage-clients` role or from an FGAP client-management permission.

## Files

- `proof_fgap.py` — executable PoC (Python 3 stdlib only); `run_fgap.sh` — harness (fresh server per run).
- `run1/`, `run2/` — per run: `proof-log.txt` (step log), `http-trace.txt`
  (full HTTP request/response trace), `fgap-config.json` (FGAP configuration
  dump: realm flag, resource server resources/scopes, created policy +
  permission), `realm-rep.json`, `token-victim-{baseline,pre-attack,after-attack1,portal2}.json`
  (decoded victim token payloads), `server.log`.
- `DRAFT-REPLY.md` — draft reply to the triager (not sent).
