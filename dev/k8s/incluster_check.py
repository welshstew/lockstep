"""Run inside the k3s cluster against the Helm release (make helm-test): signs in with
Kubernetes auth as the chart's service account, checks that the replicas share sessions,
runs a comparison, and checks the role allowlist. Exits non-zero on any failure."""
import urllib.error
import http.cookiejar, json, urllib.request
base = "http://lockstep.lockstep-helm.svc"
op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
def call(method, path, body=None):
    req = urllib.request.Request(base + path, method=method, data=json.dumps(body).encode() if body else None,
                                 headers={"X-Requested-With": "lockstep", "Content-Type": "application/json"})
    with op.open(req, timeout=20) as r:
        return json.load(r)
cfg = call("GET", "/api/config")
print("config: presets", [p["name"] for p in cfg["presets"]], "k8s", cfg["k8s_auth"])
assert cfg["k8s_auth"]["available"] and cfg["k8s_auth"]["service_account"] == "lockstep-helm/lockstep", cfg
a = call("POST", "/api/connections", {"preset_id": 0, "auth": {"method": "kubernetes", "role": "lockstep-helm"}})
b = call("POST", "/api/connections", {"preset_id": 1, "auth": {"method": "kubernetes", "role": "lockstep-helm"}})
print("signed in:", a["display_name"], a["policies"], "|", b["display_name"])
assert a["display_name"] == "kubernetes-lockstep-helm-lockstep" and "lockstep-readonly" in a["policies"]
seen = set()
for _ in range(12):  # through the Service: requests land on both replicas
    seen.add(len(call("GET", "/api/connections")))
print("connections seen on every request:", seen)
assert seen == {2}, "replicas don't share the session key"
r = call("POST", "/api/compare", {"left": {"conn_id": a["id"], "mount": "app-config"}, "right": {"conn_id": b["id"], "mount": "app-config"}})
print("compare summary:", r["summary"])
assert r["summary"]["total"] > 0 and r["summary"]["error"] == 0
try:
    call("POST", "/api/connections", {"preset_id": 0, "auth": {"method": "kubernetes", "role": "lockstep-admin"}})
    raise AssertionError("a role outside the allowlist was accepted")
except urllib.error.HTTPError as e:
    assert e.code == 403, e.code
    print("role outside allowlist: refused (403)")
print("IN-CLUSTER CHECK: PASS")
