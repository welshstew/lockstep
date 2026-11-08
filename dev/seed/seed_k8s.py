"""Dev only: enable Vault's kubernetes auth method against the k3s dev cluster.

Runs after dev/k8s/setup.sh, which leaves the reviewer token and cluster CA in /k8s.
Roles on both Vaults:
  lockstep-reader  bound to lockstep/lockstep   → lockstep-readonly
  lockstep-admin   bound to lockstep/lockstep   → lockstep-admin
  other-app        bound to lockstep/other-app  → (the tool's account must NOT get in)
  lockstep-helm    bound to lockstep-helm/lockstep → lockstep-readonly (the Helm chart in k3s)
"""

import os
import time

from seed import Vault

K8S = os.environ.get("K8S_DIR", "/k8s")


def main() -> None:
    for _ in range(60):
        if os.path.exists(f"{K8S}/reviewer.jwt") and os.path.exists(f"{K8S}/ca.crt"):
            break
        time.sleep(2)
    reviewer = open(f"{K8S}/reviewer.jwt").read().strip()
    ca = open(f"{K8S}/ca.crt").read()
    for name, addr, tok in [("vault-a", os.environ["VAULT_A_ADDR"], os.environ["VAULT_A_TOKEN"]),
                            ("vault-b", os.environ["VAULT_B_ADDR"], os.environ["VAULT_B_TOKEN"])]:
        v = Vault(name, addr, tok)
        v.wait_ready()
        v.enable_auth("kubernetes", "kubernetes")
        v.req("POST", "auth/kubernetes/config", {
            "kubernetes_host": "https://k3s:6443", "kubernetes_ca_cert": ca,
            "token_reviewer_jwt": reviewer, "disable_local_ca_jwt": True})
        for role, sa, ns, pol in [("lockstep-reader", "lockstep", "lockstep", "lockstep-readonly"),
                                  ("lockstep-admin", "lockstep", "lockstep", "lockstep-admin"),
                                  ("other-app", "other-app", "lockstep", "lockstep-readonly"),
                                  # the Helm chart installed in k3s (make helm-test): its own namespace
                                  ("lockstep-helm", "lockstep", "lockstep-helm", "lockstep-readonly")]:
            v.req("POST", f"auth/kubernetes/role/{role}", {
                "bound_service_account_names": [sa], "bound_service_account_namespaces": [ns],
                "token_policies": [pol], "token_ttl": "1h"})
        print(f"[{name}] kubernetes auth configured")
    print("k8s seed complete")


if __name__ == "__main__":
    main()
