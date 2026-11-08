.PHONY: up up-k8s down test test-k8s e2e chart-check helm-test screenshots scan scan-clean bump-base-images pin-scanner-images

up:            ## start the local stack
	podman compose up --build -d

up-k8s:        ## the stack plus a k3s cluster for Kubernetes auth
	podman compose --profile k8s up --build -d

down:
	podman compose --profile k8s --profile test --profile docs --profile e2e down

test:          ## backend test suite against the seeded Vaults
	podman compose --profile test run --rm --build tests

test-k8s:      ## tests including real Kubernetes auth logins (starts k3s if needed)
	podman compose --profile k8s up --build -d
	podman compose --profile test run --rm --build tests

e2e:           ## browser end-to-end tests (Playwright) -> reports/e2e (junit + failure screenshots)
	podman compose up --build -d
	podman compose --profile e2e build e2e
	-@podman rm -f lockstep-e2e >/dev/null 2>&1; rm -rf reports/e2e
	@rc=0; podman compose --profile e2e run --name lockstep-e2e e2e || rc=$$?; \
	  mkdir -p reports/e2e && podman cp lockstep-e2e:/reports/. reports/e2e/ >/dev/null; \
	  podman rm -f lockstep-e2e >/dev/null; exit $$rc

chart-check:   ## Helm chart: lint, render + Kubernetes schema validation, guard checks (no cluster)
	./scripts/chart-check.sh

helm-test:     ## install the Helm chart into the dev k3s cluster and test it for real
	./scripts/helm-test.sh

screenshots:   ## regenerate docs/images (README screenshots) from the running app
	podman compose run --rm --build seed
	podman compose --profile docs run --rm --build screenshots   # --build: the script is baked into the image

scan:          ## security scan (Trivy image+fs, pip-audit, npm audit, bandit, gitleaks) -> reports/
	./scripts/scan.sh

scan-clean:
	rm -rf reports

bump-base-images: ## update pinned Red Hat Hardened Image digests to the latest builds
	./scripts/bump-base-images.sh

pin-scanner-images: ## re-pin scanner images in scan/versions.env to multi-arch index digests
	python3 scripts/pin-scanner-images.py
