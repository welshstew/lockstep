# Dev-only Dex with its config baked in (no bind mount, so the stack also runs in CI, where
# the Docker host can't see the job's checkout).
FROM registry.access.redhat.com/hi/dex@sha256:8e2a356f807822396226165fa781e50e5a50436b994ba671c38c94ffc3dcb97b
COPY config.yaml /etc/dex/config.yaml
USER 65532
