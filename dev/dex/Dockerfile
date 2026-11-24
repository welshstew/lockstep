# Dev-only Dex with its config baked in (no bind mount, so the stack also runs in CI, where
# the Docker host can't see the job's checkout).
FROM registry.access.redhat.com/hi/dex@sha256:f7093894e9a19324cef296c8e9c3886351ce65fc02d1e37fc5e1727224c3a5b5
COPY config.yaml /etc/dex/config.yaml
USER 65532
