# Dev-only Dex with its config baked in (no bind mount, so the stack also runs in CI, where
# the Docker host can't see the job's checkout).
FROM registry.access.redhat.com/hi/dex@sha256:30e0fa914666c5044f7cae8a3e1128f358be499a69c4638ef1ad717b369c2c11
COPY config.yaml /etc/dex/config.yaml
USER 65532
