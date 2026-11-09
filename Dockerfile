# syntax=docker/dockerfile:1
# Single image: FastAPI backend serving the built React SPA.
#
# Built on Red Hat Hardened Images (https://images.redhat.com). The *-builder variants
# have a shell and package tools for build stages. The runtime image is distroless: no
# shell, no package manager, non-root (65532). That means no shell-form RUN/CMD/HEALTHCHECK
# in the final stage. Base images are pinned by digest; bump them deliberately.
ARG PY_BUILDER=registry.access.redhat.com/hi/python:3.14-builder@sha256:cff3c96ae1f37cc7ef71ea4af4088a0e15d4df48e79ee8cf0cca68baed75826b
ARG PY_RUNTIME=registry.access.redhat.com/hi/python:3.14@sha256:a9ad325f34cf0806b810a58a71a352a8b6321737d5ee669ed962ad26038ca5ae
ARG NODE_BUILDER=registry.access.redhat.com/hi/nodejs:24-builder@sha256:a79f666c9127faee19a0514e269b9af6a2cdfc6e7f61d9b3832d019b861abb3a

# The built SPA is the same on every architecture, so build it natively (no emulation in
# multi-arch builds).
FROM --platform=$BUILDPLATFORM ${NODE_BUILDER} AS frontend-build
WORKDIR /build
COPY --chown=65532:0 frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY --chown=65532:0 frontend/ ./
RUN npm run build

FROM ${PY_BUILDER} AS backend-build
USER 0
COPY backend/pyproject.toml /build/backend/
COPY backend/src /build/backend/src
# Install into a venv; it's copied whole into the runtime image (same Python path in both).
RUN python3 -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir /build/backend \
 && /opt/venv/bin/pip uninstall -y pip

# Test image: podman compose --profile test run --rm tests
FROM ${PY_BUILDER} AS test
USER 0
COPY backend /src/backend
COPY schemas /src/schemas
RUN python3 -m venv /opt/venv && /opt/venv/bin/pip install --no-cache-dir "/src/backend[dev]"
ENV PATH=/opt/venv/bin:$PATH
WORKDIR /src/backend
USER 65532
CMD ["python", "-m", "pytest", "-q", "-p", "no:cacheprovider"]

FROM ${PY_RUNTIME}
# Remove the system pip: unused at runtime, and it bundles its own copies of certifi,
# urllib3, msgpack and setuptools that lag behind upstream fixes. pip is RPM-installed here
# (so `pip uninstall` refuses), and there's no shell, hence an exec-form Python one-liner.
# The rpmdb still lists python3-pip; at worst scanners over-report on it, never under-report.
USER 0
RUN ["/usr/bin/python3.14", "-c", "import glob,os,shutil; [shutil.rmtree(p) if os.path.isdir(p) else os.remove(p) for p in glob.glob('/usr/lib/python3.14/site-packages/pip*') + glob.glob('/usr/bin/pip*')]"]
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 \
    PATH=/opt/venv/bin:$PATH \
    LOCKSTEP_STATIC_DIR=/app/static
COPY --from=backend-build /opt/venv /opt/venv
COPY --from=frontend-build /build/dist /app/static
COPY LICENSE NOTICE /app/
WORKDIR /app
USER 65532
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s CMD ["python", "-c", "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8080/healthz')"]
STOPSIGNAL SIGINT
ENTRYPOINT ["python", "-m", "uvicorn", "lockstep.main:app", "--host", "0.0.0.0", "--port", "8080", "--proxy-headers", "--forwarded-allow-ips", "*"]
