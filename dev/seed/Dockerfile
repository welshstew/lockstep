# Dev-only seed job, on the same Red Hat Hardened Images as the app.
ARG PY_BUILDER=registry.access.redhat.com/hi/python:3.14-builder@sha256:e97e5960378f468aed768dcdfeb3c5d6ba70c72a7ed55f1e469fef34f4ceac59
ARG PY_RUNTIME=registry.access.redhat.com/hi/python:3.14@sha256:0b69ecc37e2b8cfcc1492cad837103677a01f4e93d310e820f0bbb4df49a0881

ARG JDK_BUILDER=registry.access.redhat.com/hi/openjdk:21-builder@sha256:29ceb2457af6562676d1741110513183d393ce0d3da5d89c9419893cfebf0b5e

# Real Java keystores made by keytool, so the JKS/JCEKS reader is tested against genuine files.
FROM ${JDK_BUILDER} AS keystores
USER 0
WORKDIR /ks
RUN set -e; P=changeit; \
    keytool -genkeypair -alias partner-ca -keyalg RSA -keysize 2048 -validity 3650 -ext bc:c \
      -dname "CN=Partner CA,O=Partner Ltd" -keystore ca.p12 -storetype PKCS12 -storepass $P; \
    keytool -exportcert -rfc -alias partner-ca -keystore ca.p12 -storepass $P -file partner-ca.pem; \
    keytool -genkeypair -alias app -keyalg EC -groupname secp256r1 -validity 365 \
      -dname "CN=jks-app.example.com,O=Example Corp" -ext SAN=dns:jks-app.example.com \
      -keystore app.jks -storetype JKS -storepass $P -keypass $P; \
    keytool -importcert -noprompt -alias partner-ca -file partner-ca.pem -keystore app.jks -storetype JKS -storepass $P; \
    keytool -importkeystore -noprompt -srckeystore app.jks -srcstoretype JKS -srcstorepass $P \
      -destkeystore app.jceks -deststoretype JCEKS -deststorepass $P -destkeypass $P -srcalias app; \
    keytool -importcert -noprompt -alias partner-ca -file partner-ca.pem -keystore app.jceks -storetype JCEKS -storepass $P; \
    keytool -importcert -noprompt -alias partner-ca -file partner-ca.pem -keystore trust.jks -storetype JKS -storepass $P; \
    chmod 644 /ks/*

FROM ${PY_BUILDER} AS build
USER 0
RUN python3 -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir httpx==0.28.1 cryptography==50.0.2 \
 && /opt/venv/bin/pip uninstall -y pip

FROM ${PY_RUNTIME}
COPY --from=build /opt/venv /opt/venv
COPY seed.py seed_k8s.py /seed/
COPY --from=keystores /ks/app.jks /ks/app.jceks /ks/trust.jks /seed/fixtures/
ENV PATH=/opt/venv/bin:$PATH PYTHONUNBUFFERED=1
USER 65532
WORKDIR /seed
ENTRYPOINT ["python", "/seed/seed.py"]
