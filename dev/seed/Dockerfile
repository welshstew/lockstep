# Dev-only seed job, on the same Red Hat Hardened Images as the app.
ARG PY_BUILDER=registry.access.redhat.com/hi/python:3.14-builder@sha256:cff3c96ae1f37cc7ef71ea4af4088a0e15d4df48e79ee8cf0cca68baed75826b
ARG PY_RUNTIME=registry.access.redhat.com/hi/python:3.14@sha256:a9ad325f34cf0806b810a58a71a352a8b6321737d5ee669ed962ad26038ca5ae

ARG JDK_BUILDER=registry.access.redhat.com/hi/openjdk:21-builder@sha256:020e63a80161a01f022bb99c083a344f78c297c76aad0f1df73b87ec81ecf946

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
