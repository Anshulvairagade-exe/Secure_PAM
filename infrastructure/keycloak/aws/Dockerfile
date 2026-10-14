# SecurePAM Keycloak — PRODUCTION image (AWS). Not the local lab image (../Dockerfile runs start-dev).
#   docker build -f infrastructure/keycloak/aws/Dockerfile -t <ecr-repo>:<version> .   (context: repo root)
# Pinned Keycloak 24.0.5 = the SPI line the securepam-otp-audit provider is compiled against (24.0.0).
FROM maven:3.9-eclipse-temurin-17 AS provider-build
WORKDIR /workspace
COPY keycloak-extension/pom.xml ./pom.xml
COPY keycloak-extension/src ./src
RUN mvn -B -q -DskipTests package

FROM quay.io/keycloak/keycloak:24.0.5 AS builder
# Build-time options are baked into the optimized server (changing them needs a rebuild).
ENV KC_DB=postgres \
    KC_HEALTH_ENABLED=true \
    KC_METRICS_ENABLED=true \
    KC_FEATURES_DISABLED=impersonation
COPY --from=provider-build /workspace/target/securepam-keycloak-otp-audit.jar /opt/keycloak/providers/
RUN /opt/keycloak/bin/kc.sh build

FROM quay.io/keycloak/keycloak:24.0.5
COPY --from=builder /opt/keycloak/ /opt/keycloak/
# Sanitized realm (no keys, users or secrets). Imported ONLY when the realm does not exist yet
# (IGNORE_EXISTING); an existing realm is never overwritten.
COPY infrastructure/keycloak/realm-import/securepam-realm.json /opt/keycloak/data/import/securepam-realm.json
USER 1000
ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
# Production mode. Runtime settings (hostname, proxy headers, DB URL/credentials, bootstrap admin)
# come from the environment file written at boot from AWS Secrets Manager (see terraform/user-data.sh).
CMD ["start", "--optimized", "--import-realm"]
