# SecurePAM Keycloak: Keycloak 24 + the securepam-otp-audit event listener.
# From the teammate package's Dockerfile.keycloak; builds the provider from this repository's
# keycloak-extension/ (Java 17, Keycloak SPI 24.0.0) inside Docker, so no host Java/Maven is needed.
# Build context: the repository root (see docker-compose.keycloak.yml).
FROM maven:3.9-eclipse-temurin-17 AS provider-build
WORKDIR /workspace
COPY keycloak-extension/pom.xml ./pom.xml
COPY keycloak-extension/src ./src
RUN mvn -B -q -DskipTests package

FROM quay.io/keycloak/keycloak:24.0
COPY --from=provider-build /workspace/target/securepam-keycloak-otp-audit.jar /opt/keycloak/providers/securepam-keycloak-otp-audit.jar
# Database vendor must be fixed at build time for the optimized image.
ENV KC_DB=postgres
RUN /opt/keycloak/bin/kc.sh build
ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
CMD ["start-dev", "--import-realm"]
