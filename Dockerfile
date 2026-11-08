# ---------------------------------------------------------------------------
# © 2026 Satyendra Singh. All Rights Reserved.
# Author: Satyendra Singh
#
# SentinelGuard :: optimised multi-stage image
#
# Stage 1 (builder) resolves dependencies in a cache-friendly order and builds
# the layered Spring Boot jar, then explodes it into its layers.
# Stage 2 (runtime) copies those layers, slowest-changing first, onto a slim
# JRE. Because application code lands in the LAST layer, a code-only change
# rebuilds and re-pushes a few hundred kilobytes instead of the whole ~60MB
# dependency set.
# ---------------------------------------------------------------------------

# =========================== STAGE 1: BUILD ================================
FROM maven:3.9.9-eclipse-temurin-21-alpine AS builder

WORKDIR /build

# Dependencies change far less often than source. Copying the POM alone first
# means the (slow) resolve step is reused from the layer cache on every build
# that did not touch the POM.
COPY pom.xml ./
RUN mvn -B -ntp dependency:go-offline

# Now the sources, which change on every commit.
COPY src ./src

# Unit tests run in CI as their own reportable step, and the Docker build must
# not require a Docker daemon of its own for the Testcontainers suite.
RUN mvn -B -ntp clean package -DskipTests

# Explode the jar into its layers (Spring Boot 3.3+ "tools" jarmode).
RUN java -Djarmode=tools -jar target/sentinelguard.jar \
        extract --layers --launcher --destination extracted

# ========================== STAGE 2: RUNTIME ===============================
FROM eclipse-temurin:21-jre-alpine AS runtime

LABEL org.opencontainers.image.title="SentinelGuard" \
      org.opencontainers.image.description="Reactive Distributed Rate-Limiter and Fraud Detection Engine" \
      org.opencontainers.image.version="1.0.0" \
      org.opencontainers.image.authors="Satyendra Singh" \
      org.opencontainers.image.vendor="Satyendra Singh" \
      org.opencontainers.image.licenses="Proprietary"

# wget (busybox) backs the HEALTHCHECK; curl is not installed to keep the
# attack surface and the image small.
RUN addgroup --system --gid 1001 sentinel \
    && adduser --system --uid 1001 --ingroup sentinel --no-create-home sentinel \
    && mkdir -p /app \
    && chown -R sentinel:sentinel /app

WORKDIR /app
USER 1001:1001

# Layer order is deliberate: least to most frequently changed.
COPY --from=builder --chown=sentinel:sentinel /build/extracted/dependencies/ ./
COPY --from=builder --chown=sentinel:sentinel /build/extracted/spring-boot-loader/ ./
COPY --from=builder --chown=sentinel:sentinel /build/extracted/snapshot-dependencies/ ./
COPY --from=builder --chown=sentinel:sentinel /build/extracted/application/ ./

# MaxRAMPercentage rather than a fixed -Xmx lets the JVM respect whatever
# container limit it is given, so one image is correct on a 512Mi pod and on a
# 4Gi one. ExitOnOutOfMemoryError makes the orchestrator replace a poisoned
# process instead of letting it limp along.
ENV SERVER_PORT=8080 \
    REDIS_HOST=redis \
    REDIS_PORT=6379 \
    KAFKA_BOOTSTRAP_SERVERS=kafka:9092 \
    JAVA_OPTS="-XX:MaxRAMPercentage=75.0 -XX:InitialRAMPercentage=50.0 -XX:+UseG1GC -XX:MaxGCPauseMillis=100 -XX:+ExitOnOutOfMemoryError -Dfile.encoding=UTF-8"

EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=3s --start-period=40s --retries=4 \
    CMD wget -qO- "http://127.0.0.1:${SERVER_PORT}/actuator/health/readiness" \
        | grep -q '"status":"UP"' || exit 1

# exec keeps the JVM as PID 1 so SIGTERM reaches it and Spring's graceful
# shutdown can drain in-flight exchanges instead of being killed.
ENTRYPOINT ["sh", "-c", "exec java $JAVA_OPTS org.springframework.boot.loader.launch.JarLauncher"]
