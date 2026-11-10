# The gateway's image (step 19a, ADR-54). Built from the repository root:
#   docker build -f gateway/Dockerfile .
# Base images are pinned by digest (an exact fingerprint), like the actions in CI: a tag can be
# moved to point at a different image, a digest cannot. Update both the version and the digest.

# ---- Stage 1: build the program with the full Java kit (thrown away afterwards)
FROM eclipse-temurin:25.0.4_7-jdk-alpine@sha256:541729c21f9308a68cebbe5a0627e4cd465dfe8980fc03bac0b2feaee57daafd AS build
WORKDIR /src
# The Maven wrapper and the list of libraries first: Docker reuses this slow download step until they change.
COPY gateway/mvnw gateway/pom.xml ./
COPY gateway/.mvn .mvn
RUN sh mvnw -B -q dependency:go-offline
COPY gateway/src src
# Tests run in CI's own job (and need their own throwaway database), not inside the image build.
RUN sh mvnw -B -q -DskipTests package && cp target/gateway-*.jar /gateway.jar

# ---- Stage 2: only the Java runtime and the finished program
FROM eclipse-temurin:25.0.4_7-jre-alpine@sha256:2ca9adf44f5c29d28ecd26cf92d75cc0c66b7f32bfd839a4439e363a8b428af8
# An ordinary user: if the program were ever taken over, the attacker would not be root in the container.
RUN addgroup -S app && adduser -S -G app -H app \
    && mkdir -p /app/logs /certs /gateway-ca \
    && chown app:app /app/logs /certs /gateway-ca
WORKDIR /app
COPY --from=build /gateway.jar /app/gateway.jar
COPY deploy/make-gateway-certificate.sh /app/make-gateway-certificate.sh
USER app
ENV SPRING_PROFILES_ACTIVE=production
EXPOSE 8443
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=60", "-jar", "/app/gateway.jar"]
