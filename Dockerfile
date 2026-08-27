FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /build
COPY pom.xml .
RUN mvn -B dependency:go-offline
COPY src ./src
RUN mvn -B package

# ---- runtime stage ----
FROM eclipse-temurin:21-jre-alpine
WORKDIR /app

RUN addgroup -S loglens && adduser -S loglens -G loglens

COPY --from=build --chown=loglens:loglens /build/target/loglens-1.0.0.jar ./loglens.jar

USER loglens

ENTRYPOINT ["java", "-jar", "/app/loglens.jar"]
