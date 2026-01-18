# Multi-stage production ready build

# Build stage
FROM maven:3.9.6-eclipse-temurin-21 as builder

WORKDIR /app

# Copy pom.xml (dependency caching)
COPY pom.xml .

# Install dependency
RUN mvn dependency:go-offline -B

# Copy source & build fat JAR
COPY src ./src
RUN mvn clean package -DskipTests -B

# Run stage
FROM eclipse-temurin:21-jre-jammy

# Copy fat JAR from builder
COPY --from=builder /app/target/*.jar /app/authx.jar

# Health-check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8080/actuator/health || exit 1

EXPOSE 8080
ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -jar /app/authx.jar"]
