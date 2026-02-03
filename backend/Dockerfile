# Stage 1: Build the JAR
FROM eclipse-temurin:17-jdk-jammy AS build

WORKDIR /app

# Copy pom.xml and download dependencies first (caching)
COPY pom.xml .
RUN apt-get update && apt-get install -y maven
RUN mvn dependency:go-offline -B

# Copy the rest of the source code
COPY . .

# Build the project (skip tests for faster build)
RUN mvn clean package -DskipTests

# Stage 2: Run the JAR
FROM eclipse-temurin:17-jdk-jammy

WORKDIR /app

# Copy the built jar from the previous stage
COPY --from=build /app/target/HotelManagementSystem-0.0.1-SNAPSHOT.jar app.jar

# Expose the application port
EXPOSE 4040

# Run the Spring Boot app
ENTRYPOINT ["java","-jar","app.jar"]
