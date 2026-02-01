# Use valid OpenJDK 17 slim
FROM openjdk:17.0.8-jdk-slim

# Set working directory
WORKDIR /app

# Copy backend files
COPY . .

# Make Maven wrapper executable
RUN chmod +x mvnw

# Build the Spring Boot project
RUN ./mvnw clean package -DskipTests

# Expose port
EXPOSE 8080

# Run the JAR (replace jar name if different)
CMD ["java", "-jar", "target/hotel-management-system-0.0.1-SNAPSHOT.jar"]
