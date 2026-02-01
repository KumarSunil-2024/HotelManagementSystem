# Use Eclipse Temurin OpenJDK 17 (works on Render)
FROM eclipse-temurin:17-jdk

# Set working directory
WORKDIR /app

# Copy backend files
COPY . .

# Make Maven wrapper executable
RUN chmod +x mvnw

# Build project (skip tests)
RUN ./mvnw clean package -DskipTests

# Expose port
EXPOSE 8080

# Run the Spring Boot JAR (replace with your actual jar name)
CMD ["java", "-jar", "target/hotel-management-system-0.0.1-SNAPSHOT.jar"]
