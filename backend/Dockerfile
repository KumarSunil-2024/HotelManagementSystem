# Use Eclipse Temurin OpenJDK 17
FROM eclipse-temurin:17-jdk

# Set working directory inside container
WORKDIR /app

# Copy all backend files
COPY . .

# Make Maven wrapper executable
RUN chmod +x mvnw

# Build the project (skip tests)
RUN ./mvnw clean package -DskipTests

# Expose the port (Render provides $PORT)
EXPOSE 8080

# Run the JAR (replace with your actual jar name)
CMD ["java", "-jar", "target/hotel-management-system-0.0.1-SNAPSHOT.jar"]
