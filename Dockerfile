FROM eclipse-temurin:17-jdk-alpine
WORKDIR /app
COPY src ./src
RUN javac src/main/java/com/example/App.java -d out
CMD ["java", "-cp", "out", "com.example.App"]
