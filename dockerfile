FROM eclipse-temurin:17-jdk-jammy

WORKDIR /sirup/service

COPY ./target /sirup/service/target
COPY ./secret.key /sirup/service

CMD ["java","-jar","./target/AuthService-1.0-SNAPSHOT-shaded.jar"]