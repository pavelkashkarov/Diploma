FROM openjdk:18-jdk-alpine3.13

EXPOSE 5050

ADD target/Diploma-1.0-SNAPSHOT.jar diploma.jar

ENTRYPOINT ["java", "-jar", "diploma.jar"]