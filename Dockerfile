FROM openjdk:8-jdk-alpine

EXPOSE 8081

ADD target/gateway-0.0.1-SNAPSHOT.jar gateway-0.0.1-SNAPSHOT.jar

ENTRYPOINT [ "java", "-jar" , "/gateway-0.0.1-SNAPSHOT.jar" ]