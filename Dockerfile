# For Java 8, try this
FROM openjdk:8

# Refer to Maven build -> finalName
ARG JAR_FILE=target/gateway-server-0.0.1-SNAPSHOT.jar

# cd /opt/app
WORKDIR /opt/app

# cp target/gateway-server.jar /opt/app/gateway-server.jar
COPY ${JAR_FILE} gateway-server-0.0.1-SNAPSHOT.jar

# java -jar /opt/app/gateway-server.jar
ENTRYPOINT ["java","-jar","gateway-server-0.0.1-SNAPSHOT.jar"]
