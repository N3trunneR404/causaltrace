FROM ghcr.io/christophetd/log4shell-vulnerable-app:latest

USER root

# Install tools needed for attack-chain recon/lateral-movement stages
RUN apt-get update 2>/dev/null && apt-get install -y --no-install-recommends \
    netcat-openbsd curl procps iproute2 2>/dev/null; \
    rm -rf /var/lib/apt/lists/* 2>/dev/null; true

EXPOSE 8080

CMD ["java", "-jar", "/app/spring-boot-application.jar"]
