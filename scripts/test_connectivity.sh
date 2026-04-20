#!/bin/bash
# test_connectivity.sh — Verify testbed before experiments
set -e
echo "CausalTrace — Testbed Connectivity Check"
echo ""

echo "[1/4] Checking containers..."
for c in ct-web ct-api ct-db; do
    STATUS=$(docker inspect -f '{{.State.Status}}' $c 2>/dev/null || echo "not found")
    IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $c 2>/dev/null || echo "?")
    echo "  $c: $STATUS ($IP)"
done

echo ""
echo "[2/4] Testing Web → API (via nginx proxy_pass)..."
RESP=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/api/health 2>/dev/null || echo "fail")
echo "  GET /api/health → HTTP $RESP"

echo ""
echo "[3/4] Testing API → DB (TCP connection)..."
RESP=$(curl -s http://localhost:8080/api/db/query 2>/dev/null || echo "fail")
echo "  GET /api/db/query → $RESP"

echo ""
echo "[4/4] Testing direct container access..."
RESP=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8081/health 2>/dev/null || echo "fail")
echo "  GET ct-api:8081/health → HTTP $RESP"

echo ""
echo "Connectivity check complete."
