#!/bin/bash
# One independent K1-FGAP proof run: fresh server data -> scenario -> stop server.
# Usage: run_fgap.sh <runlabel> <realm>
set -u
LABEL=$1
REALM=$2
FG=~/workspace/sorona-replies/SOR-EC0RS7-fgap
RT=~/workspace/sorona/keycloak-audit/runtime
KC=$RT/keycloak-26.8.2
OUT=$FG/$LABEL
mkdir -p "$OUT"

export JAVA_HOME=$RT/jre21
export PATH=$JAVA_HOME/bin:$PATH

# fresh state
pkill -f "keycloak-26.8.2" 2>/dev/null; sleep 2
rm -rf "$KC/data"
mkdir -p "$KC/data"

KC_BOOTSTRAP_ADMIN_USERNAME=admin KC_BOOTSTRAP_ADMIN_PASSWORD=adminpass \
JAVA_OPTS="-Xms128m -Xmx896m" \
nohup "$KC/bin/kc.sh" start-dev --http-port=8080 --http-host=127.0.0.1 \
  > "$OUT/server.log" 2>&1 &
echo "server pid $!"

for i in $(seq 1 90); do
  code=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8080/ 2>/dev/null)
  if [ "$code" = "200" ] || [ "$code" = "302" ] || [ "$code" = "303" ]; then
    echo "server up after ${i} tries (HTTP $code)"; break
  fi
  sleep 4
  if [ "$i" = "90" ]; then echo "SERVER FAILED TO START"; tail -30 "$OUT/server.log"; exit 1; fi
done
sleep 3

python3 "$FG/proof_fgap.py" "$REALM" "$OUT"
RC=$?
echo "proof_fgap.py exit: $RC"

pkill -f "keycloak-26.8.2" 2>/dev/null; sleep 2
exit $RC
