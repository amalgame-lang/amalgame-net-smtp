#!/usr/bin/env bash
# tls_verify_test.sh — the SMTP server's certificate is verified (v0.2.11).
#
# Until v0.2.10 the TLS context had no SSL_CTX_set_verify : OpenSSL's client
# default is SSL_VERIFY_NONE, so ANY certificate was accepted and the
# AUTH LOGIN exchange (user, password) went to whoever answered. Here a fake
# relay (Python ssl) records what it receives ; a throwaway CA is trusted
# through SSL_CERT_FILE :
#   1. certificate for the right name (localhost)    → TLS passes (the relay sees EHLO)
#   2. valid certificate for another name             → refused before any SMTP byte
#   3. self-signed certificate                        → refused
#   4. an IP literal : IP SAN accepted, DNS-only refused
#   5. STARTTLS (port 587 path) with another name     → refused, no AUTH sent
# OLD_HEADER=<path to an older Amalgame_Net_Smtp.h>, when given, runs case 2
# on it as a witness : the relay then receives the password.
set -euo pipefail
cd "$(dirname "$0")/.."
RT="${AMC_RUNTIME:-$HOME/.local/share/amalgame/runtime}"
[ -d "$RT" ] || { echo "AMC_RUNTIME introuvable"; exit 1; }
command -v openssl >/dev/null 2>&1 || { echo "[SKIP] openssl absent"; exit 0; }
command -v python3 >/dev/null 2>&1 || { echo "[SKIP] python3 absent"; exit 0; }

B="$(mktemp -d)"; PIDS=""
trap 'for p in $PIDS; do kill "$p" 2>/dev/null || true; done; rm -rf "$B"' EXIT

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -keyout "$B/ca.key" -out "$B/ca.crt" -subj "/CN=Test CA" >/dev/null 2>&1
leaf() {  # name san
    openssl req -newkey rsa:2048 -nodes -keyout "$B/$1.key" -out "$B/$1.csr" -subj "/CN=$1" >/dev/null 2>&1
    printf "subjectAltName=%s\n" "$2" > "$B/$1.ext"
    openssl x509 -req -in "$B/$1.csr" -CA "$B/ca.crt" -CAkey "$B/ca.key" -CAcreateserial -days 1 \
        -extfile "$B/$1.ext" -out "$B/$1.crt" >/dev/null 2>&1
}
leaf localhost "DNS:localhost"
leaf other "DNS:relay.other.test"
leaf ip "IP:127.0.0.1"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -keyout "$B/self.key" -out "$B/self.crt" \
    -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost" >/dev/null 2>&1
export SSL_CERT_FILE="$B/ca.crt"

# Fake relay : implicit TLS (or STARTTLS when the 4th arg is "starttls") ;
# logs every line it receives to <log>, accepts AUTH, refuses MAIL FROM.
cat > "$B/relay.py" <<'PY'
import socket, ssl, sys, threading
port, cert, key, mode, log = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(cert, key)
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port)); srv.listen(8)
def lines(f):
    while True:
        l = f.readline()
        if not l: return
        open(log, "a").write(l.decode(errors="replace"))
        yield l.strip().upper()
def talk(c):
    step = 0
    try:
        if mode == "starttls":
            f = c.makefile("rwb")
            f.write(b"220 relay ESMTP\r\n"); f.flush()
            for l in lines(f):
                if l.startswith(b"EHLO"): f.write(b"250-relay\r\n250 STARTTLS\r\n"); f.flush()
                elif l.startswith(b"STARTTLS"): f.write(b"220 go\r\n"); f.flush(); break
            c = ctx.wrap_socket(c, server_side=True)
            f = c.makefile("rwb")
        else:
            c = ctx.wrap_socket(c, server_side=True)
            f = c.makefile("rwb")
            f.write(b"220 relay ESMTP\r\n"); f.flush()
        for l in lines(f):
            if l.startswith(b"EHLO"): f.write(b"250-relay\r\n250 AUTH LOGIN\r\n")
            elif l.startswith(b"AUTH"): f.write(b"334 VXNlcm5hbWU6\r\n"); step = 1
            elif step == 1: f.write(b"334 UGFzc3dvcmQ6\r\n"); step = 2
            elif step == 2: f.write(b"235 ok\r\n"); step = 0
            elif l.startswith(b"MAIL"): f.write(b"550 test relay\r\n")
            elif l.startswith(b"QUIT"): f.write(b"221 bye\r\n"); f.flush(); break
            else: f.write(b"250 ok\r\n")
            f.flush()
    except Exception:
        pass
    finally:
        try: c.close()
        except Exception: pass
while True:
    c, _ = srv.accept()
    threading.Thread(target=talk, args=(c,), daemon=True).start()
PY
relay() {  # port cert mode
    python3 "$B/relay.py" "$1" "$B/$2.crt" "$B/$2.key" "$3" "$B/relay-$1.log" >/dev/null 2>&1 &
    PIDS="$PIDS $!"
}
relay 18471 localhost implicit
relay 18472 other implicit
relay 18473 self implicit
relay 18474 ip implicit
sleep 1

cat > "$B/send.c" <<'EOF'
#include "Amalgame_Net_Smtp.h"
#include <stdio.h>
#include <stdlib.h>
int main(int argc, char** argv) {
    GC_INIT();
    code_bool ok = Amalgame_Net_Smtp_Send(argv[1], atoi(argv[2]), "kairos-user", "s3cret-pass",
        "from@example.com", "to@example.com", "Test", "body");
    printf("ok=%d error=%s\n", (int) ok, Amalgame_Net_Smtp_LastError());
    return 0;
}
EOF
gcc -O2 -Iruntime -I"$RT" "$B/send.c" -lssl -lcrypto -lgc -o "$B/send"

FAILS=0
check() { if echo "$3" | grep -Eq "$2"; then echo "[PASS] $1"; else echo "[FAIL] $1 : $3"; FAILS=$((FAILS+1)); fi; }
sent() { [ -f "$B/relay-$1.log" ] && grep -c . "$B/relay-$1.log" || echo 0; }

out=$("$B/send" localhost 18471)
check "1. bon nom (localhost) : TLS accepté, le relais reçoit EHLO" "error=SMTP rejected: 550" "$out"
grep -q "^EHLO" "$B/relay-18471.log" || { echo "[FAIL] 1. le relais n'a rien reçu"; FAILS=$((FAILS+1)); }
out=$("$B/send" localhost 18472)
check "2. certificat valide d'un autre nom : refusé" "certificate of localhost not trusted" "$out"
[ "$(sent 18472)" = 0 ] && echo "[PASS] 2. aucun octet SMTP envoyé (ni identifiant ni mot de passe)" || { echo "[FAIL] 2. le relais a reçu : $(cat $B/relay-18472.log)"; FAILS=$((FAILS+1)); }
out=$("$B/send" localhost 18473)
check "3. certificat auto-signé : refusé" "not trusted \(self.signed" "$out"
out=$("$B/send" 127.0.0.1 18474)
check "4a. adresse IP, certificat IP:127.0.0.1 : accepté" "error=SMTP rejected: 550" "$out"
out=$("$B/send" 127.0.0.1 18471)
check "4b. adresse IP, certificat DNS seulement : refusé" "not trusted" "$out"

# STARTTLS : the client uses that path on port 587 only, a privileged port :
# the relay runs as root through passwordless sudo (CI runners), skipped
# otherwise.
if sudo -n true 2>/dev/null; then
    sudo -n python3 "$B/relay.py" 587 "$B/other.crt" "$B/other.key" starttls "$B/relay-587.log" >/dev/null 2>&1 &
    PIDS="$PIDS $!"
    trap 'for p in $PIDS; do kill "$p" 2>/dev/null || true; done; sudo -n pkill -f "relay.py 587" 2>/dev/null || true; rm -rf "$B"' EXIT
    sleep 1
    out=$("$B/send" localhost 587)
    check "5. STARTTLS, certificat d'un autre nom : refusé" "\(STARTTLS\) : certificate of localhost not trusted" "$out"
    if sudo -n grep -q "^AUTH" "$B/relay-587.log" 2>/dev/null; then echo "[FAIL] 5. AUTH envoyé"; FAILS=$((FAILS+1)); else echo "[PASS] 5. aucun AUTH envoyé"; fi
else
    echo "[SKIP] 5. STARTTLS (port 587 réservé, pas de sudo sans mot de passe)"
fi

if [ -s "${OLD_HEADER:-}" ]; then
    mkdir -p "$B/old" && cp "$OLD_HEADER" "$B/old/Amalgame_Net_Smtp.h"
    gcc -O2 -I"$B/old" -I"$RT" "$B/send.c" -lssl -lcrypto -lgc -o "$B/send_old" 2>/dev/null
    rm -f "$B/relay-18472.log"
    out=$("$B/send_old" localhost 18472)
    pw=$(grep -c "czNjcmV0LXBhc3M=" "$B/relay-18472.log" 2>/dev/null || true)
    echo "[TÉMOIN] version précédente, certificat d'un autre nom : $out ; mot de passe reçu par le faux relais : $([ "${pw:-0}" -gt 0 ] && echo OUI || echo non)"
fi
[ "$FAILS" = 0 ]
