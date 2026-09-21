#!/usr/bin/env bash
# Tests pour amalgame-net-smtp.
#
# Deux niveaux :
#   1. smoke C — la classe Smtp est header-only ; on compile un C qui
#      inclut le header et appelle Smtp_Send / FileBase64, pour valider
#      le header, l'ABI et la gestion d'échec réseau (pas d'envoi réel).
#   2. builder Mail (façade mail.am) — on compile la façade puis un
#      consumer AM qui l'utilise (HTML + texte), pour valider la
#      résolution AM + le pont @c vers le header. Cible un host
#      injoignable → pas d'envoi réel.
#
# Un vrai envoi se teste à la main avec de vrais identifiants SMTP
# (voir le README, section « Envoi réel »).
set -euo pipefail
cd "$(dirname "$0")/.."

# Localiser le runtime amc (_runtime.h, GC).
if [ -n "${AMC_RUNTIME:-}" ] && [ -d "$AMC_RUNTIME" ]; then
    RT="$AMC_RUNTIME"
elif [ -d "$HOME/.local/share/amalgame/runtime" ]; then
    RT="$HOME/.local/share/amalgame/runtime"
else
    echo "error: runtime amc introuvable (set AMC_RUNTIME=<dir>)"; exit 1
fi

# Localiser le binaire amc (arg 1, env AMC, PATH, install local).
if [ -n "${1:-}" ] && [ -x "$1" ]; then AMC="$1"
elif [ -n "${AMC:-}" ] && [ -x "$AMC" ]; then AMC="$AMC"
elif command -v amc >/dev/null 2>&1; then AMC="$(command -v amc)"
elif [ -x "$HOME/.local/bin/amc" ]; then AMC="$HOME/.local/bin/amc"
else echo "error: amc introuvable (passer le chemin en arg 1 ou set AMC=)"; exit 1
fi

BUILD="$(mktemp -d)"
trap 'rm -rf "$BUILD"; rm -f amalgame.lock' EXIT

# ── 1) smoke C ────────────────────────────────────────────────────
echo "── smoke C (header + ABI + échec réseau) ──"
gcc -O2 -Wall -Iruntime -I"$RT" tests/smoke.c -lssl -lcrypto -lgc -o "$BUILD/smoke"
OUT="$("$BUILD/smoke")"
echo "$OUT"
fail=0
echo "$OUT" | grep -q "openssl_built: 1"            || { echo "[FAIL] OpenSSL non détecté"; fail=1; }
echo "$OUT" | grep -q "send_failed_as_expected: 1"  || { echo "[FAIL] Send aurait dû échouer"; fail=1; }
[ "$fail" -eq 0 ] && echo "[PASS] smoke C" || { echo "FAIL (smoke)"; exit 1; }

# ── 2) builder Mail (façade + consumer AM) ────────────────────────
echo ""
echo "── builder Mail (façade + consumer AM) ──"
# Self-cache : permet à amc de voir la classe Mail du package courant
# pendant la compilation du consumer (PkgRegistry lit le toml via
# AMALGAME_PACKAGES_DIR + un amalgame.lock transitoire dans le cwd).
SELF="$BUILD/cache"
mkdir -p "$SELF/github.com/amalgame-lang/amalgame-net-smtp"
ln -s "$(pwd)" "$SELF/github.com/amalgame-lang/amalgame-net-smtp/v0.2.0_selfbuild"
cat > amalgame.lock <<'EOF'
[[package]]
name = "amalgame-net-smtp"
git  = "github.com/amalgame-lang/amalgame-net-smtp"
tag  = "v0.2.0"
rev  = "0000000000000000000000000000000000000000"
EOF

# Façade → objet (le header est force-inclus pour les ponts @c).
"$AMC" --lib mail.am -o "$BUILD/mail" >/dev/null 2>&1
gcc -O2 -Iruntime -I"$RT" -include runtime/Amalgame_Net_Smtp.h \
    -c "$BUILD/mail.c" -o "$BUILD/mail.o"

# Consumer (façade en --external) → exécutable.
AMALGAME_PACKAGES_DIR="$SELF" "$AMC" examples/mail_demo.am \
    -o "$BUILD/demo" --external mail.am >/dev/null 2>&1
gcc -O2 -Iruntime -I"$RT" -include runtime/Amalgame_Net_Smtp.h \
    "$BUILD/demo.c" "$BUILD/mail.o" -lssl -lcrypto -lgc -lm -o "$BUILD/demo"

DOUT="$("$BUILD/demo")"
echo "$DOUT"
echo "$DOUT" | grep -q "\[PASS\]" || { echo "FAIL (Mail builder)"; exit 1; }
echo "[PASS] builder Mail"

# ── 3) security: email header injection + DATA dot-stuffing ────────
echo ""
echo "── security (header injection + dot-stuffing) ──"
AMALGAME_PACKAGES_DIR="$SELF" "$AMC" examples/mail_security.am \
    -o "$BUILD/sec" --external mail.am >/dev/null 2>&1
gcc -O2 -Iruntime -I"$RT" -include runtime/Amalgame_Net_Smtp.h \
    "$BUILD/sec.c" "$BUILD/mail.o" -lssl -lcrypto -lgc -lm -o "$BUILD/sec"
SOUT="$("$BUILD/sec")"
echo "$SOUT"
echo "$SOUT" | grep -q "\[FAIL\]" && { echo "FAIL (security)"; exit 1; }
echo "$SOUT" | grep -q "no header injection" || { echo "FAIL (security: missing pass)"; exit 1; }
echo "[PASS] security"

# ── 4) encodage des corps (quoted-printable) + Message-ID unique ───
echo ""
echo "── encodage (quoted-printable, lignes ≤ 76, Message-ID unique) ──"
AMALGAME_PACKAGES_DIR="$SELF" "$AMC" examples/mail_encoding.am \
    -o "$BUILD/enc" --external mail.am >/dev/null 2>&1
gcc -O2 -Iruntime -I"$RT" -include runtime/Amalgame_Net_Smtp.h \
    "$BUILD/enc.c" "$BUILD/mail.o" -lssl -lcrypto -lgc -lm -o "$BUILD/enc"
"$BUILD/enc" > "$BUILD/enc.out"
python3 - "$BUILD/enc.out" <<'PY' || { echo "FAIL (encodage)"; exit 1; }
import sys, email, email.policy
raw = open(sys.argv[1], encoding="utf-8", newline="").read()   # garder les CRLF tels quels
html = raw.split("===HTML===\n")[1].split("\n===A===")[0]
a = raw.split("===A===\n")[1].split("\n===B===")[0]
b = raw.split("===B===\n")[1].split("\n===END===")[0]
text = "Ligne avec espace final \r\nTab final\t\r\n.\r\nfin=ok"
bad = 0
def must(c, label):
    global bad
    print(("[PASS] " if c else "[FAIL] ") + label); bad += 0 if c else 1
for name, w in (("A", a), ("B", b)):
    lines = w.split("\r\n")
    must(max(len(l.encode()) for l in lines) <= 76, name + " : aucune ligne > 76 octets (max %d)" % max(len(l.encode()) for l in lines))
    must(all(ord(ch) < 128 for ch in w), name + " : message 7 bits")
    must("8bit" not in w, name + " : plus de 8bit")
def undot(w): return w.replace("\r\n..", "\r\n.")
ma = email.message_from_bytes(undot(a).encode(), policy=email.policy.default)
mb = email.message_from_bytes(undot(b).encode(), policy=email.policy.default)
parts = {p.get_content_type(): p for p in ma.walk()}
must(parts["text/html"].get_payload(decode=True).decode("utf-8") == html, "HTML décodé identique (3 Ko, accents, =)")
must(parts["text/plain"].get_payload(decode=True).decode("utf-8") == text, "texte décodé identique (espace/tab finals, ligne '.')")
must(mb.get_payload(decode=True).decode("utf-8") == text, "texte seul décodé identique")
must(ma["Message-ID"] != mb["Message-ID"], "Message-ID différents (%s / %s)" % (ma["Message-ID"], mb["Message-ID"]))
sys.exit(1 if bad else 0)
PY
echo "[PASS] encodage"

echo ""
echo "All tests passed."
