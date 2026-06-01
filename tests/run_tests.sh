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

echo ""
echo "All tests passed."
