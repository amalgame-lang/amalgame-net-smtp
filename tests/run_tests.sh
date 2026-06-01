#!/usr/bin/env bash
# Tests pour amalgame-net-smtp.
#
# La classe Smtp est header-only (toute la conversation SMTP vit dans
# runtime/Amalgame_Net_Smtp.h). Tester l'API AM-facing depuis Amalgame
# exigerait le flux complet `amc package add` (le manifeste enregistre
# la classe + ses fonctions — ce que `--external` ne fait pas). Le bon
# scope ici est un smoke C direct contre le header : il valide que le
# header compile, que l'ABI de Send/LastError est cohérente, et que
# l'échec réseau est géré proprement (pas d'envoi réel).
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

BUILD="$(mktemp -d)"
trap 'rm -rf "$BUILD"' EXIT

echo "── smoke C (header + ABI + échec réseau) ──"
gcc -O2 -Wall -Iruntime -I"$RT" tests/smoke.c -lssl -lcrypto -lgc -o "$BUILD/smoke"
OUT="$("$BUILD/smoke")"
echo "$OUT"

fail=0
echo "$OUT" | grep -q "openssl_built: 1"            || { echo "[FAIL] OpenSSL non détecté à la compilation"; fail=1; }
echo "$OUT" | grep -q "send_failed_as_expected: 1"  || { echo "[FAIL] Send aurait dû échouer sur un host invalide"; fail=1; }

if [ "$fail" -eq 0 ]; then
    echo "[PASS] amalgame-net-smtp smoke"
else
    echo "FAIL"; exit 1
fi
