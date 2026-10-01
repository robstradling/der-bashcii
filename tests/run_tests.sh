#!/usr/bin/env bash
# Tests for der2ascii.sh and ascii2der.sh.
#
# Always runs round-trip tests. If the reference Go tools are available (set
# REF_BIN to the directory holding der2ascii and ascii2der), also runs
# differential tests and random fuzzing against them.
#
# Usage: tests/run_tests.sh [FUZZ_ITERATIONS]

set -u
cd "$(dirname "$0")/.." || exit 1

D2A=./der2ascii.sh
A2D=./ascii2der.sh
FUZZ=${1:-200}
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
pass=0
fail=0

ok() { pass=$((pass + 1)); }
bad() {
	fail=$((fail + 1))
	echo "FAIL: $*"
}

ref_d2a=""
ref_a2d=""
if [[ -n ${REF_BIN-} ]]; then
	ref_d2a=$REF_BIN/der2ascii
	ref_a2d=$REF_BIN/ascii2der
fi

for txt in tests/*.txt; do
	$A2D -i "$txt" >"$TMP/a.der" || { bad "$txt: ascii2der failed"; continue; }
	$D2A -i "$TMP/a.der" >"$TMP/a.txt" || { bad "$txt: der2ascii failed"; continue; }
	$A2D -i "$TMP/a.txt" >"$TMP/b.der" || { bad "$txt: re-assembly failed"; continue; }
	if cmp -s "$TMP/a.der" "$TMP/b.der"; then ok; else bad "$txt: round trip mismatch"; fi

	$A2D -i "$txt" -pem TEST >"$TMP/a.pem"
	$D2A -pem -i "$TMP/a.pem" >"$TMP/p.txt"
	if cmp -s "$TMP/a.txt" "$TMP/p.txt"; then ok; else bad "$txt: PEM round trip mismatch"; fi

	od -An -v -tx1 "$TMP/a.der" >"$TMP/a.hex"
	$D2A -hex -i "$TMP/a.hex" >"$TMP/h.txt"
	if cmp -s "$TMP/a.txt" "$TMP/h.txt"; then ok; else bad "$txt: hex input mismatch"; fi

	if [[ -n $ref_a2d ]]; then
		"$ref_a2d" -i "$txt" >"$TMP/r.der"
		if cmp -s "$TMP/a.der" "$TMP/r.der"; then ok; else bad "$txt: differs from reference ascii2der"; fi
		"$ref_d2a" -i "$TMP/r.der" >"$TMP/r.txt"
		if cmp -s "$TMP/a.txt" "$TMP/r.txt"; then ok; else bad "$txt: differs from reference der2ascii"; fi
		"$ref_a2d" -i "$txt" -pem TEST >"$TMP/r.pem"
		if cmp -s "$TMP/a.pem" "$TMP/r.pem"; then ok; else bad "$txt: PEM differs from reference"; fi
	fi
done

if [[ -n $ref_d2a ]]; then
	seeds=()
	for txt in tests/*.txt; do
		"$ref_a2d" -i "$txt" >"$TMP/seed$((${#seeds[@]})).der"
		seeds+=("$TMP/seed${#seeds[@]}.der")
	done
	for ((i = 0; i < FUZZ; i++)); do
		in=$TMP/fuzz.der
		if ((i % 2)); then
			head -c $((RANDOM % 64 + 1)) /dev/urandom >"$in"
		else
			# Flip a few random bytes of a valid seed.
			seed=${seeds[RANDOM % ${#seeds[@]}]}
			cp "$seed" "$in"
			size=$(wc -c <"$seed")
			for ((k = 0; k < 3; k++)); do
				printf "\\x$(printf %02x $((RANDOM % 256)))" |
					dd of="$in" bs=1 seek=$(((RANDOM * 32768 + RANDOM) % size)) conv=notrunc status=none 2>/dev/null
			done
			head -c $(((RANDOM % size) + 1)) "$in" >"$in.cut"
			mv "$in.cut" "$in"
		fi
		"$ref_d2a" -i "$in" >"$TMP/r.txt"
		$D2A -i "$in" >"$TMP/m.txt"
		if ! cmp -s "$TMP/r.txt" "$TMP/m.txt"; then
			# is_print only approximates Go's Unicode tables, so u"" / U"" literals
			# may escape differently while still encoding the same bytes.
			if ! diff "$TMP/r.txt" "$TMP/m.txt" | grep '^[<>]' | grep -qv '[uU]"' &&
				"$ref_a2d" -i "$TMP/m.txt" | cmp -s - "$in"; then
				cosmetic=$((${cosmetic-0} + 1))
				ok
				continue
			fi
			cp "$in" "tests/fuzz-failure-$i.der"
			bad "fuzz $i: der2ascii differs (saved tests/fuzz-failure-$i.der)"
			continue
		fi
		$A2D -i "$TMP/m.txt" >"$TMP/m.der"
		if cmp -s "$in" "$TMP/m.der"; then ok; else bad "fuzz $i: round trip mismatch"; fi
	done
fi

echo "passed: $pass (cosmetic Unicode escaping differences: ${cosmetic-0}), failed: $fail"
((fail == 0))
