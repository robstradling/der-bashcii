#!/usr/bin/env bash
# ascii2der.sh - assemble DER ASCII into DER/BER bytes, written entirely in Bash.
#
# The input language is https://github.com/google/der-ascii (language.txt).
#
# Usage: ascii2der.sh [-i in] [-o out] [-pem TYPE]

set -u
set -f
shopt -s extglob
# Bash 5.2+ can splice each match into a substitution with &.
AMP=0
shopt -s patsub_replacement 2>/dev/null && AMP=1
export LC_ALL=C

usage() {
	cat >&2 <<'EOF'
Usage: ascii2der.sh [options]
  -i FILE     input file to use (defaults to stdin)
  -o FILE     output file to use (defaults to stdout)
  -pem TYPE   format the output as a PEM block with this type
EOF
	exit 2
}

die() {
	printf 'ascii2der: %s\n' "$1" >&2
	exit 1
}

# die_at POS MSG: reports an error at the line containing byte offset POS. POS
# may also be OFFSET:N, meaning N lines after that one.
die_at() {
	local pos=${1%:*} extra=0 pre nl
	[[ $1 == *:* ]] && extra=${1#*:}
	pre=${TXT:0:pos}
	nl=${pre//[!$'\n']/}
	die "line $((${#nl} + extra + 1)): $2"
}

# Universal tag aliases: UNUM[name]=number, UCONS[name]=default constructed bit.
declare -A UNUM UCONS
while read -r n name c; do
	UNUM[$name]=$n
	UCONS[$name]=$c
done <<'EOF'
1 BOOLEAN 0
2 INTEGER 0
3 BIT_STRING 0
4 OCTET_STRING 0
5 NULL 0
6 OBJECT_IDENTIFIER 0
7 OBJECT_DESCRIPTOR 0
8 EXTERNAL 0
9 REAL 0
10 ENUMERATED 0
11 EMBEDDED_PDV 0
12 UTF8String 0
13 RELATIVE_OID 0
14 TIME 0
16 SEQUENCE 1
17 SET 1
18 NumericString 0
19 PrintableString 0
20 T61String 0
21 VideotexString 0
22 IA5String 0
23 UTCTime 0
24 GeneralizedTime 0
25 GraphicString 0
26 VisibleString 0
27 GeneralString 0
28 UniversalString 0
30 BMPString 0
31 DATE 0
32 TIME-OF-DAY 0
33 DATE-TIME 0
34 DURATION 0
35 OID-IRI 0
36 RELATIVE-OID-IRI 0
EOF

INT64_MIN=$((-9223372036854775807 - 1))
WS=$' \t\r\n'
# Characters that end a bare symbol; ']' must come first inside a bracket expression.
SYMDELIM=$']{}[ \t\r\n`"#'

TXT=""  # input text
TLEN=0  # length of TXT in bytes
P=0     # scanner position (byte offset into TXT)
# Bash substring access is O(length), so the scanner reads through a small
# window of TXT that starts at offset WB.
WIN=""
WB=0
WLEN=0
WSIZE=4096
# The fast tokenizer matches TOKRE against TW, a copy of TXT starting at P.
TW=""
TWB=0
NL=$'\n'
TOKRE='^(['"$WS"']|#[^'"$NL"']*'"$NL"')*([{}]|[uU]?"([^"\\]|\\.)*"|b?`[^`]*`|\[[^]]*]|[^'"$SYMDELIM"']+)'
# Characters that end a run of plain words; ']' must come first.
SEGSTOP=']"`[#'
WQ=()         # queued words
WI=0          # index of the next queued word
NWQ=0         # number of queued words
SEGP=0        # position of the queued words, for error messages
SEGL=0        # newlines passed since SEGP
declare -A SYMV # bare symbol -> encoding
declare -A TAGV # bracketed tag -> encoding
S=""    # string return register
ERR=""  # error message register
h=""

# printf arguments that convert the characters of $piece to numbers in one
# call. All entries have the same width, so a prefix covers N characters.
printf -v ORDARGS '"'"'"'${piece:%5d:1}" ' {0..255}
ORDW=$((${#ORDARGS} / 256))

# chars_to_hex STR FORMAT -> V (FORMAT applied to each character's code)
chars_to_hex() {
	local s=$1 piece o
	V=""
	for ((o = 0; o < ${#s}; o += 256)); do
		piece=${s:o:256}
		eval "printf -v h '$2' ${ORDARGS:0:${#piece}*ORDW}"
		V+=$h
	done
}

# ---------------------------------------------------------------------------
# Integer helpers. uint64 values are stored in bash's signed 64-bit integers.

# lshr V N -> LS (logical right shift; shifts of 64 or more yield 0)
lshr() {
	if (($2 >= 64)); then
		LS=0
	elif (($2 == 0)); then
		LS=$1
	else
		LS=$(((($1 >> 1) & 0x7fffffffffffffff) >> ($2 - 1)))
	fi
}

# ult A B: unsigned A < B
ult() {
	((($1 ^ INT64_MIN) < ($2 ^ INT64_MIN)))
}

# parse_uint DIGITS MAX -> U (fails if the value exceeds the decimal string MAX)
parse_uint() {
	local d=${1##+(0)}
	[[ -z $d ]] && d=0
	((${#d} < ${#2})) || { ((${#d} == ${#2})) && ! [[ $d > $2 ]]; } || return 1
	if ((${#d} <= 18)); then
		U=$((10#$d))
	else
		U=$((10#${d:0:${#d}-1} * 10 + ${d: -1}))
	fi
}

# parse_int64 STR -> U
parse_int64() {
	local s=$1 neg=0
	[[ $s == -* ]] && neg=1 && s=${s:1}
	if ((neg)); then
		parse_uint "$s" 9223372036854775808 || return 1
		U=$((-U))
	else
		parse_uint "$s" 9223372036854775807 || return 1
	fi
}

# ---------------------------------------------------------------------------
# Encoders. All return lowercase hex in S.

# append_base128 VALUE LENGTH_OVERRIDE -> S
append_base128() {
	local v=$1 len=$2 l=1 n i
	local -a out=()
	if ((v < 0)); then
		l=10
	else
		for ((n = v >> 7; n; n >>= 7)); do ((l++)); done
	fi
	if ((len)); then
		if ((len < l)); then
			ERR="length override of $len is too small, need at least $l bytes"
			return 1
		fi
		l=$len
	fi
	for ((i = l - 1; i >= 0; i--)); do
		if ((7 * i >= 64)); then
			LS=0
		elif ((v >= 0)); then
			LS=$((v >> 7 * i))
		else
			lshr "$v" $((7 * i))
		fi
		out+=($((LS & 0x7f | (i ? 0x80 : 0))))
	done
	printf -v S '%02x' "${out[@]}"
}

# append_tag CLASS NUMBER CONSTRUCTED LONG_FORM_OVERRIDE -> S
append_tag() {
	local b=$(($1 | ($3 ? 0x20 : 0))) t
	if (($2 < 31 && $4 == 0)); then
		printf -v S '%02x' $((b | $2))
		return 0
	fi
	printf -v t '%02x' $((b | 0x1f))
	append_base128 "$2" "$4" || return 1
	S=$t$S
}

# append_length LENGTH LENGTH_OVERRIDE -> S
append_length() {
	local len=$1 ll=$2 l=0 n i b
	if ((len < 0x80 && ll == 0)); then
		printf -v S '%02x' "$len"
		return 0
	fi
	for ((n = len; n != 0; n >>= 8)); do ((l++)); done
	if ((ll)); then
		if ((ll > 127)); then
			ERR="length override too large"
			return 1
		fi
		if ((ll < l)); then
			ERR="length override of $ll too small, need at least $l bytes"
			return 1
		fi
		l=$ll
	fi
	printf -v S '%02x' $((0x80 | l))
	for ((i = l - 1; i >= 0; i--)); do
		if ((8 * i >= 64)); then b=0; else b=$(((len >> (8 * i)) & 0xff)); fi
		printf -v h '%02x' "$b"
		S+=$h
	done
}

# append_integer VALUE -> S (minimal two's complement)
append_integer() {
	local v=$1 n=$1 l=1 i
	while ((n > 0x7f || n < -0x80)); do ((n >>= 8, l++)); done
	S=""
	for ((i = l - 1; i >= 0; i--)); do
		printf -v h '%02x' $(((v >> (8 * i)) & 0xff))
		S+=$h
	done
}

# append_oid COMPONENT... -> S
append_oid() {
	local first v out
	(($# >= 2)) || return 1
	ult "$1" 3 || return 1
	if (($1 < 2)) && ult 39 "$2"; then return 1; fi
	first=$(($1 * 40 + $2))
	ult "$first" "$2" && return 1
	append_base128 "$first" 0
	out=$S
	shift 2
	for v; do
		append_base128 "$v" 0
		out+=$S
	done
	S=$out
}

# utf16_hex CODEPOINT (signed 32-bit) -> h
utf16_hex() {
	local r=$1
	if ((r <= 0xffff)); then
		printf -v h '%04x' $((r & 0xffff))
	elif ((r > 0x10ffff)); then
		h=fffdfffd
	else
		((r -= 0x10000))
		printf -v h '%04x%04x' $((0xd800 + (r >> 10))) $((0xdc00 + (r & 0x3ff)))
	fi
}

# ---------------------------------------------------------------------------
# Scanner

# at OFFSET LEN -> C: up to LEN characters of TXT starting at P+OFFSET.
at() {
	local i=$((P + $1 - WB))
	if ((i < 0 || (i + $2 > WLEN && WB + WLEN < TLEN))); then
		WB=$P
		WIN=${TXT:P:WSIZE}
		WLEN=${#WIN}
		i=$1
	fi
	C=${WIN:i:$2}
}

# ord CHAR -> O
ord() {
	printf -v O '%d' "'$1"
	((O &= 0xff))
}

# consume_up_to CHAR -> CU (text before CHAR); P moves past CHAR.
consume_up_to() {
	local i=$((P - WB)) rest=""
	((i >= 0 && i < WLEN)) && rest=${WIN:i}
	CU=${rest%%"$1"*}
	if ((${#CU} == ${#rest})); then
		rest=${TXT:P}
		CU=${rest%%"$1"*}
		((${#CU} < ${#rest})) || return 1
	fi
	((P += ${#CU} + 1))
}

# skip_space: skips whitespace and comments.
skip_space() {
	local i rest ws
	while :; do
		at 0 1
		case $C in
		' ' | $'\t' | $'\r' | $'\n')
			i=$((P - WB))
			rest=${WIN:i}
			ws=${rest%%[!$WS]*}
			((P += ${#ws}))
			;;
		'#')
			consume_up_to $'\n' || P=$TLEN
			;;
		*) return ;;
		esac
	done
}

# hex_digits COUNT -> R (value of the next COUNT hex digits)
hex_digits() {
	((P + $1 <= TLEN)) || die_at "$P" "unfinished escape sequence"
	at 0 "$1"
	[[ $C =~ ^[0-9a-fA-F]+$ ]] || die_at "$P" "invalid hex in escape sequence \"$C\""
	R=$((16#$C))
	((P += $1))
}

# parse_escape -> R (code point as a signed 32-bit value). P is at the backslash.
parse_escape() {
	((P++))
	((P < TLEN)) || die_at "$P" "expected escape character"
	at 0 1
	((P++))
	case $C in
	n) R=10 ;;
	'"') R=34 ;;
	'\') R=92 ;;
	x) hex_digits 2 ;;
	u) hex_digits 4 ;;
	U)
		hex_digits 8
		((R >= 0x80000000)) && ((R -= 0x100000000))
		;;
	*) die_at $((P - 1)) "unknown escape sequence \\$C" ;;
	esac
}

# decode_utf8 -> R, advancing P past one UTF-8 encoded code point.
decode_utf8() {
	local b0 b1 b2 b3 lo=0x80 hi=0xbf
	at 0 4
	local c4=$C
	ord "${c4:0:1}"
	b0=$O
	if ((b0 < 0x80)); then
		R=$b0
		((P++))
		return
	fi
	if ((b0 >= 0xc2 && b0 <= 0xdf)); then
		if ((${#c4} >= 2)); then
			ord "${c4:1:1}"
			b1=$O
			if ((b1 >= 0x80 && b1 <= 0xbf)); then
				R=$(((b0 & 0x1f) << 6 | (b1 & 0x3f)))
				((P += 2))
				return
			fi
		fi
	elif ((b0 >= 0xe0 && b0 <= 0xef)); then
		((b0 == 0xe0)) && lo=0xa0
		((b0 == 0xed)) && hi=0x9f
		if ((${#c4} >= 3)); then
			ord "${c4:1:1}"
			b1=$O
			ord "${c4:2:1}"
			b2=$O
			if ((b1 >= lo && b1 <= hi && b2 >= 0x80 && b2 <= 0xbf)); then
				R=$(((b0 & 0x0f) << 12 | (b1 & 0x3f) << 6 | (b2 & 0x3f)))
				((P += 3))
				return
			fi
		fi
	elif ((b0 >= 0xf0 && b0 <= 0xf4)); then
		((b0 == 0xf0)) && lo=0x90
		((b0 == 0xf4)) && hi=0x8f
		if ((${#c4} >= 4)); then
			ord "${c4:1:1}"
			b1=$O
			ord "${c4:2:1}"
			b2=$O
			ord "${c4:3:1}"
			b3=$O
			if ((b1 >= lo && b1 <= hi && b2 >= 0x80 && b2 <= 0xbf && b3 >= 0x80 && b3 <= 0xbf)); then
				R=$(((b0 & 0x07) << 18 | (b1 & 0x3f) << 12 | (b2 & 0x3f) << 6 | (b3 & 0x3f)))
				((P += 4))
				return
			fi
		fi
	fi
	die_at "$P" "invalid UTF-8"
}

# scan_quoted MODE -> V. MODE is 8 (bytes), 16 (UTF-16) or 32 (UTF-32).
# P is just past the opening quote.
scan_quoted() {
	local mode=$1 start=$P esc
	local -a parts=()
	while :; do
		((P < TLEN)) || die_at "$start" 'unmatched "'
		at 0 1
		case $C in
		'"')
			((P++))
			printf -v V '%s' "${parts[@]}"
			return
			;;
		'\')
			esc=$P
			parse_escape
			case $mode in
			8)
				((R > 0xff)) && die_at "$esc" "illegal escape for quoted string"
				printf -v h '%02x' $((R & 0xff))
				;;
			16) utf16_hex "$R" ;;
			32) printf -v h '%08x' $((R & 0xffffffff)) ;;
			esac
			;;
		*)
			if ((mode == 8)); then
				ord "$C"
				printf -v h '%02x' "$O"
				((P++))
			else
				decode_utf8
				if ((mode == 16)); then utf16_hex "$R"; else printf -v h '%08x' "$R"; fi
			fi
			;;
		esac
		parts+=("$h")
	done
}

# scan_bit_string -> V. P is just past "b`".
scan_bit_string() {
	local bits="" i ch saw=0 pad=0 nbytes rem inrem j
	consume_up_to '`' || die_at "$P" 'unmatched `'
	for ((i = 0; i < ${#CU}; i++)); do
		ch=${CU:i:1}
		case $ch in
		0 | 1) bits+=$ch ;;
		'|')
			((saw)) && die_at "$P" "duplicate |"
			nbytes=$(((${#bits} + 7) / 8))
			rem=$((nbytes * 8 - ${#bits}))
			inrem=$((${#CU} - i - 1))
			((inrem > rem)) && die_at "$P" "expected at most $rem explicit padding bits; found $inrem"
			saw=1
			pad=$rem
			;;
		*) die_at "$P" "unexpected rune '$ch'" ;;
		esac
	done
	nbytes=$(((${#bits} + 7) / 8))
	((saw)) || pad=$((nbytes * 8 - ${#bits}))
	while ((${#bits} < nbytes * 8)); do bits+=0; done
	printf -v V '%02x' "$pad"
	for ((j = 0; j < nbytes; j++)); do
		printf -v h '%02x' $((2#${bits:j*8:8}))
		V+=$h
	done
}

# decode_long_form STR -> L
decode_long_form() {
	[[ $1 =~ ^[+-]?[0-9]+$ ]] || return 1
	L=$((10#${1#[+-]}))
	[[ $1 == -* ]] && L=$((-L))
	((L > 0)) || { ERR="invalid long-form override"; return 1; }
}

# decode_tag_string STR -> V (encoded tag)
decode_tag_string() {
	local s=$1 class=128 num cons=1 lfo=0
	local -a ss=()
	while :; do
		ss+=("${s%% *}")
		[[ $s == *' '* ]] || break
		s=${s#* }
	done
	if [[ ${ss[0]} == long-form:* ]]; then
		ERR="invalid long-form override"
		decode_long_form "${ss[0]#long-form:}" || return 1
		lfo=$L
		ss=("${ss[@]:1}")
	fi
	if ((${#ss[@]} == 0)); then
		ERR="expected tag component"
		return 1
	fi
	if [[ -n ${UNUM[${ss[0]}]-} ]]; then
		class=0
		num=${UNUM[${ss[0]}]}
		cons=${UCONS[${ss[0]}]}
		ss=("${ss[@]:1}")
	else
		case ${ss[0]} in
		APPLICATION) class=64 ;;
		PRIVATE) class=192 ;;
		UNIVERSAL) class=0 ;;
		esac
		((class != 128)) && ss=("${ss[@]:1}")
		if ((${#ss[@]} == 0)); then
			ERR="expected tag number"
			return 1
		fi
		if ! [[ ${ss[0]} =~ ^[0-9]+$ ]] || ! parse_uint "${ss[0]}" 4294967295; then
			ERR="invalid tag number \"${ss[0]}\""
			return 1
		fi
		num=$U
		ss=("${ss[@]:1}")
	fi
	if ((${#ss[@]} > 0)); then
		case ${ss[0]} in
		CONSTRUCTED) cons=1 ;;
		PRIMITIVE) cons=0 ;;
		*)
			ERR="unexpected tag component \"${ss[0]}\""
			return 1
			;;
		esac
		ss=("${ss[@]:1}")
	fi
	if ((${#ss[@]} != 0)); then
		ERR="excess tag component \"${ss[0]}\""
		return 1
	fi
	append_tag "$class" "$num" "$cons" "$lfo" || return 1
	V=$S
}

# slow_next_token: next_token for any input, scanning character by character.
slow_next_token() {
	local c start sym n rest
	skip_space
	TP=$P
	if ((P >= TLEN)); then
		K=eof
		return
	fi
	K=bytes
	at 0 2
	c=${C:0:1}
	n=${C:1:1}
	case $c in
	'{' | '}')
		K=$c
		((P++))
		return
		;;
	'"')
		((P++))
		scan_quoted 8
		return
		;;
	'`')
		((P++))
		consume_up_to '`' || die_at "$P" 'unmatched `'
		[[ $CU =~ ^([0-9a-fA-F][0-9a-fA-F])*$ ]] || die_at "$TP" "invalid hex literal"
		V=${CU,,}
		return
		;;
	'[')
		((P++))
		consume_up_to ']' || die_at "$P" "unmatched ["
		decode_tag_string "$CU" || die_at "$TP" "$ERR"
		return
		;;
	u | U | b)
		if [[ $c == u && $n == '"' ]]; then
			((P += 2))
			scan_quoted 16
			return
		elif [[ $c == U && $n == '"' ]]; then
			((P += 2))
			scan_quoted 32
			return
		elif [[ $c == b && $n == '`' ]]; then
			((P += 2))
			scan_bit_string
			return
		fi
		;;
	esac

	# A bare symbol runs to the next whitespace or delimiter.
	start=$P
	sym=$c
	((P++))
	while ((P < TLEN)); do
		at 0 1
		rest=${WIN:P-WB}
		C=${rest%%[$SYMDELIM]*}
		sym+=$C
		((P += ${#C}))
		((${#C} < ${#rest})) && break
	done
	classify_symbol "$sym" "$start"
}

# sync_window: makes TW start at P.
sync_window() {
	local n=$((P - TWB))
	if ((n)); then
		if ((n > 0 && n < ${#TW})); then TW=${TW:n}; else TW=${TXT:P:WSIZE}; fi
		TWB=$P
	fi
	((${#TW} < 512 && P + ${#TW} < TLEN)) && TW=${TXT:P:WSIZE}
}

# fill_queue: queues the whitespace-separated words before the next character
# that needs the regex tokenizer. Newlines are queued as '#' words, which can't
# otherwise occur. Fails if there are no words.
fill_queue() {
	local ws seg oifs
	sync_window
	ws=${TW%%[!$WS]*}
	if [[ -n $ws ]]; then
		((P += ${#ws}))
		TW=${TW:${#ws}} TWB=$P
	fi
	seg=${TW%%[$SEGSTOP]*}
	# Leave a word that may be cut off by the window, or that may be the u, U
	# or b prefix of a string, to the regex tokenizer.
	if { ((${#seg} == ${#TW} && P + ${#TW} < TLEN)) || [[ ${TW:${#seg}:1} == [\"\`] ]]; } &&
		[[ $seg != *[$WS] ]]; then
		[[ $seg == *[$WS]* ]] || return 1
		seg=${seg%[$WS]*}
	fi
	[[ -n $seg ]] || return 1
	((P += ${#seg}))
	[[ $seg == *$NL* ]] && seg=${seg//$NL/ # }
	seg=${seg//\{/ \{ }
	seg=${seg//\}/ \} }
	oifs=$IFS IFS=$WS
	WQ=($seg)
	IFS=$oifs
	WI=0 NWQ=${#WQ[@]} SEGP=$TWB SEGL=0
}

# next_token -> K (kind), V (hex value for bytes), L (length modifier), TP (position)
# Kinds: bytes '{' '}' indefinite long-form adjust-length eof
# Runs of plain words are split in bulk by fill_queue. Other common tokens are
# matched with one regex, and anything else (escapes, bit strings, errors,
# EOF) is left to slow_next_token.
next_token() {
	local tok body n size=$WSIZE
	while ((WI < NWQ)) || fill_queue; do
		tok=${WQ[WI++]}
		# The word is SEGL lines after the one holding SEGP.
		case $tok in
		'#')
			((SEGL++))
			continue
			;;
		'{' | '}')
			K=$tok TP=$SEGP:$SEGL
			return
			;;
		esac
		TP=$SEGP:$SEGL K=bytes
		V=${SYMV[$tok]-}
		if [[ -z $V ]]; then
			classify_symbol "$tok" "$TP"
			[[ $K == bytes ]] && SYMV[$tok]=$V
		fi
		return
	done
	sync_window
	# A match that reaches the end of the window may be cut short.
	until [[ $TW =~ $TOKRE ]] && ((${#BASH_REMATCH[0]} < ${#TW} || P + ${#TW} >= TLEN)); do
		if ((P + ${#TW} >= TLEN)); then
			slow_next_token
			return
		fi
		((size *= 2))
		TW=${TXT:P:size}
	done
	tok=${BASH_REMATCH[2]}
	n=${#BASH_REMATCH[0]}
	TP=$((P + n - ${#tok}))
	K=bytes
	case $tok in
	'{' | '}')
		K=$tok
		;;
	\"*)
		[[ $tok == *\\* ]] && { P=$TP; slow_next_token; return; }
		chars_to_hex "${tok:1:${#tok}-2}" '%02x'
		;;
	u\"* | U\"*)
		body=${tok:2:${#tok}-3}
		[[ $body == *[!\ -~]* || $body == *\\* ]] && { P=$TP; slow_next_token; return; }
		if [[ $tok == u* ]]; then chars_to_hex "$body" '%04x'; else chars_to_hex "$body" '%08x'; fi
		;;
	b\`*)
		P=$TP
		slow_next_token
		return
		;;
	\`*)
		body=${tok:1:${#tok}-2}
		[[ $body =~ ^([0-9a-fA-F][0-9a-fA-F])*$ ]] || die_at "$TP" "invalid hex literal"
		V=${body,,}
		;;
	\[*)
		body=${tok:1:${#tok}-2}
		[[ -z $body ]] && { P=$TP; slow_next_token; return; }
		V=${TAGV[$body]-}
		if [[ -z $V ]]; then
			decode_tag_string "$body" || die_at "$TP" "$ERR"
			TAGV[$body]=$V
		fi
		;;
	*)
		V=${SYMV[$tok]-}
		if [[ -z $V ]]; then
			classify_symbol "$tok" "$TP"
			[[ $K == bytes ]] && SYMV[$tok]=$V
		fi
		;;
	esac
	((P += n))
}

# classify_symbol SYM START -> K, V, L
classify_symbol() {
	local sym=$1 start=$2 n oifs
	local -a parts
	K=bytes
	if [[ -n ${UNUM[$sym]-} ]]; then
		append_tag 0 "${UNUM[$sym]}" "${UCONS[$sym]}" 0
		V=$S
	elif [[ $sym =~ ^-?[0-9]+$ ]]; then
		parse_int64 "$sym" || die_at "$start" "integer out of range: $sym"
		append_integer "$U"
		V=$S
	elif [[ $sym =~ ^[0-9]+(\.[0-9]+)+$ ]]; then
		oifs=$IFS IFS=.
		parts=($sym)
		IFS=$oifs
		for ((n = 0; n < ${#parts[@]}; n++)); do
			parse_uint "${parts[n]}" 18446744073709551615 || die_at "$start" "OID component out of range: $sym"
			parts[n]=$U
		done
		append_oid "${parts[@]}" || die_at "$start" "invalid OID: $sym"
		V=$S
	elif [[ $sym =~ ^(\.[0-9]+)+$ ]]; then
		oifs=$IFS IFS=.
		parts=(${sym:1})
		IFS=$oifs
		V=""
		for ((n = 0; n < ${#parts[@]}; n++)); do
			parse_uint "${parts[n]}" 18446744073709551615 || die_at "$start" "OID component out of range: $sym"
			append_base128 "$U" 0
			V+=$S
		done
	elif [[ $sym == TRUE ]]; then
		V=ff
	elif [[ $sym == FALSE ]]; then
		V=00
	elif [[ $sym == indefinite ]]; then
		K=indefinite
	elif [[ $sym == adjust-length:* ]]; then
		n=${sym#adjust-length:}
		n=${n#+}
		[[ $n =~ ^-?[0-9]+$ ]] && parse_int64 "$n" || die_at "$start" "invalid adjust-length: $sym"
		K=adjust-length
		L=$U
	elif [[ $sym == long-form:* ]]; then
		ERR="invalid long-form override: $sym"
		decode_long_form "${sym#long-form:}" || die_at "$start" "$ERR"
		K=long-form
	else
		die_at "$start" "unrecognized symbol \"$sym\""
	fi
}

# encode_seq NESTED OPEN_POS -> R_HEX. Encodes tokens until EOF or, when
# NESTED, the matching '}'.
encode_seq() {
	local nested=$1 open=$2 lm="" lmlen=0 lmpos=0 adj="" adjlen=0 adjpos=0
	local child len tpos
	local -a parts=()
	while :; do
		next_token
		case $K in
		bytes | eof)
			if [[ -n $lm$adj ]]; then
				[[ -n $lm ]] && die_at "$lmpos" "$lm token must modify '{'"
				die_at "$adjpos" "adjust-length token must modify '{'"
			fi
			if [[ $K == bytes ]]; then
				parts+=("$V")
				continue
			fi
			((nested)) && die_at "$open" "unmatched '{'"
			printf -v R_HEX '%s' "${parts[@]}"
			return
			;;
		'{')
			tpos=$TP
			encode_seq 1 "$tpos"
			child=$R_HEX
			len=$((${#child} / 2))
			if [[ -n $adj ]]; then
				((len += adjlen))
				if ((len < 0 || len > 2147483647)); then
					((adjlen < 0)) && die_at "$tpos" "length adjustment underflowed"
					die_at "$tpos" "length adjustment overflowed"
				fi
			fi
			if [[ $lm == indefinite ]]; then
				parts+=(80 "$child" 0000)
			else
				if [[ $lm == long-form ]]; then
					append_length "$len" "$lmlen" || die_at "$lmpos" "$ERR"
				else
					append_length "$len" 0 || die_at "$tpos" "$ERR"
				fi
				parts+=("$S" "$child")
			fi
			lm=""
			adj=""
			;;
		'}')
			if ((nested)); then
				printf -v R_HEX '%s' "${parts[@]}"
				return
			fi
			die_at "$TP" "unmatched '}'"
			;;
		indefinite | long-form)
			[[ -n $lm ]] && die_at "$TP" "found $K token but already seen $lm token"
			lm=$K
			lmpos=$TP
			lmlen=${L-0}
			;;
		adjust-length)
			[[ -n $adj ]] && die_at "$TP" "duplicate adjust-length token"
			adj=1
			adjlen=$L
			adjpos=$TP
			;;
		esac
	done
}

# ---------------------------------------------------------------------------
# Output

# write_binary HEX: writes the bytes to stdout.
write_binary() {
	local hex=$1 n=${#1} o j k blk piece fmt
	for ((o = 0; o < n; o += 65536)); do
		blk=${hex:o:65536}
		for ((j = 0; j < ${#blk}; j += 4096)); do
			piece=${blk:j:4096}
			if ((AMP)); then
				fmt=${piece//??/\\x&}
			else
				fmt=""
				for ((k = 0; k < ${#piece}; k += 2)); do
					fmt+="\\x${piece:k:2}"
				done
			fi
			printf "$fmt"
		done
	done
}

B64=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/

# write_pem TYPE HEX: 64 base64 characters (48 bytes, 96 hex digits) per line.
write_pem() {
	local type=$1 hex=$2 n=${#2} o j k blk piece v line
	local -a lines=()
	for ((o = 0; o < n; o += 98304)); do
		blk=${hex:o:98304}
		for ((j = 0; j < ${#blk}; j += 96)); do
			piece=${blk:j:96}
			line=""
			for ((k = 0; k + 6 <= ${#piece}; k += 6)); do
				v=$((16#${piece:k:6}))
				line+=${B64:v>>18&63:1}${B64:v>>12&63:1}${B64:v>>6&63:1}${B64:v&63:1}
			done
			if ((${#piece} - k == 2)); then
				v=$((16#${piece:k:2} << 16))
				line+=${B64:v>>18&63:1}${B64:v>>12&63:1}==
			elif ((${#piece} - k == 4)); then
				v=$((16#${piece:k:4} << 8))
				line+=${B64:v>>18&63:1}${B64:v>>12&63:1}${B64:v>>6&63:1}=
			fi
			lines+=("$line")
		done
	done
	printf -- '-----BEGIN %s-----\n' "$type"
	((${#lines[@]} == 0)) || printf '%s\n' "${lines[@]}"
	printf -- '-----END %s-----\n' "$type"
}

main() {
	local in="" out="" pem=""
	while (($#)); do
		case $1 in
		-i) (($# >= 2)) || usage; in=$2; shift ;;
		-o) (($# >= 2)) || usage; out=$2; shift ;;
		-pem) (($# >= 2)) || usage; pem=$2; shift ;;
		*) usage ;;
		esac
		shift
	done
	if [[ -n $in ]]; then exec <"$in" || die "cannot open $in"; fi
	IFS= read -r -d '' TXT || true
	TLEN=${#TXT}

	encode_seq 0 0

	if [[ -n $out ]]; then exec >"$out" || die "cannot open $out"; fi
	if [[ -n $pem ]]; then
		write_pem "$pem" "$R_HEX"
	else
		write_binary "$R_HEX"
	fi
}

main "$@"
