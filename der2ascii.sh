#!/usr/bin/env bash
# der2ascii.sh - disassemble DER/BER into DER ASCII, written entirely in Bash.
#
# The output format follows https://github.com/google/der-ascii (language.txt)
# and mirrors the heuristics of its der2ascii tool.
#
# Usage: der2ascii.sh [-i in] [-o out] [-hex | -pem]

set -u
shopt -s extglob
export LC_ALL=C

usage() {
	cat >&2 <<'EOF'
Usage: der2ascii.sh [options]
  -i FILE   input file to use (defaults to stdin)
  -o FILE   output file to use (defaults to stdout)
  -hex      treat the input as hex, ignoring punctuation and whitespace
  -pem      treat the input as PEM and decode the first PEM block
EOF
	exit 2
}

die() {
	printf 'der2ascii: %s\n' "$1" >&2
	exit 1
}

# Universal tag aliases: UNAME[number]=name, UCONS[number]=default constructed bit.
declare -a UNAME UCONS
while read -r n name c; do
	UNAME[n]=$name
	UCONS[n]=$c
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

# Known OIDs keyed by the hex of their encoded contents (from der-ascii's oid_names.go).
declare -A OIDNAME=(
  [2b81040021]='secp224r1'
  [2a8648ce3d030107]='secp256r1'
  [2b81040022]='secp384r1'
  [2b81040023]='secp521r1'
  [2a8648ce3d0101]='prime-field'
  [2a8648ce3d0102]='characteristic-two-field'
  [2a8648ce3d01020301]='gnBasis'
  [2a8648ce3d01020302]='tpBasis'
  [2a8648ce3d01020303]='ppBasis'
  [2a864886f70d0202]='md2'
  [2a864886f70d0204]='md4'
  [2a864886f70d0205]='md5'
  [2b0e03021a]='sha1'
  [608648016503040204]='sha224'
  [608648016503040201]='sha256'
  [608648016503040202]='sha384'
  [608648016503040203]='sha512'
  [2a864886f70d010108]='mgf1'
  [2a864886f70d010101]='rsaEncryption'
  [2a864886f70d01010a]='rsassa-pss'
  [2a8648ce3d0201]='ecPublicKey'
  [2a8648ce380401]='dsa'
  [2b656e]='x25519'
  [2b656f]='x448'
  [608648016503040311]='ml-dsa-44'
  [608648016503040312]='ml-dsa-65'
  [608648016503040313]='ml-dsa-87'
  [608648016503040401]='ml-kem-512'
  [608648016503040402]='ml-kem-768'
  [608648016503040403]='ml-kem-1024'
  [2a864886f70d010102]='md2WithRSAEncryption'
  [2a864886f70d010103]='md4WithRSAEncryption'
  [2a864886f70d010104]='md5WithRSAEncryption'
  [2a864886f70d010105]='sha1WithRSAEncryption'
  [2a864886f70d01010e]='sha224WithRSAEncryption'
  [2a864886f70d01010b]='sha256WithRSAEncryption'
  [2a864886f70d01010c]='sha384WithRSAEncryption'
  [2a864886f70d01010d]='sha512WithRSAEncryption'
  [2a8648ce380403]='dsa-with-sha1'
  [608648016503040301]='dsa-with-sha224'
  [608648016503040302]='dsa-with-sha256'
  [2a8648ce3d0401]='ecdsa-with-SHA1'
  [2a8648ce3d040301]='ecdsa-with-SHA224'
  [2a8648ce3d040302]='ecdsa-with-SHA256'
  [2a8648ce3d040303]='ecdsa-with-SHA384'
  [2a8648ce3d040304]='ecdsa-with-SHA512'
  [2b6570]='ed25519'
  [2b6571]='ed448'
  [2b06010505070624]='alg-unsigned'
  [2b06010505070101]='authorityInfoAccess'
  [2b06010505070107]='ipAddrBlocks'
  [2b06010505070108]='autonomousSysIds'
  [2b0601050507010b]='subjectInfoAccess'
  [2b0601050507011c]='ipAddrBlocks-v2'
  [2b0601050507011d]='autonomousSysIds-v2'
  [551d09]='subjectDirectoryAttributes'
  [551d0e]='subjectKeyIdentifier'
  [551d0f]='keyUsage'
  [551d10]='privateKeyUsagePeriod'
  [551d11]='subjectAltName'
  [551d12]='issuerAltName'
  [551d13]='basicConstraints'
  [551d14]='cRLNumber'
  [551d15]='reasonCode'
  [551d17]='instructionCode'
  [551d18]='invalidityDate'
  [551d1b]='deltaCRLIndicator'
  [551d1c]='issuingDistributionPoint'
  [551d1d]='certificateIssuer'
  [551d1e]='nameConstraints'
  [551d1f]='cRLDistributionPoints'
  [551d20]='certificatePolicies'
  [551d21]='policyMappings'
  [551d23]='authorityKeyIdentifier'
  [551d24]='policyConstraints'
  [551d25]='extKeyUsage'
  [551d2e]='freshestCRL'
  [551d36]='inhibitAnyPolicy'
  [2b06010505070301]='serverAuth'
  [2b06010505070302]='clientAuth'
  [2b06010505070303]='codeSigning'
  [2b06010505070304]='emailProtection'
  [2b06010505070308]='timeStamping'
  [2b06010505070309]='OCSPSigning'
  [2b0601050507031e]='bgpsec-router'
  [551d2500]='anyExtendedKeyUsage'
  [2b06010505070201]='cps'
  [2b06010505070202]='unotice'
  [2b06010505070e02]='ipAddr-asNumber'
  [2b06010505070e03]='ipAddr-asNumber-v2'
  [551d2000]='anyPolicy'
  [67810c010201]='domain-validated'
  [67810c010202]='organization-validated'
  [67810c010203]='individual-validated'
  [2b06010505073001]='ocsp'
  [2b06010505073002]='caIssuers'
  [2b06010505073005]='caRepository'
  [2b0601050507300a]='rpkiManifest'
  [2b0601050507300b]='signedObject'
  [2b0601050507300d]='rpkiNotify'
  [2a864886f70d010901]='emailAddress'
  [2a864886f70d010902]='unstructuredName'
  [2a864886f70d010903]='contentType'
  [2a864886f70d010904]='messageDigest'
  [2a864886f70d010905]='signingTime'
  [2a864886f70d010906]='counterSignature'
  [2a864886f70d010907]='challengePassword'
  [2a864886f70d010908]='unstructuredAddress'
  [2a864886f70d010909]='extendedCertificateAttributes'
  [2a864886f70d01090a]='issuerAndSerialNumber'
  [2a864886f70d01090b]='passwordCheck'
  [2a864886f70d01090c]='publicKey'
  [2a864886f70d01090d]='signingDescription'
  [2a864886f70d01090e]='extensionRequest'
  [2a864886f70d01090f]='smimeCapabilities'
  [2a864886f70d010914]='friendlyName'
  [2a864886f70d010915]='localKeyId'
  [550403]='commonName'
  [550405]='serialNumber'
  [550406]='countryName'
  [550407]='localityName'
  [550408]='stateOrProvinceName'
  [550409]='streetAddress'
  [55040a]='organizationName'
  [55040b]='organizationUnitName'
  [55040c]='title'
  [550411]='postalCode'
  [2b06010505071901]='rdna-unsigned'
  [2a864886f70d0109100201]='receiptRequest'
  [2a864886f70d0109100202]='securityLabel'
  [2a864886f70d0109100203]='mlExpandHistory'
  [2a864886f70d0109100204]='contentHint'
  [2a864886f70d0109100205]='msgSigDigest'
  [2a864886f70d0109100207]='contentIdentifier'
  [2a864886f70d0109100209]='equivalentLabels'
  [2a864886f70d010910020a]='contentReference'
  [2a864886f70d010910020b]='encrypKeyPref'
  [2a864886f70d010910020c]='signingCertificate'
  [2a864886f70d0109100b01]='preferBinaryInside'
  [2a864886f70d010701]='data'
  [2a864886f70d010702]='signedData'
  [2a864886f70d010703]='envelopedData'
  [2a864886f70d010704]='signedAndEnvelopedData'
  [2a864886f70d010705]='digestedData'
  [2a864886f70d010706]='encryptedData'
  [2a864886f70d0109100101]='receipt'
  [2a864886f70d0109100102]='authData'
  [2a864886f70d0109100106]='contentInfo'
  [2a864886f70d0109100118]='routeOriginAuthz'
  [2a864886f70d010910011a]='rpkiManifest'
  [2a864886f70d0109100123]='rpkiGhostbusters'
  [2a864886f70d010910012f]='geofeedCSVwithCRLF'
  [2a864886f70d0109100130]='signedChecklist'
  [2a864886f70d0109100131]='ASPA'
  [2a864886f70d0109100132]='signedTAL'
  [2a864886f70d010c0a0101]='keyBag'
  [2a864886f70d010c0a0102]='pkcs-8ShroudedKeyBag'
  [2a864886f70d010c0a0103]='certBag'
  [2a864886f70d010c0a0104]='crlBag'
  [2a864886f70d010c0a0105]='secretBag'
  [2a864886f70d010c0a0106]='safeContentsBag'
  [2a864886f70d010c0101]='pbeWithSHAAnd128BitRC4'
  [2a864886f70d010c0102]='pbeWithSHAAnd40BitRC4'
  [2a864886f70d010c0103]='pbeWithSHAAnd3-KeyTripleDES-CBC'
  [2a864886f70d010c0104]='pbeWithSHAAnd2-KeyTripleDES-CBC'
  [2a864886f70d010c0105]='pbeWithSHAAnd128BitRC2-CBC'
  [2a864886f70d010c0106]='pbewithSHAAnd40BitRC2-CBC'
  [2b06010401d679020402]='embeddedSCTList'
  [2b06010401d679020403]='ctPoison'
  [2b06010401d679020404]='ctPrecertificateSigning'
  [2b06010401d679020405]='ocspSCTList'
  [2a864886f70d010501]='pbeWithMD2AndDES-CBC'
  [2a864886f70d010503]='pbeWithMD5AndDES-CBC'
  [2a864886f70d010504]='pbeWithMD2AndRC2-CBC'
  [2a864886f70d010506]='pbeWithMD5AndRC2-CBC'
  [2a864886f70d01050a]='pbeWithSHA1AndDES-CBC'
  [2a864886f70d01050b]='pbeWithSHA1AndRC2-CBC'
  [2a864886f70d01050c]='PBKDF2'
  [2a864886f70d01050d]='PBES2'
  [2a864886f70d01050e]='PBMAC1'
  [2a864886f70d0207]='hmacWithSHA1'
  [2a864886f70d0208]='hmacWithSHA224'
  [2a864886f70d0209]='hmacWithSHA256'
  [2a864886f70d020a]='hmacWithSHA384'
  [2a864886f70d020b]='hmacWithSHA512'
  [2a864886f70d0302]='RC2-CBC'
  [2a864886f70d0307]='DES-EDE3-CBC'
  [2a864886f70d0309]='RC5-CBC-Pad'
  [608648016503040102]='AES-128-CBC'
  [608648016503040116]='AES-192-CBC'
  [60864801650304012a]='AES-256-CBC'
)

# Printable ASCII characters indexed by byte value.
declare -a CHR
for ((i = 32; i < 127; i++)); do
	printf -v h '%02x' "$i"
	printf -v "CHR[$i]" '%b' "\\x$h"
done

# Bash substring access is O(length), so input bytes live in an array.
declare -a B # input bytes as decimal values
NB=0         # number of input bytes
# The input is also kept as "hh " triples in chunks of HCH bytes, so ranges can
# be extracted and classified with string operations instead of per-byte loops.
declare -a HXC
HCH=1024
HACC=""
declare -a OUTL # output lines
NO=0            # number of output lines
S=""            # string return register
X=""            # spaced hex return register
Q=""            # string builder for quoted output
declare -a PAD  # indentation strings by depth
declare -A TAGS # tag_to_string cache
declare -A OIDS # oid_to_string cache keyed by hex

# ---------------------------------------------------------------------------
# Input handling

# printf arguments that convert the characters (ORDARGS) or hex digit pairs
# (HEXARGS) of $piece to numbers in one call. All entries have the same width,
# so a prefix covers the first N characters or pairs.
printf -v ORDARGS '"'"'"'${piece:%5d:1}" ' {0..1023}
printf -v HEXARGS '0x${piece:%5d:2} ' {0..2046..2}
ORDW=$((${#ORDARGS} / 1024))
HEXW=$((${#HEXARGS} / 1024))

# add_bytes DECIMALS...: appends bytes to B and HXC.
add_bytes() {
	local h
	(($#)) || return 0
	B+=("$@")
	((NB += $#))
	printf -v h '%02x ' "$@"
	HACC+=$h
	while ((${#HACC} >= 3 * HCH)); do
		HXC+=("${HACC:0:3*HCH}")
		HACC=${HACC:3*HCH}
	done
}

# Reads stdin as binary into B. With -d '' a NUL ends a read early, so a short
# successful read means a NUL byte was consumed.
read_binary() {
	local piece m v st
	while :; do
		if IFS= read -r -d '' -n 1024 piece; then st=0; else st=1; fi
		m=${#piece}
		v=""
		((m)) && eval "printf -v v '%d ' ${ORDARGS:0:m*ORDW}"
		((st == 0 && m < 1024)) && v+=0
		add_bytes $v
		((st)) && break
	done
	HXC+=("$HACC")
}

# Reads stdin as hex into B, ignoring whitespace and punctuation.
read_hex() {
	local text piece o v
	IFS= read -r -d '' text || true
	text=${text//[[:space:][:punct:]]/}
	[[ $text =~ ^([0-9a-fA-F][0-9a-fA-F])*$ ]] || die "invalid hex input"
	for ((o = 0; o < ${#text}; o += 2048)); do
		piece=${text:o:2048}
		eval "printf -v v '%d ' ${HEXARGS:0:${#piece}/2*HEXW}"
		add_bytes $v
	done
	HXC+=("$HACC")
}

B64=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/
declare -A B64V
for ((i = 0; i < 64; i++)); do B64V[${B64:i:1}]=$i; done

# Decodes the first PEM block of stdin into B.
read_pem() {
	local line state=0 b64="" blk piece o j k n v rest=""
	local -a out
	while IFS= read -r line || [[ -n $line ]]; do
		line=${line%$'\r'}
		if ((state == 0)); then
			[[ $line == -----BEGIN\ *----- ]] && state=1
		elif [[ $line == -----END\ *----- ]]; then
			state=2
			break
		elif [[ $line != *:* ]]; then
			b64+=$line
		fi
	done
	((state == 2)) || die "no PEM block found"
	b64=${b64//[[:space:]]/}
	b64=${b64%%+(=)}
	[[ $b64 =~ ^[A-Za-z0-9+/]*$ ]] || die "invalid base64 in PEM block"
	n=${#b64}
	((n % 4 != 1)) || die "invalid base64 length in PEM block"
	for ((o = 0; o < n; o += 65536)); do
		blk=${b64:o:65536}
		for ((j = 0; j < ${#blk}; j += 512)); do
			piece=${blk:j:512}
			out=()
			for ((k = 0; k + 4 <= ${#piece}; k += 4)); do
				v=$((B64V[${piece:k:1}] << 18 | B64V[${piece:k+1:1}] << 12 |
					B64V[${piece:k+2:1}] << 6 | B64V[${piece:k+3:1}]))
				out+=($((v >> 16)) $((v >> 8 & 255)) $((v & 255)))
			done
			((${#out[@]} == 0)) || add_bytes "${out[@]}"
			rest=${piece:k}
		done
	done
	if ((${#rest} == 2)); then
		add_bytes $((B64V[${rest:0:1}] << 2 | B64V[${rest:1:1}] >> 4))
	elif ((${#rest} == 3)); then
		v=$((B64V[${rest:0:1}] << 10 | B64V[${rest:1:1}] << 4 | B64V[${rest:2:1}] >> 2))
		add_bytes $((v >> 8)) $((v & 255))
	fi
	HXC+=("$HACC")
}

# ---------------------------------------------------------------------------
# BER parsing. Positions are indices into B.

# spaced_range START END -> X ("hh hh ... ")
spaced_range() {
	local c=$(($1 / HCH)) o=$(($1 % HCH * 3)) n=$((($2 - $1) * 3)) piece
	X=""
	while ((n > 0)); do
		piece=${HXC[c++]:o:n}
		X+=$piece
		((n -= ${#piece}, o = 0))
	done
}

# hex_range START END -> S
hex_range() {
	spaced_range "$1" "$2"
	S=${X// /}
}

# parse_tag POS END -> T_CLASS T_NUM T_CONS T_LFO T_NEXT
parse_tag() {
	local p=$1 end=$2 b n=0 minimal=1
	((p < end)) || return 1
	b=${B[p++]}
	T_CLASS=$((b & 0xc0))
	T_CONS=$(((b & 0x20) != 0))
	T_NUM=$((b & 0x1f))
	T_LFO=0
	if ((T_NUM < 31)); then
		T_NEXT=$p
		return 0
	fi
	# Tolerate non-minimal (leading 0x80) high tag numbers.
	while ((p < end && B[p] == 0x80)); do
		minimal=0
		((p++))
	done
	((p < end)) || return 1
	while :; do
		((p < end)) || return 1
		b=${B[p++]}
		n=$(((n << 7) | (b & 0x7f)))
		((n <= 0xffffffff)) || return 1
		((b & 0x80)) || break
	done
	if ((!minimal || n < 31)); then T_LFO=$((p - $1 - 1)); fi
	T_NUM=$n
	T_NEXT=$p
}

# parse_element POS END -> E_CLASS E_NUM E_CONS E_TLFO E_INDEF E_LLFO E_BS E_BE E_NEXT
# An EOC parses as a primitive universal 0 element; callers must check for it.
parse_element() {
	local p=$1 end=$2 b n i len=0
	((p < end)) || return 1
	b=${B[p]}
	if (((b & 0x1f) != 0x1f)); then
		((E_CLASS = b & 0xc0, E_CONS = (b & 0x20) != 0, E_NUM = b & 0x1f, E_TLFO = 0, p++))
	else
		parse_tag "$p" "$end" || return 1
		E_CLASS=$T_CLASS E_NUM=$T_NUM E_CONS=$T_CONS E_TLFO=$T_LFO p=$T_NEXT
	fi
	((p < end)) || return 1
	b=${B[p++]}
	E_INDEF=0 E_LLFO=0
	if ((b < 0x80)); then
		len=$b
	elif ((b == 0x80)); then
		((E_CONS)) || return 1
		((E_INDEF = 1, E_BS = E_BE = E_NEXT = p))
		return 0
	else
		n=$((b & 0x7f))
		((n <= end - p)) || return 1
		for ((i = 0; i < n; i++)); do
			((len < 1 << 23)) || return 1
			len=$(((len << 8) | B[p + i]))
		done
		((B[p] == 0 || len < 0x80)) && E_LLFO=$n
		((p += n))
	fi
	((len <= end - p)) || return 1
	((E_BS = p, E_BE = E_NEXT = p + len))
}

# starts_with_eoc POS END
starts_with_eoc() {
	(($1 + 2 <= $2 && B[$1] == 0 && B[$1 + 1] == 0))
}

# is_made_of_elements START END: true if the range is a series of BER elements.
is_made_of_elements() {
	local p=$1 end=$2 indef=0
	while ((p < end)); do
		if starts_with_eoc "$p" "$end"; then
			((indef > 0)) || return 1
			((p += 2, indef--))
			continue
		fi
		parse_element "$p" "$end" || return 1
		p=$E_NEXT
		((E_INDEF)) && ((indef++))
	done
	((indef == 0))
}

# ---------------------------------------------------------------------------
# Formatting

# add_line INDENT TEXT
add_line() {
	[[ -n ${PAD[$1]+x} ]] || printf -v "PAD[$1]" '%*s' $(($1 * 2)) ''
	OUTL[NO++]=${PAD[$1]}$2
}

# set_line INDEX INDENT TEXT
set_line() {
	OUTL[$1]=${PAD[$2]}$3
}

# tag_to_string CLASS NUM CONS LFO -> S
tag_to_string() {
	S=${TAGS[$1,$2,$3,$4]-}
	[[ -n $S ]] && return
	make_tag_string "$@"
	TAGS[$1,$2,$3,$4]=$S
}

make_tag_string() {
	local class=$1 num=$2 cons=$3 lfo=$4 name="" inc=0 ok=0
	if ((class == 0)) && [[ -n ${UNAME[num]-} ]]; then
		ok=1
		name=${UNAME[num]}
		((UCONS[num] != cons)) && inc=1
		if ((lfo == 0 && inc == 0)); then
			S=$name
			return
		fi
	fi
	if ((!ok)); then
		case $class in
		0) name="UNIVERSAL $num" ;;
		64) name="APPLICATION $num" ;;
		128) name=$num ;;
		*) name="PRIVATE $num" ;;
		esac
		inc=$((!cons))
	fi
	S="["
	((lfo)) && S+="long-form:$lfo "
	S+=$name
	if ((inc)); then
		if ((cons)); then S+=" CONSTRUCTED"; else S+=" PRIMITIVE"; fi
	fi
	S+="]"
}

# bytes_to_string START END -> S (quoted string if mostly printable, else hex)
bytes_to_string() {
	local n=$(($2 - $1)) t
	if ((n == 0)); then
		S=""
		return
	fi
	spaced_range "$1" "$2"
	# Delete the printable bytes and count what is left.
	t=${X//[2-6]? /}
	t=${t//7[0-9a-e] /}
	t=${t//0a /}
	if (((n - ${#t} / 3) * 20 > n * 17)); then
		bytes_to_quoted "$1" "$2"
	else
		S="\`${X// /}\`"
	fi
}

# bytes_to_quoted START END -> S. X must hold spaced_range START END.
bytes_to_quoted() {
	local i b q='"' f t
	local -a hx
	# Fast path: printable bytes other than '"' and '\' need no escaping.
	t=${X//[346]? /}
	t=${t//2[013-9a-f] /}
	t=${t//5[0-9abd-f] /}
	t=${t//7[0-9a-e] /}
	if [[ -z $t ]]; then
		hx=($X)
		printf -v f '\\x%s' "${hx[@]}"
		printf -v S '"%b"' "$f"
		return
	fi
	for ((i = $1; i < $2; i++)); do
		b=${B[i]}
		if ((b == 10)); then
			q+='\n'
		elif ((b == 34)); then
			q+='\"'
		elif ((b == 92)); then
			q+='\\'
		elif ((b >= 32 && b < 127)); then
			q+=${CHR[b]}
		else
			printf -v f '\\x%02x' "$b"
			q+=$f
		fi
	done
	S=$q'"'
}

# Approximates Go's unicode.IsPrint. Unassigned code points in otherwise
# populated blocks are treated as printable.
is_print() {
	local r=$1
	((r >= 0x20 && r < 0x7f)) && return 0
	((r < 0xa1 || r > 0x10ffff)) && return 1
	((r == 0xad || r == 0x61c || r == 0x6dd || r == 0x70f || r == 0x8e2 || r == 0x1680 ||
		r == 0x180e || r == 0x205f || r == 0x3000 || r == 0xfeff || r == 0x110bd ||
		r == 0x110cd || r == 0xe0001)) && return 1
	(((r >= 0x600 && r <= 0x605) || (r >= 0x890 && r <= 0x891) ||
		(r >= 0x2000 && r <= 0x200f) || (r >= 0x2028 && r <= 0x202f) ||
		(r >= 0x2060 && r <= 0x206f) || (r >= 0xd800 && r <= 0xf8ff) ||
		(r >= 0xfdd0 && r <= 0xfdef) || (r >= 0xfff0 && r <= 0xfffb) ||
		(r & 0xfffe) == 0xfffe || (r >= 0x13430 && r <= 0x1343f) ||
		(r >= 0x1bca0 && r <= 0x1bca3) || (r >= 0x1d173 && r <= 0x1d17a) ||
		(r >= 0x40000 && r < 0xe0100) || r > 0xe01ef)) && return 1
	return 0
}

# Appends the UTF-8 encoding of code point $1 to Q.
put_rune() {
	local r=$1 f
	if ((r < 0x80)); then
		printf -v f '\\x%02x' "$r"
	elif ((r < 0x800)); then
		printf -v f '\\x%02x\\x%02x' $((0xc0 | r >> 6)) $((0x80 | (r & 0x3f)))
	elif ((r < 0x10000)); then
		printf -v f '\\x%02x\\x%02x\\x%02x' $((0xe0 | r >> 12)) $((0x80 | (r >> 6 & 0x3f))) \
			$((0x80 | (r & 0x3f)))
	else
		printf -v f '\\x%02x\\x%02x\\x%02x\\x%02x' $((0xf0 | r >> 18)) $((0x80 | (r >> 12 & 0x3f))) \
			$((0x80 | (r >> 6 & 0x3f))) $((0x80 | (r & 0x3f)))
	fi
	printf -v f '%b' "$f"
	Q+=$f
}

# Appends code point $1 to Q inside a u"" or U"" literal, escaping as needed.
put_code_point() {
	local u=$1 f
	if ((u == 10)); then
		Q+='\n'
	elif ((u == 34)); then
		Q+='\"'
	elif ((u == 92)); then
		Q+='\\'
	elif ((u <= 0x10ffff && (u < 0xd800 || u > 0xdfff))) && is_print "$u"; then
		put_rune "$u"
	elif ((u <= 0xff)); then
		printf -v f '\\x%02x' "$u"
		Q+=$f
	elif ((u <= 0xffff)); then
		printf -v f '\\u%04x' "$u"
		Q+=$f
	else
		printf -v f '\\U%08x' "$u"
		Q+=$f
	fi
}

# bmp_to_string START END -> S
bmp_to_string() {
	local s=$1 e=$2 n=$((($2 - $1) / 2)) i u u2 r f
	Q='u"'
	for ((i = 0; i < n; i++)); do
		u=$((B[s + 2 * i] << 8 | B[s + 2 * i + 1]))
		if ((u >= 0xd800 && u < 0xdc00 && i + 1 < n)); then
			u2=$((B[s + 2 * i + 2] << 8 | B[s + 2 * i + 3]))
			if ((u2 >= 0xdc00 && u2 <= 0xdfff)); then
				r=$(((((u - 0xd800) << 10) | (u2 - 0xdc00)) + 0x10000))
				if is_print "$r"; then
					put_rune "$r"
				else
					printf -v f '\\U%08x' "$r"
					Q+=$f
				fi
				((i++))
				continue
			fi
		fi
		put_code_point "$u"
	done
	Q+='"'
	if (((e - s) & 1)); then
		printf -v f ' `%02x`' "${B[e - 1]}"
		Q+=$f
	fi
	S=$Q
}

# universal_to_string START END -> S
universal_to_string() {
	local s=$1 e=$2 n=$((($2 - $1) / 4)) i p
	Q='U"'
	for ((i = 0; i < n; i++)); do
		p=$((s + 4 * i))
		put_code_point $((B[p] << 24 | B[p + 1] << 16 | B[p + 2] << 8 | B[p + 3]))
	done
	Q+='"'
	if (((e - s) & 3)); then
		hex_range $((s + 4 * n)) "$e"
		Q+=" \`$S\`"
	fi
	S=$Q
}

# integer_to_string START END -> S
integer_to_string() {
	local s=$1 e=$2 v i
	if ((e > s)) && ! ((e - s > 1 && (B[s] == 0 || B[s] == 0xff) && (B[s] & 0x80) == (B[s + 1] & 0x80))); then
		v=${B[s]}
		((v & 0x80)) && ((v -= 256))
		for ((i = s + 1; i < e; i++)); do
			(((v << 8) >> 8 == v)) || break
			v=$(((v << 8) | B[i]))
		done
		if ((i == e && v >= -100000 && v <= 100000)); then
			S=$v
			return
		fi
	fi
	hex_range "$s" "$e"
	S="\`$S\`"
}

# decode_base128_list START END -> COMP (uint64 values stored as bash ints)
decode_base128_list() {
	local p=$1 e=$2 b v
	COMP=()
	while ((p < e)); do
		((B[p] == 0x80)) && return 1
		v=0
		while :; do
			((p < e)) || return 1
			(((v >> 57) & 0x7f)) && return 1
			b=${B[p++]}
			v=$(((v << 7) | (b & 0x7f)))
			((b & 0x80)) || break
		done
		COMP+=("$v")
	done
}

# oid_to_string START END -> S
oid_to_string() {
	local s=$1 e=$2 first c u
	if ! decode_base128_list "$s" "$e" || ((${#COMP[@]} == 0)); then
		hex_range "$s" "$e"
		S="\`$S\`"
		return
	fi
	first=${COMP[0]}
	if ((first < 0 || first >= 80)); then
		printf -v S '2.%u' $((first - 80))
	elif ((first >= 40)); then
		S="1.$((first - 40))"
	else
		S="0.$first"
	fi
	for c in "${COMP[@]:1}"; do
		printf -v u '%u' "$c"
		S+=".$u"
	done
}

# relative_oid_to_string START END -> S
relative_oid_to_string() {
	local s=$1 e=$2 c u
	if ! decode_base128_list "$s" "$e" || ((${#COMP[@]} == 0)); then
		hex_range "$s" "$e"
		S="\`$S\`"
		return
	fi
	S=""
	for c in "${COMP[@]}"; do
		printf -v u '%u' "$c"
		S+=".$u"
	done
}

# bit_string_literal START END -> S (b`...` form; body must be 2..5 bytes, first < 8)
bit_string_literal() {
	local s=$1 e=$2 sig=$((8 - B[$1])) i j o last bits=""
	for ((i = s + 1; i < e; i++)); do
		o=${B[i]}
		last=$((i == e - 1))
		for ((j = 0; j < 8; j++)); do
			if ((last && sig == j)); then
				((o == 0)) && break
				bits+='|'
			fi
			if ((o & 0x80)); then bits+=1; else bits+=0; fi
			o=$(((o << 1) & 0xff))
		done
	done
	S="b\`$bits\`"
}

# der_to_ascii START END INDENT STOP_AT_EOC: appends to OUTL, sets R_POS to the
# unconsumed position (END unless stopped at an EOC).
der_to_ascii() {
	local p=$1 end=$2 ind=$3 stop=$4
	local class num cons tlfo indef llfo bs be tag header slot name b0 n first key
	while ((p < end)); do
		if ((stop)) && starts_with_eoc "$p" "$end"; then
			R_POS=$p
			return
		fi
		if ! parse_element "$p" "$end"; then
			bytes_to_string "$p" "$end"
			add_line "$ind" "$S"
			R_POS=$end
			return
		fi
		class=$E_CLASS num=$E_NUM cons=$E_CONS tlfo=$E_TLFO \
			indef=$E_INDEF llfo=$E_LLFO bs=$E_BS be=$E_BE p=$E_NEXT
		tag_to_string "$class" "$num" "$cons" "$tlfo"
		tag=$S

		if ((indef)); then
			# The header depends on whether an EOC follows the body, so
			# reserve its line and fill it in afterwards.
			slot=$NO
			add_line "$ind" ""
			der_to_ascii "$p" "$end" $((ind + 1)) 1
			p=$R_POS
			if starts_with_eoc "$p" "$end"; then
				set_line "$slot" "$ind" "$tag indefinite {"
				add_line "$ind" "}"
				((p += 2))
			else
				set_line "$slot" "$ind" "$tag \`80\`"
			fi
			continue
		fi

		if ((llfo)); then header="$tag long-form:$llfo {"; else header="$tag {"; fi
		n=$((be - bs))
		if ((n == 0)); then
			add_line "$ind" "$header}"
			continue
		fi

		if ((cons)); then
			add_line "$ind" "$header"
			der_to_ascii "$bs" "$be" $((ind + 1)) 0
			add_line "$ind" "}"
			continue
		fi

		name=""
		((class == 0)) && name=${UNAME[num]-}
		case $name in
		INTEGER)
			integer_to_string "$bs" "$be"
			add_line "$ind" "$header $S }"
			;;
		OBJECT_IDENTIFIER)
			hex_range "$bs" "$be"
			key=$S
			S=${OIDNAME[$key]-}
			[[ -n $S ]] && add_line "$ind" "# $S"
			S=${OIDS[$key]-}
			if [[ -z $S ]]; then
				oid_to_string "$bs" "$be"
				OIDS[$key]=$S
			fi
			add_line "$ind" "$header $S }"
			;;
		RELATIVE_OID)
			relative_oid_to_string "$bs" "$be"
			add_line "$ind" "$header $S }"
			;;
		BOOLEAN)
			if ((n == 1 && B[bs] == 0)); then
				S=FALSE
			elif ((n == 1 && B[bs] == 0xff)); then
				S=TRUE
			else
				hex_range "$bs" "$be"
				S="\`$S\`"
			fi
			add_line "$ind" "$header $S }"
			;;
		BIT_STRING)
			b0=${B[bs]}
			if ((n > 1 && b0 == 0)) && is_made_of_elements $((bs + 1)) "$be"; then
				add_line "$ind" "$header"
				add_line $((ind + 1)) '`00`'
				der_to_ascii $((bs + 1)) "$be" $((ind + 1)) 0
				add_line "$ind" "}"
			elif ((n == 1 && b0 == 0)); then
				add_line "$ind" "$header b\`\` }"
			elif ((n > 1 && n <= 5 && b0 < 8)); then
				bit_string_literal "$bs" "$be"
				add_line "$ind" "$header $S }"
			elif ((n > 1 && b0 < 8)); then
				bytes_to_string "$bs" $((bs + 1))
				first=$S
				bytes_to_string $((bs + 1)) "$be"
				add_line "$ind" "$header $first $S }"
			else
				bytes_to_string "$bs" "$be"
				add_line "$ind" "$header $S }"
			fi
			;;
		BMPString)
			bmp_to_string "$bs" "$be"
			add_line "$ind" "$header $S }"
			;;
		UniversalString)
			universal_to_string "$bs" "$be"
			add_line "$ind" "$header $S }"
			;;
		*)
			if is_made_of_elements "$bs" "$be"; then
				add_line "$ind" "$header"
				der_to_ascii "$bs" "$be" $((ind + 1)) 0
				add_line "$ind" "}"
			else
				bytes_to_string "$bs" "$be"
				add_line "$ind" "$header $S }"
			fi
			;;
		esac
	done
	R_POS=$end
}

# ---------------------------------------------------------------------------

main() {
	local in="" out="" mode=binary
	while (($#)); do
		case $1 in
		-i) (($# >= 2)) || usage; in=$2; shift ;;
		-o) (($# >= 2)) || usage; out=$2; shift ;;
		-hex) mode=hex ;;
		-pem) mode=pem ;;
		*) usage ;;
		esac
		shift
	done
	if [[ -n $in ]]; then exec <"$in" || die "cannot open $in"; fi

	case $mode in
	binary) read_binary ;;
	hex) read_hex ;;
	pem) read_pem ;;
	esac

	der_to_ascii 0 "$NB" 0 0

	if [[ -n $out ]]; then exec >"$out" || die "cannot open $out"; fi
	((NO == 0)) || printf '%s\n' "${OUTL[@]}"
}

main "$@"
