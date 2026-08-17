package patterns

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

// Hex blob handling. Apps (and the cpp/ native layer in this repo) hide strings
// as hex: byte-array literals like `{0x77,0x6E,0xC4,...}`, hex string literals
// like "776EC45F...", or XOR-0x42-encoded tables. These helpers parse any of
// those forms, decode ASCII (and XOR 0x42), and tell us whether the decoded
// text is "interesting" (contains detection / credential keywords).

// HexDecodeKey is a transform applied to raw bytes to recover plaintext.
type HexDecodeKey struct {
	Name       string
	Key        byte // XOR key; 0 = no transform
	Bruteforce bool // part of the full 0x01-0xFF sweep (gated, see DecodeHexBlob)
}

// CommonXORKeys are the transforms tried on a hex blob, in order:
//  1. plain ASCII (key 0),
//  2. a curated set of single-byte XOR keys that appear in real Android
//     obfuscators (cpp/str_enc.h uses 0x42; 0x41/0x5a and the repeating-byte
//     keys 0x11..0xff are common in string-table encoders),
//  3. a full 0x01-0xFF bruteforce sweep, so any single-byte XOR obfuscation
//     is recovered even when the key is not a "common" one.
//
// DecodeHexBlob only keeps results that decode to a readable run (>= 4 ASCII
// chars), so the extra keys are cheap: on real encrypted tables exactly one
// key recovers the text, on random data almost no key yields a readable run.
var CommonXORKeys = func() []HexDecodeKey {
	curated := []HexDecodeKey{
		{Name: "ascii", Key: 0},
		// cpp/str_enc.h's key (0x42), plus its close neighbours.
		{Name: "xor-0x42", Key: 0x42},
		{Name: "xor-0x41", Key: 0x41},
		{Name: "xor-0x5a", Key: 0x5a},
		// Repeating-byte / magic keys seen in Android string obfuscators.
		{Name: "xor-0x11", Key: 0x11},
		{Name: "xor-0x22", Key: 0x22},
		{Name: "xor-0x33", Key: 0x33},
		{Name: "xor-0x44", Key: 0x44},
		{Name: "xor-0x55", Key: 0x55},
		{Name: "xor-0x66", Key: 0x66},
		{Name: "xor-0x77", Key: 0x77},
		{Name: "xor-0x88", Key: 0x88},
		{Name: "xor-0x99", Key: 0x99},
		{Name: "xor-0xaa", Key: 0xaa},
		{Name: "xor-0xbb", Key: 0xbb},
		{Name: "xor-0xcc", Key: 0xcc},
		{Name: "xor-0xdd", Key: 0xdd},
		{Name: "xor-0xee", Key: 0xee},
		{Name: "xor-0xff", Key: 0xff},
		{Name: "xor-0x0f", Key: 0x0f},
		{Name: "xor-0xf0", Key: 0xf0},
		{Name: "xor-0x7f", Key: 0x7f},
		{Name: "xor-0x80", Key: 0x80},
		{Name: "xor-0xfe", Key: 0xfe},
		{Name: "xor-0x6b", Key: 0x6b},
		{Name: "xor-0x5c", Key: 0x5c},
		{Name: "xor-0x23", Key: 0x23}, // '#' — string tables
		{Name: "xor-0x2e", Key: 0x2e}, // '.'
		{Name: "xor-0x20", Key: 0x20}, // space
		{Name: "xor-0x7e", Key: 0x7e}, // '~'
	}
	// Full bruteforce sweep: every key 0x01-0xFF not already named above.
	// Marked Bruteforce so DecodeHexBlob can gate it (short blobs only, longer
	// readable runs required) — running 255 decodes on long random blobs
	// (hashes, icons) mostly produces readable noise that false-positives the
	// keyword filter.
	out := curated
	have := map[byte]bool{}
	for _, c := range curated {
		have[c.Key] = true
	}
	for k := 1; k <= 0xff; k++ {
		if have[byte(k)] {
			continue
		}
		out = append(out, HexDecodeKey{
			Name:       fmt.Sprintf("xor-0x%02x", byte(k)),
			Key:        byte(k),
			Bruteforce: true,
		})
	}
	return out
}()

// HexResult is one interpretation of a hex blob.
type HexResult struct {
	KeyName  string
	Decoded  string
	Readable []string
	Keywords []string // interesting keywords found in the decoded text
	NonASCII int      // count of non-printable bytes (obfuscation signal)
}

// Interesting returns true if the decoded text contains any of the
// detection/credential keywords we care about.
func (hr *HexResult) Interesting() bool { return len(hr.Keywords) > 0 }

// HexInterestingKeywords are the keywords that make a decoded string worth
// surfacing. Drawn from the detection dictionary in cpp/ (str_enc.h tables,
// /proc scans, system properties, thread names) plus generic credential /
// security terms and the JNI / direct-syscall technique vocabulary.
var HexInterestingKeywords = []string{
	// hooking / RASP / frida
	"hook", "hooked", "hooking", "frida", "gum", "gum-js", "gum_js",
	"gum-js-loop", "gum_interceptor", "gum_init_embedded", "gadget",
	"libgadget", "frida-gadget", "frida-agent", "frida-helper",
	"frida-zymbiote", "frida_gadget_load", "frida_gadget_wait_for_debugger",
	"linjector", "substrate", "dobby", "shadowhook", "whale", "pine",
	"xposed", "lsposed", "edxposed", "zygisk", "zygisknext", "libzygisk",
	"lspd", "zymbiote", "memfd", "jit-cache", "rwxp",
	// root / magisk / apatch / hiding modules
	"root", "su_binary", "magisk", "magisk_daemon", "apatch", "shamiko",
	"hidemyapplist", "hideroot", "rootcloak", "busybox", "xbin", "sbin",
	"debug_ramdisk", "whitelist", "cannot run", "tampered", "tamper",
	// anti-debug / ptrace / syscall
	"ptrace", "tracer", "tracerpid", "tracepid", "PTRACE_TRACEME", "debug",
	"debugger", "waitfordebugger", "syscall", "getdents64", "readlinkat",
	"openat", "gdb",
	// /proc filesystem paths
	"proc", "cmdline", "comm", "mounts", "mountinfo", "maps", "status",
	"fd", "task", "net/tcp", "net/unix", "tcp6", "net", "unix", "socket",
	// selinux / system properties / build state
	"selinux", "enforce", "permissive", "ro.debuggable", "ro.secure",
	"ro.build.type", "ro.build.tags", "ro.boot.vbmeta", "ro.boot.verifiedbootstate",
	"init.svc.adbd", "test-keys", "userdebug", "eng", "bootloader",
	"verifiedbootstate", "vbmeta", "orange", "yellow",
	// adb
	"adb", "adbd", "adb_keys", "adb_port",
	// ssl / native hook of crypto
	"ssl", "ssl_write", "ssl_read", "conscrypt", "tmpfs", "cacerts",
	"libc", "dlopen", "dlsym", "dladdr", "rtld_default",
	// jni / native layer
	"native", "jni", "jnionload", "registernatives", "system.loadlibrary",
	"newglobalref", "getenv", "findclass", "getstaticmethodid", "getmethodid",
	// snitchtt / DeviceTrust / RASP SDK names
	"snitchtt", "snitch", "snitchative", "sna_e", "snb_e", "devicetrust",
	"devicetrustnative", "collectnativesignals", "talsec", "aheaditec",
	"rasp", "threatlistener", "onalert",
	// integrity / attestation / credentials
	"detect", "integrity", "attest", "verify", "verifySignatures",
	"checksum", "signature", "signinginfo", "codeintegrity",
	"key", "secret", "token", "password", "credential", "auth", "bearer",
	"api_key", "apikey", "client_secret", "access_token",
	"cert", "aes", "rsa", "encrypt", "decrypt", "cipher", "sign",
	// frida-server / gadget system artifacts
	"frida-server", "re.frida.server", "/tmp/frida-", "frida_agent_main",
	"gum_interceptor_replace", "gum_init", "27042", "27043", "27047",
	// anti-debug ptrace family
	"PTRACE_ATTACH", "PTRACE_DETACH", "wchan", "sys_ptrace", "fork",
	// Flutter / Dart AOT framework
	"libapp.so", "libflutter.so", "kernel_blob", "flutter_assets",
	"isolate_snapshot_data", "vm_snapshot_data", "Dart_Initialize", "dart:ui",
	// React Native / Hermes framework
	"libhermes.so", "libreactnativejni.so", "index.android.bundle", "hermes",
	"turbomodule", "jailmonkey",
	// Packers / commercial hardening wrappers
	"jiagu", "legu", "bangcle", "secshell", "dexshell", "baiduprotect",
	"tencent_stub", "dexprotector", "ijiami", "execmain", "stubapp",
	"proxyapplication",
}

var hexInterestingRe = buildAnyRegex(HexInterestingKeywords)

// ParseHexBytes converts any common hex representation into raw bytes.
// Accepts: "77 6E C4", "0x77, 0x6E, 0xC4", "776EC45F", "'77”6E'".
// Returns nil if the input cannot be parsed as hex.
func ParseHexBytes(input string) []byte {
	s := input
	// Strip 0x/0X prefixes.
	var b strings.Builder
	for i := 0; i < len(s); {
		c := s[i]
		if c == '0' && i+1 < len(s) && (s[i+1] == 'x' || s[i+1] == 'X') {
			i += 2
			continue
		}
		b.WriteByte(c)
		i++
	}
	s = b.String()
	// Remove separators: comma, space, tab, newline, quotes, brackets, dots.
	s = strings.NewReplacer(",", "", " ", "", "\t", "", "\r", "", "\n", "",
		`"`, "", "'", "", "{", "", "}", "", "(", "", ")", "", ".", "").Replace(s)
	if len(s) == 0 || len(s)%2 != 0 {
		return nil
	}
	out := make([]byte, 0, len(s)/2)
	for i := 0; i+1 < len(s); i += 2 {
		v, err := hex.DecodeString(strings.ToLower(s[i : i+2]))
		if err != nil {
			return nil
		}
		out = append(out, v[0])
	}
	return out
}

// decodeMaxBruteBytes is the blob-length ceiling for the full 0x01-0xFF
// bruteforce sweep. XOR-encoded string tables (str_enc.h) are short; on long
// blobs (hashes, icons) a random key almost always yields a readable run that
// would false-positive the keyword filter, so the sweep is skipped there.
const decodeMaxBruteBytes = 128

// decodeBruteMinRun is the minimum readable-run length a bruteforce-decoded
// blob must contain to be worth returning. A short 4-5 char run can be random
// noise; a real decoded table is a coherent string of 6+ chars.
const decodeBruteMinRun = 6

// DecodeHexBlob tries each transform over raw bytes and returns the results
// whose decoded text contains a readable run.
func DecodeHexBlob(raw []byte) []HexResult {
	if len(raw) < 2 {
		return nil
	}
	var out []HexResult
	for _, key := range CommonXORKeys {
		// Full-sweep keys are only worth trying on short encoded tables.
		if key.Bruteforce && len(raw) > decodeMaxBruteBytes {
			continue
		}
		dec := raw
		if key.Key != 0 {
			dec = make([]byte, len(raw))
			for i, c := range raw {
				dec[i] = c ^ key.Key
			}
		}
		readable := ExtractReadable(dec)
		if len(readable) == 0 {
			continue
		}
		// Bruteforce keys need a longer run to be meaningful.
		if key.Bruteforce && !hasLongRun(readable, decodeBruteMinRun) {
			continue
		}
		text := strings.Join(readable, " ")
		hr := HexResult{
			KeyName:  key.Name,
			Decoded:  text,
			Readable: readable,
			NonASCII: countNonPrintable(raw),
		}
		hr.Keywords = MatchKeywords(text)
		if len(text) > 0 {
			out = append(out, hr)
		}
	}
	return out
}

// ExtractReadable returns runs of printable ASCII (>=4 chars) from a blob.
func ExtractReadable(b []byte) []string {
	var out []string
	cur := make([]byte, 0, 16)
	flush := func() {
		if len(cur) >= 4 {
			out = append(out, string(cur))
		}
		cur = cur[:0]
	}
	for _, c := range b {
		if c >= 0x20 && c < 0x7f {
			cur = append(cur, c)
		} else {
			flush()
		}
	}
	flush()
	return out
}

// hasLongRun reports whether any readable run is at least minLen chars long.
func hasLongRun(readable []string, minLen int) bool {
	for _, s := range readable {
		if len(s) >= minLen {
			return true
		}
	}
	return false
}

// MatchKeywords returns the interesting keywords present in text.
func MatchKeywords(text string) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range hexInterestingRe.FindAllString(text, -1) {
		k := strings.ToLower(m)
		if !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	return out
}

// MatchSecrets returns the names of credential patterns (SecretPatterns)
// present in text. Used to flag decoded hex strings that carry real secrets
// (API keys, tokens, passwords, private keys).
func MatchSecrets(text string) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range SecretPatterns {
		if p.Regexp.MatchString(text) && !seen[p.Name] {
			seen[p.Name] = true
			out = append(out, p.Name)
		}
	}
	return out
}

func countNonPrintable(b []byte) int {
	n := 0
	for _, c := range b {
		if c < 0x20 || c >= 0x7f {
			n++
		}
	}
	return n
}

// ByteArrayRe matches a decimal/hex byte-array literal of >= 8 elements.
var ByteArrayRe = regexp.MustCompile(`\{[ \t]*(?:0[xX])?[0-9a-fA-F]{2}(?:[ \t]*,[ \t]*(?:0[xX])?[0-9a-fA-F]{2}){7,}[ \t]*\}`)

// HexStringRe matches a quoted continuous hex string of >= 16 chars.
var HexStringRe = regexp.MustCompile(`"[0-9a-fA-F]{16,}"`)

// HexBlobRe matches a free-form hex blob (e.g. pasted dumps) of >= 16 hex chars.
var HexBlobRe = regexp.MustCompile(`(?i)(?:0x[0-9a-fA-F]{2}[,\s]+){7,}0x[0-9a-fA-F]{2}`)
