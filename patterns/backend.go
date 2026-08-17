package patterns

import "regexp"

// Backend / infrastructure detection. Many hosts, API endpoints and Firebase
// config values live in compiled binary resources (resources.arsc) and the
// Dart AOT snapshot (libapp.so), so this dictionary is applied to raw resource
// file content as well as decompiled code.

// DomainRe matches a domain or hostname (also inside full URLs).
var DomainRe = regexp.MustCompile(`(?i)\b[a-z0-9][a-z0-9\-]*\.[a-z0-9][a-z0-9\-]*\.?[a-z0-9\-]*\.[a-z]{2,}\b|\b[a-z0-9\-]+\.[a-z]{2,}\b`)

// IPv4Re matches dotted-quad IPv4 addresses.
var IPv4Re = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)

// CleartextURLRe flags plain-http URLs (MITM exposure).
var CleartextURLRe = regexp.MustCompile(`(?i)\bhttp://[^\s"']+`)

// NamespaceURLRe matches schema / XML-namespace URIs that routinely appear in
// compiled resources and manifest references but are NOT network traffic
// (ns.adobe.com/xap, www.w3.org, schemas.android.com, ...).
var NamespaceURLRe = regexp.MustCompile(`(?i)\bhttp://(?:ns\.)?(?:adobe\.com|w3\.org|schemas\.android\.com|apache\.org|xmlpull\.org|purl\.org|openxmlformats\.org|opensearch\.org|oasis-open\.org|xml\.apache\.org)/`)

// CleartextURLs returns the real cleartext http:// URLs in text, excluding
// schema/namespace URIs that would otherwise produce false positives.
func CleartextURLs(text string) []string {
	var out []string
	for _, u := range CleartextURLRe.FindAllString(text, -1) {
		if !NamespaceURLRe.MatchString(u) {
			out = append(out, u)
		}
	}
	return uniqueStringsB(out)
}

// uniqueStringsB dedupes a slice while preserving first-occurrence order.
func uniqueStringsB(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// FirebaseDomainRe matches Google/Firebase-hosted domains. Backend host
// findings only surface Firebase domains (plus any domain that already appears
// inside a cleartext/leaking URL) — the tool does not curate any other
// predefined domain list.
var FirebaseDomainRe = regexp.MustCompile(`(?i)\b(?:[a-z0-9\-]+\.)?(?:firebasestorage\.app|firebasedatabase\.app|firebaseapp\.com|firebaseio\.com|firebase\.google\.com)\b`)

// HTTPSURLRe flags https URLs.
var HTTPSURLRe = regexp.MustCompile(`(?i)\bhttps://[^\s"']+`)

// ServicePrefixRe matches the microservice base paths of this app family.
var ServicePrefixRe = regexp.MustCompile(`(?i)/(?:user|fare|ticketing|pass|wallet)-service(?:/api/v\d+)?`)

// EndpointRe matches API path segments that look like real endpoints:
// a leading slash followed by path segments (letters, digits, / _ - { }).
var EndpointRe = regexp.MustCompile(`(?i)(?:/api/v\d+)?/[a-z0-9][a-z0-9/\-_{}]{2,60}`)

// FirebaseKeyRe matches Google/Firebase web API keys.
var FirebaseKeyRe = regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}\b`)

// FirebaseAppIDRe matches the "project:android:..." app id.
var FirebaseAppIDRe = regexp.MustCompile(`\b1:[0-9]{5,15}:android:[0-9a-f]{8,40}\b`)

// FirebaseSenderRe matches the GCM sender id / project number.
var FirebaseSenderRe = regexp.MustCompile(`\b1:[0-9]{5,15}:(?:android|ios)`)

// StorageBucketRe matches a firebasestorage.app bucket.
var StorageBucketRe = regexp.MustCompile(`(?i)\b[a-z0-9\-]+\.firebasestorage\.app\b`)

// FirebaseConfigRegexes scan text / resources for Firebase configuration values.
var FirebaseConfigRegexes = []*regexp.Regexp{
	FirebaseKeyRe,
	FirebaseAppIDRe,
	FirebaseSenderRe,
	StorageBucketRe,
	mustRe(`firebase_database_url["']?\s*[:=]\s*["']?https?://[^\s"']+`),
	mustRe(`project_id["']?\s*[:=]\s*["']?[a-z0-9\-]+`),
}

// BackendCodeRegexes scan decompiled Java for hosts, IPs and API paths.
var BackendCodeRegexes = []*regexp.Regexp{
	DomainRe,
	IPv4Re,
	CleartextURLRe,
	ServicePrefixRe,
	EndpointRe,
}

// BackendResourceNames are the packaged files whose raw content is worth
// scanning for backend / Firebase data.
var BackendResourceNames = []string{
	"network_security_config.xml",
	"google-services.json",
	"resources.arsc",
	"libapp.so",
	"classes.dex",
	"certs.ts",
}
