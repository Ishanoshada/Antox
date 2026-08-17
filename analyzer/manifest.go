package analyzer

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"strings"
	"time"

	"antox/mcp"
)

// ManifestInfo is the parsed, analysis-relevant subset of AndroidManifest.xml.
type ManifestInfo struct {
	Package               string
	VersionName           string
	VersionCode           string
	CompileSdkVersion     string
	MinSdkVersion         string
	TargetSdkVersion      string
	Label                 string
	ApplicationName       string
	Debuggable            bool
	AllowBackup           bool
	UsesCleartextTraffic  bool
	NetworkSecurityConfig string
	FullBackupContent     string
	DataExtractionRules   string
	Permissions           []string
}

// rawManifest mirrors the JSON shape the plugin returns: the XML lives as a
// string under "content".
type rawManifest struct {
	Content string `json:"content"`
}

type manifestXML struct {
	XMLName         xml.Name `xml:"manifest"`
	Package         string   `xml:"package,attr"`
	VersionCode     string   `xml:"versionCode,attr"`
	VersionName     string   `xml:"versionName,attr"`
	CompileSdk      string   `xml:"compileSdkVersion,attr"`
	PlatformBuildVC string   `xml:"platformBuildVersionCode,attr"`
	UsesSDK         struct {
		MinSdkVersion    string `xml:"minSdkVersion,attr"`
		TargetSdkVersion string `xml:"targetSdkVersion,attr"`
	} `xml:"uses-sdk"`
	Application struct {
		Label                 string `xml:"label,attr"`
		Name                  string `xml:"name,attr"`
		Debuggable            string `xml:"debuggable,attr"`
		AllowBackup           string `xml:"allowBackup,attr"`
		Cleartext             string `xml:"usesCleartextTraffic,attr"`
		NetworkSecurityConfig string `xml:"networkSecurityConfig,attr"`
		FullBackupContent     string `xml:"fullBackupContent,attr"`
		DataExtractionRules   string `xml:"dataExtractionRules,attr"`
	} `xml:"application"`
	UsesPermissions []struct {
		Name string `xml:"name,attr"`
	} `xml:"uses-permission"`
	Permissions []struct {
		Name string `xml:"name,attr"`
	} `xml:"permission"`
}

// fetchManifest retrieves and parses the AndroidManifest.xml from jadx.
func fetchManifest(ctx context.Context, client *mcp.Client) (*ManifestInfo, string, error) {
	tr, err := client.CallTool(ctx, "get_android_manifest", map[string]any{})
	if err != nil {
		return nil, "", err
	}
	return parseManifestXML(toolRawJSON(tr))
}

// parseManifestXML handles both the plugin's {"content":"<xml>"} shape and a
// bare XML string.
func parseManifestXML(raw []byte) (*ManifestInfo, string, error) {
	var xmlText string
	var rm rawManifest
	if json.Unmarshal(raw, &rm) == nil && strings.TrimSpace(rm.Content) != "" {
		xmlText = rm.Content
	} else if strings.HasPrefix(strings.TrimSpace(string(raw)), "<") {
		xmlText = string(raw)
	} else {
		return nil, string(raw), fmt.Errorf("manifest not in a parseable shape")
	}

	var mx manifestXML
	if err := xml.Unmarshal([]byte(xmlText), &mx); err != nil {
		return nil, xmlText, fmt.Errorf("parse manifest XML: %w", err)
	}

	mi := &ManifestInfo{
		Package:               mx.Package,
		VersionName:           mx.VersionName,
		VersionCode:           mx.VersionCode,
		CompileSdkVersion:     mx.CompileSdk,
		MinSdkVersion:         mx.UsesSDK.MinSdkVersion,
		TargetSdkVersion:      mx.UsesSDK.TargetSdkVersion,
		Label:                 mx.Application.Label,
		ApplicationName:       mx.Application.Name,
		Debuggable:            mx.Application.Debuggable == "true",
		AllowBackup:           mx.Application.AllowBackup == "true",
		UsesCleartextTraffic:  mx.Application.Cleartext == "true",
		NetworkSecurityConfig: mx.Application.NetworkSecurityConfig,
		FullBackupContent:     mx.Application.FullBackupContent,
		DataExtractionRules:   mx.Application.DataExtractionRules,
	}
	for _, p := range mx.UsesPermissions {
		if p.Name != "" {
			mi.Permissions = append(mi.Permissions, p.Name)
		}
	}
	for _, p := range mx.Permissions {
		if p.Name != "" {
			mi.Permissions = append(mi.Permissions, p.Name)
		}
	}
	mi.Permissions = uniqueStrings(mi.Permissions)
	return mi, xmlText, nil
}

// AnalyzeManifest extracts app configuration from AndroidManifest.xml: package,
// versions, SDK levels, flags (debuggable, allowBackup, cleartext), exported
// components and requested permissions.
func (e *Engine) AnalyzeManifest(ctx context.Context, o Options) (*Report, error) {
	start := time.Now()
	r := &Report{Mode: o.Mode, AppName: "unknown"}

	mi, xmlText, err := fetchManifest(ctx, e.Client)
	if err != nil {
		e.Errs = append(e.Errs, fmt.Sprintf("get_android_manifest: %v", err))
		r.DurationMS = time.Since(start).Milliseconds()
		e.finishReport(ctx, r)
		return r, err
	}
	r.Manifest = xmlText
	r.APKPackage = mi.Package
	r.AppName = mi.Label
	if r.AppName == "" {
		r.AppName = mi.ApplicationName
	}

	infoFindings := []struct{ key, title, detail string }{
		{"package", "Application package", mi.Package},
		{"versionName", "Version name", mi.VersionName},
		{"versionCode", "Version code", mi.VersionCode},
		{"compileSdkVersion", "Compile SDK version", mi.CompileSdkVersion},
		{"minSdkVersion", "Min SDK version", mi.MinSdkVersion},
		{"targetSdkVersion", "Target SDK version", mi.TargetSdkVersion},
	}
	for _, f := range infoFindings {
		if f.detail != "" {
			r.Findings = append(r.Findings, Finding{
				Category: "manifest", Severity: "info",
				Title: f.title, Class: f.key, Detail: f.detail,
			})
		}
	}

	// Security-relevant flags (present = risk).
	if mi.Debuggable {
		r.Findings = append(r.Findings, Finding{
			Category: "manifest", Severity: "high",
			Title: "Debuggable application", Class: "application:debuggable",
			Detail: "debuggable is enabled — the app can be attached to by a debugger",
		})
	}
	if mi.AllowBackup {
		r.Findings = append(r.Findings, Finding{
			Category: "manifest", Severity: "medium",
			Title: "Backup allowed", Class: "application:allowBackup",
			Detail: "app data can be extracted via adb backup",
		})
	}
	if mi.UsesCleartextTraffic {
		r.Findings = append(r.Findings, Finding{
			Category: "manifest", Severity: "high",
			Title: "Cleartext traffic permitted", Class: "application:usesCleartextTraffic",
			Detail: "HTTP (non-TLS) traffic is allowed",
		})
	}
	for _, key := range []struct{ name, value, title string }{
		{"networkSecurityConfig", mi.NetworkSecurityConfig, "Network security config referenced"},
		{"fullBackupContent", mi.FullBackupContent, "Backup rules referenced"},
		{"dataExtractionRules", mi.DataExtractionRules, "Data extraction rules referenced"},
	} {
		if key.value != "" {
			r.Findings = append(r.Findings, Finding{
				Category: "manifest", Severity: "info",
				Title: key.title, Class: key.name, Detail: key.value,
			})
		}
	}

	if len(mi.Permissions) > 0 {
		r.Findings = append(r.Findings, Finding{
			Category: "manifest", Severity: "info",
			Title:  fmt.Sprintf("Permissions requested (%d)", len(mi.Permissions)),
			Class:  "uses-permission",
			Detail: strings.Join(mi.Permissions, ", "),
		})
	}

	// Main activity.
	if ma, err := e.Client.CallTool(ctx, "get_main_activity_class", map[string]any{}); err == nil {
		if txt := strings.TrimSpace(ma.Text()); txt != "" && txt != "{}" {
			r.Findings = append(r.Findings, Finding{
				Category: "manifest", Severity: "info",
				Title: "Main activity", Class: "MainActivity", Detail: txt,
			})
		}
	}

	// Exported components per type.
	for _, ctype := range []string{"activity", "service", "receiver", "provider"} {
		ctr, err := e.Client.CallTool(ctx, "get_manifest_component",
			map[string]any{"component_type": ctype, "only_exported": true})
		if err != nil {
			continue
		}
		comps := parseComponentNames(ctr)
		if len(comps) > 0 {
			r.Findings = append(r.Findings, Finding{
				Category: "manifest", Severity: "medium",
				Title:  fmt.Sprintf("Exported %s components (%d)", ctype, len(comps)),
				Class:  ctype,
				Detail: strings.Join(comps, ", "),
			})
		}
	}

	r.DurationMS = time.Since(start).Milliseconds()
	e.finishReport(ctx, r)
	return r, nil
}

// parseComponentNames extracts component names from a get_manifest_component
// result, which is a list of dicts each carrying a "name" key.
func parseComponentNames(tr *mcp.ToolResult) []string {
	var out []string
	var items []json.RawMessage
	raw := toolRawJSON(tr)
	if err := json.Unmarshal(raw, &items); err != nil || len(items) == 0 {
		var doc struct {
			Items []json.RawMessage `json:"items"`
		}
		if json.Unmarshal(raw, &doc) == nil {
			items = doc.Items
		}
	}
	for _, it := range items {
		var m map[string]any
		if json.Unmarshal(it, &m) == nil {
			for _, k := range []string{"name", "component", "class_name"} {
				if v, ok := m[k]; ok {
					if s, ok := v.(string); ok && s != "" {
						out = append(out, s)
						break
					}
				}
			}
		}
	}
	return uniqueStrings(out)
}
