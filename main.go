// Command antox is an Android APK static-analysis tool that drives the
// jadx MCP server (jadx-mcp-server, streamable HTTP at /mcp) directly over
// JSON-RPC — no AI tool wrapper. It has one analysis mode per extraction
// category (manifest, secrets, firebase, security, detection, native, hexenc,
// search, all) plus an interactive shell.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"antox/analyzer"
	"antox/mcp"
)

const defaultMCP = "http://127.0.0.1:8651/mcp"

var banner = `    
_____     ____ _/  |_  ____ ___  ___ 
\__  \   /    \\   __\/  _ \\  \/  / 
 / __ \_|   |  \|  | (  <_> )>    <  
(____  /|___|  /|__|  \____//__/\_ \ 
     \/      \/                   \/ 
                                     
  Android APK static analysis via jadx MCP server
`

type config struct {
	mcpURL      string
	out         string
	format      string
	term        string
	scope       string
	apkDir      string
	packageName string
	subModes    string
	limit       int
	workers     int
	timeout     int
	debug       bool
	quiet       bool
	noColor     bool
	noSave      bool
}

func main() {
	cfg := config{}
	fs := flag.NewFlagSet("antox", flag.ContinueOnError)
	fs.StringVar(&cfg.mcpURL, "mcp", defaultMCP, "jadx MCP server endpoint (streamable HTTP)")
	fs.StringVar(&cfg.out, "out", "reports", "output directory (or a file path ending in .md/.json)")
	fs.StringVar(&cfg.format, "format", "both", "report format: md, json, both")
	fs.StringVar(&cfg.term, "term", "", "custom search term (search mode)")
	fs.StringVar(&cfg.scope, "scope", "code", "search scope: class,method,field,code,resource,comments (comma-sep); resource surfaces .so/.dex files")
	fs.StringVar(&cfg.packageName, "package", "", "restrict searches to a package")
	fs.StringVar(&cfg.apkDir, "apk", "", "unzipped APK dir(s), comma-separated (raw binary scan: resources.arsc, libapp.so, network_security_config.xml, .so string sweep)")
	fs.IntVar(&cfg.limit, "limit", 8, "max class sources fetched per category")
	fs.IntVar(&cfg.workers, "workers", 8, "concurrent class-source fetches (threading)")
	fs.IntVar(&cfg.timeout, "timeout", 900, "per-request timeout in seconds")
	fs.BoolVar(&cfg.debug, "debug", false, "print raw MCP search results")
	fs.BoolVar(&cfg.quiet, "quiet", false, "suppress progress output")
	fs.BoolVar(&cfg.noColor, "no-color", false, "disable ANSI colors")
	fs.BoolVar(&cfg.noSave, "no-save", false, "do not write report files")

	fs.Usage = func() { printUsage(fs) }

	// Allow both "antox <mode> [flags]" and flags-before-mode.
	if err := fs.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}
	mode := ""
	if fs.NArg() > 0 {
		mode = fs.Arg(0)
	}
	if fs.NArg() > 1 {
		// The token right after the mode may be a comma-separated extra-mode
		// list ("antox sostr detection,secrets -apk ..."); everything
		// after it is re-parsed as flags that the first Parse stopped at.
		rest := fs.Args()[1:]
		if !strings.HasPrefix(rest[0], "-") {
			cfg.subModes = rest[0]
			rest = rest[1:]
		}
		if err := fs.Parse(rest); err != nil {
			os.Exit(2)
		}
	}
	mode = strings.ToLower(strings.TrimSpace(mode))
	if cfg.subModes != "" {
		for _, m := range strings.Split(cfg.subModes, ",") {
			m = strings.ToLower(strings.TrimSpace(m))
			if m != "" && !isMode(m) {
				fmt.Fprintf(os.Stderr, "error: unknown mode %q in mode list\n", m)
				os.Exit(2)
			}
		}
	}

	if mode == "" || mode == "help" || mode == "modes" || mode == "--help" || mode == "-h" {
		printUsage(fs)
		return
	}
	if mode == "version" || mode == "--version" || mode == "-v" {
		fmt.Println("antox v1.0.0")
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	client := mcp.New(cfg.mcpURL)
	client.SetTimeout(time.Duration(cfg.timeout) * time.Second)

	switch mode {
	case "ping":
		if err := runPing(ctx, client); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		return
	case "list-tools":
		if err := runListTools(ctx, client); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		return
	case "shell":
		runShell(ctx, client, cfg)
		return
	}

	eng := analyzer.NewEngine(client, cfg.limit, cfg.debug)
	eng.Quiet = cfg.quiet
	eng.NoColor = cfg.noColor
	if cfg.workers > 0 {
		eng.Workers = cfg.workers
	}
	o := analyzer.Options{
		Mode:    mode,
		Term:    cfg.term,
		Scope:   cfg.scope,
		Package: cfg.packageName,
		Limit:   cfg.limit,
		Debug:   cfg.debug,
		ApkDir:  cfg.apkDir,
		OutDir:  cfg.out,
	}
	if _, err := execute(ctx, eng, o, cfg); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// splitSubModes expands a comma-separated mode list into a slice. The caller
// has already validated each token via isMode.
func splitSubModes(s string) []string {
	var out []string
	for _, m := range strings.Split(s, ",") {
		m = strings.ToLower(strings.TrimSpace(m))
		if m != "" {
			out = append(out, m)
		}
	}
	return out
}

// execute runs one analysis and renders + saves the report. When extra modes
	// are given ("antox sostr detection,secrets"), they run together and
// merge into one report.
func execute(ctx context.Context, eng *analyzer.Engine, o analyzer.Options, cfg config) (*analyzer.Report, error) {
	var rep *analyzer.Report
	var err error
	if cfg.subModes != "" {
		modes := append([]string{o.Mode}, splitSubModes(cfg.subModes)...)
		rep, err = eng.RunModes(ctx, modes, o)
	} else {
		rep, err = eng.Run(ctx, o)
	}

	// On interrupt (Ctrl+C), render whatever partial results we have and
	// return nil so main() doesn't exit(1) with an error message.
	if err != nil && rep != nil && ctx.Err() != nil {
		fmt.Fprintf(os.Stderr, "\n  interrupted — showing partial results (%d findings)\n\n", len(rep.Findings))
		renderAndSave(rep, o, cfg)
		return rep, nil
	}

	if err != nil {
		return rep, err
	}

	renderAndSave(rep, o, cfg)
	return rep, nil
}

// renderAndSave renders the report to the console and optionally saves it to
// disk. Extracted so both the normal and interrupt paths share the same logic.
func renderAndSave(rep *analyzer.Report, o analyzer.Options, cfg config) {
	if rep == nil {
		return
	}
	// full-scan mode defaults to a single .md report unless the user picked a
	// different format explicitly.
	format := cfg.format
	if o.Mode == "full" && format == "both" {
		format = "md"
	}
	rep.RenderConsole(os.Stdout, !cfg.noColor)
	// fridahook with -out <file>.js uses that path for the generated script
	// itself; don't also try to save a report into the same file as a directory.
	scriptOut := o.Mode == "fridahook" && strings.HasSuffix(strings.ToLower(o.OutDir), ".js")
	if !cfg.noSave && !scriptOut && len(rep.Findings) > 0 {
		files, serr := rep.Save(cfg.out, format)
		if serr != nil {
			fmt.Fprintf(os.Stderr, "  warning: save report: %v\n", serr)
			return
		}
		for _, f := range files {
			fmt.Printf("saved report: %s\n", f)
		}
	} else if !cfg.noSave && !scriptOut {
		fmt.Println("no findings to save")
	}
}

func runPing(ctx context.Context, client *mcp.Client) error {
	info, err := client.Initialize(ctx)
	if err != nil {
		return fmt.Errorf("initialize: %w", err)
	}
	fmt.Printf("connected to %s\n", client.BaseURL())
	if info != nil {
		fmt.Printf("  protocol version: %s\n", info.ProtocolVersion)
		if info.ServerInfo != nil {
			fmt.Printf("  server: %v\n", info.ServerInfo)
		}
	}
	tools, err := client.ListTools(ctx)
	if err != nil {
		fmt.Printf("  tools: <list failed: %v>\n", err)
		return nil
	}
	fmt.Printf("  tools: %d available\n", len(tools))
	for _, t := range tools {
		fmt.Printf("    - %s\n", t.Name)
	}
	return nil
}

func runListTools(ctx context.Context, client *mcp.Client) error {
	if _, err := client.Initialize(ctx); err != nil {
		return fmt.Errorf("initialize: %w", err)
	}
	tools, err := client.ListTools(ctx)
	if err != nil {
		return err
	}
	for _, t := range tools {
		fmt.Printf("%s\n  %s\n\n", t.Name, t.Description)
	}
	return nil
}

// runShell provides an interactive REPL where each mode command runs a
// category search and prints (and optionally saves) the report.
func runShell(ctx context.Context, client *mcp.Client, cfg config) {
	eng := analyzer.NewEngine(client, cfg.limit, cfg.debug)
	eng.Quiet = cfg.quiet
	eng.NoColor = cfg.noColor
	if cfg.workers > 0 {
		eng.Workers = cfg.workers
	}
	if _, err := client.Initialize(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "error: cannot connect to MCP server:", err)
		return
	}
	fmt.Print(banner)
	fmt.Println("  connected:", cfg.mcpURL)
	fmt.Println("  type a mode, 'search <term> [scope]', or 'help'. 'exit' to quit.")
	fmt.Println()

	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("anzle> ")
		line, err := reader.ReadString('\n')
		if err != nil {
			fmt.Println()
			break
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		cmd := strings.ToLower(parts[0])

		switch cmd {
		case "exit", "quit", "q":
			return
		case "help", "modes", "?":
			printModes()
			continue
		case "ping":
			if err := runPing(ctx, client); err != nil {
				fmt.Fprintln(os.Stderr, "error:", err)
			}
			continue
		}

		o := analyzer.Options{
			Scope:   cfg.scope,
			Package: cfg.packageName,
			Limit:   cfg.limit,
			Debug:   cfg.debug,
			ApkDir:  cfg.apkDir,
			OutDir:  cfg.out,
		}
		switch cmd {
		case "search":
			if len(parts) < 2 {
				fmt.Println("usage: search <term> [scope]   e.g. search apiKey code")
				fmt.Println("  scopes: class,method,field,code,resource,comments  (resource = .so/.dex file names)")
				continue
			}
			o.Term = parts[1]
			o.Mode = "search"
			if len(parts) >= 3 {
				o.Scope = parts[2]
			}
		default:
			if !isMode(cmd) {
				fmt.Printf("unknown command %q — type 'help' for modes\n", cmd)
				continue
			}
			o.Mode = cmd
		}

		if _, err := execute(ctx, eng, o, cfg); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
		}
		fmt.Println()
	}
}

func isMode(m string) bool {
	switch m {
	case "manifest", "secrets", "apikey", "apikeys", "keys", "firebase",
		"security", "hardening", "detection", "sdks", "sdk", "libraries", "libs",
		"native", "so", "jni",
		"sostr", "so-scan", "sostrings",
		"hexenc", "obfuscation", "obfuscate",
		"hexstr", "hex", "hextract",
		"hexdump", "hexdecode",
		"backend", "hosts", "endpoints", "infra",
		"fridahook", "frida", "hookjs", "bypass",
		"all", "full":
		return true
	}
	return false
}

func printModes() {
	fmt.Println(`modes:
  manifest     analyze AndroidManifest.xml (components, permissions, flags)
  secrets      extract API keys / tokens / credentials from code & strings
  firebase     extract Firebase / google-services configuration
  security     map security layers (root, frida, emulator, debugger, ssl, crypto, integrity, rasp)
  detection    find detection logic & hardening SDKs (includes SDK inventory)
  sdks         inventory vendor SDKs by package: RASP / hardening / attestation /
               device-intel / analytics / hook frameworks (e.g. Talsec, DexGuard,
               Play Integrity, ThreatMetrix, AppsFlyer, Xposed)
  native       auto-detect native .so libs, JNI exports, function names, syscalls
  sostr        scan packaged .so files for hook/root/detection strings (-apk required);
               may take extra modes to run together: sostr detection,secrets
  hexenc       find hex / string obfuscation routines
  hexstr       scan code for hex blobs and decode (ascii / xor-0x42 / xor-0x41 / xor-0x5a)
  hexdump      decode a hex blob passed via -term   (try each XOR key)
  backend      map backend hosts/IPs/endpoints + Firebase config (code & raw resource content)
  fridahook    generate an app-tailored Frida bypass script (frida-hook.js) from
               the discovered detection targets; -out <file.js> sets the path
  search       custom keyword search   (requires -term)
  all          run every mode (manifest, secrets, firebase, security, detection,
               native, hexenc, hexstr, backend, fridahook)
  full         full scan: same as 'all', but writes a .md report by default
  shell        interactive session
  ping         test connectivity to the MCP server
  list-tools   list tools exposed by the MCP server`)
}

func printUsage(fs *flag.FlagSet) {
	fmt.Print(banner)
	fmt.Println("\nusage: antox <mode> [flags]")
	fmt.Println()
	printModes()
	fmt.Println()
	fmt.Println("flags:")
	fs.PrintDefaults()
	fmt.Println()
	fmt.Println("examples (Windows cmd friendly):")
	fmt.Println("  antox ping")
	fmt.Println("  antox full")
	fmt.Println("  antox full -out report.md -format md")
	fmt.Println("  antox backend -apk base.apk_folder,config.arm64_v8a.apk_folder")
	fmt.Println("  antox sostr -apk base.apk_folder")
	fmt.Println("  antox sostr detection,secrets -apk base.apk_folder")
	fmt.Println("  antox full -apk base.apk_folder,config.arm64_v8a.apk_folder -out report.md")
	fmt.Println("  antox search apiKey -scope code,method")
	fmt.Println("  antox shell")
}
