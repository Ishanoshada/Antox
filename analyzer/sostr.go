package analyzer

import (
	"archive/zip"
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"antox/patterns"
)

// AnalyzeSoStrings scans every packaged .so file found under -apk for hook /
// root / anti-debug detection strings (the t.py keyword sweep) and resolves
// where each string is referenced by raw pointers in the image (the t2.py
// stage, fixed to scan both 8-byte and 4-byte little-endian pointers — Dart
// AOT snapshots reference strings through 4-byte object-pool slots that an
// 8-byte-only scan misses). Each -apk token may be an unzipped APK root or a
// raw .apk/.zip file (the native libs are read straight out of the container).
func (e *Engine) AnalyzeSoStrings(ctx context.Context, o Options) (*Report, error) {
	start := time.Now()
	r := &Report{Mode: o.Mode, AppName: "unknown", APKPackage: e.appPackage(ctx)}

	if o.ApkDir == "" {
		r.Notes = append(r.Notes, "sostr: no -apk dir provided — pass the unzipped APK root or an .apk file")
		r.DurationMS = time.Since(start).Milliseconds()
		e.finishReport(ctx, r)
		return r, nil
	}

	payloads := e.soPayloads(o.ApkDir)
	if len(payloads) == 0 {
		r.Notes = append(r.Notes, "sostr: no .so files found under -apk input")
		r.DurationMS = time.Since(start).Milliseconds()
		e.finishReport(ctx, r)
		return r, nil
	}

	for _, p := range payloads {
		e.scanSoImage(ctx, r, p.name, p.image)
	}

	if len(r.Findings) == 0 {
		r.Notes = append(r.Notes, "sostr: no hook/root/detection strings found in packaged .so files")
	}

	r.DurationMS = time.Since(start).Milliseconds()
	e.finishReport(ctx, r)
	return r, nil
}

// soPayload is one .so payload discovered from -apk input, already read into
// memory. name is the display name (lib basename or zip entry path).
type soPayload struct {
	name  string
	image []byte
}

// soPayloads discovers .so payloads under every -apk token. A token may be:
//   - an unzipped APK root directory (walk it for *.so files), or
//   - a raw .apk / .zip file (read lib/**/*.so entries out of the container).
//
// Payloads are de-duplicated by basename (a split config APK repeats the same
// library per ABI — scanning the first copy is enough), mirroring scanApkDir.
func (e *Engine) soPayloads(apkDir string) []soPayload {
	visited := map[string]bool{}
	var out []soPayload
	for _, d := range strings.FieldsFunc(apkDir, func(c rune) bool { return c == ',' || c == ';' }) {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		fi, err := os.Stat(d)
		if err != nil {
			e.Errs = append(e.Errs, fmt.Sprintf("sostr stat %s: %v", d, err))
			continue
		}
		if fi.IsDir() {
			out = append(out, e.dirSoPayloads(d, visited)...)
			continue
		}
		out = append(out, e.zipSoPayloads(d, visited)...)
	}
	return out
}

// dirSoPayloads walks an unzipped APK root and reads every *.so file.
func (e *Engine) dirSoPayloads(dir string, visited map[string]bool) []soPayload {
	var out []soPayload
	err := filepath.Walk(dir, func(path string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() {
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(path), ".so") {
			return nil
		}
		base := strings.ToLower(fi.Name())
		if visited[base] {
			return nil
		}
		visited[base] = true
		if fi.Size() > 300_000_000 {
			e.Errs = append(e.Errs, fmt.Sprintf("sostr %s: file too large (%d bytes)", path, fi.Size()))
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			e.Errs = append(e.Errs, fmt.Sprintf("sostr %s: read: %v", path, err))
			return nil
		}
		out = append(out, soPayload{name: filepath.Base(path), image: data})
		return nil
	})
	if err != nil {
		e.Errs = append(e.Errs, fmt.Sprintf("sostr walk %s: %v", dir, err))
	}
	return out
}

// zipSoPayloads opens a raw .apk/.zip file and reads every *.so entry (these
// live under lib/<abi>/ in an APK). Entry sizes are capped so a hostile or
// inflated archive can't exhaust memory.
func (e *Engine) zipSoPayloads(apkPath string, visited map[string]bool) []soPayload {
	zr, err := zip.OpenReader(apkPath)
	if err != nil {
		e.Errs = append(e.Errs, fmt.Sprintf("sostr %s: open apk: %v", apkPath, err))
		return nil
	}
	defer zr.Close()

	var out []soPayload
	for _, zf := range zr.File {
		if !strings.HasSuffix(strings.ToLower(zf.Name), ".so") {
			continue
		}
		base := strings.ToLower(filepath.Base(zf.Name))
		if visited[base] {
			continue
		}
		visited[base] = true
		if zf.UncompressedSize64 > 300_000_000 {
			e.Errs = append(e.Errs, fmt.Sprintf("sostr %s: entry too large (%d bytes)", zf.Name, zf.UncompressedSize64))
			continue
		}
		rc, err := zf.Open()
		if err != nil {
			e.Errs = append(e.Errs, fmt.Sprintf("sostr %s: open entry: %v", zf.Name, err))
			continue
		}
		data, rerr := io.ReadAll(rc)
		rc.Close()
		if rerr != nil {
			e.Errs = append(e.Errs, fmt.Sprintf("sostr %s: read entry: %v", zf.Name, rerr))
			continue
		}
		out = append(out, soPayload{name: zf.Name, image: data})
	}
	return out
}

// scanSoImage extracts detection strings from one .so image in memory and
// emits findings:
//
//   - strings: printable runs from .rodata / .data / .data.rel.ro (t.py izj)
//   - refs:    4-byte + 8-byte little-endian pointers equal to the string vaddr
//     located in the pointer-bearing sections (t2.py /xj)
//   - lib:     a known detection-payload basename (libts, libsna, ...) is
//     flagged independently of its strings
//
// A string that is actually referenced by the image is raised to high; a
// present-but-unreferenced string is reported as medium. On a Dart AOT snapshot
// (libapp.so) the alert strings are reached through tagged object-pool entries,
// so most come back medium — that is the honest result, not an omission.
func (e *Engine) scanSoImage(ctx context.Context, r *Report, name string, image []byte) {
	f, err := elf.NewFile(bytes.NewReader(image))
	if err != nil {
		e.Errs = append(e.Errs, fmt.Sprintf("sostr %s: elf: %v", name, err))
		return
	}
	defer f.Close()

	base := filepath.Base(name)
	if isSuspiciousSo(base) {
		r.Findings = append(r.Findings, Finding{
			Category: "so",
			Severity: "high",
			Title:    "Suspicious native security/detection library",
			Class:    base,
			Detail:   "library basename matches a known detection payload (.so) family",
		})
	}

	var spans []patterns.SectionSpan
	var strSecs []*elf.Section
	for _, sec := range f.Sections {
		if sec.Type != elf.SHT_PROGBITS || sec.Size == 0 {
			continue
		}
		switch sec.Name {
		case ".rodata", ".data", ".data.rel.ro":
			strSecs = append(strSecs, sec)
			spans = append(spans, patterns.SectionSpan{Name: sec.Name, Offset: sec.Offset, Size: sec.Size})
		case ".got":
			spans = append(spans, patterns.SectionSpan{Name: sec.Name, Offset: sec.Offset, Size: sec.Size})
		}
	}
	if len(strSecs) == 0 {
		return
	}

	// Collect keyword-matching strings.
	var matched []patterns.SoString
	vaddrs := map[uint64]bool{}
	for _, sec := range strSecs {
		data, err := sec.Data()
		if err != nil {
			continue
		}
		for _, s := range patterns.ExtractSectionStrings(data, sec.Addr, 4) {
			if patterns.SoScanRe.MatchString(s.Str) {
				matched = append(matched, s)
				vaddrs[s.VAddr] = true
			}
		}
	}
	if len(matched) == 0 {
		return
	}

	// One pass over the pointer-bearing spans: any slot whose 4- or 8-byte
	// value equals a matched string vaddr is a reference to it.
	refs := resolveSoRefs(image, spans, vaddrs)

	for _, s := range matched {
		sr := refs[s.VAddr]
		sev, title := "medium", "Detection string in native library"
		if len(sr) > 0 {
			sev, title = "high", "Referenced detection string in native library"
		}
		ev := []string{fmt.Sprintf("0x%x %q -> %s", s.VAddr, s.Str, strings.Join(patterns.MatchSoKeywords(s.Str), ","))}
		for _, rf := range sr {
			ev = append(ev, fmt.Sprintf("  referenced from 0x%x (%s)", rf.Offset, rf.Section))
		}
		r.Findings = append(r.Findings, Finding{
			Category: "so",
			Severity: sev,
			Title:    title,
			Class:    base,
			Detail:   "hook/root/detection string in packaged .so",
			Evidence: strings.Join(ev, "\n"),
		})
	}
}

// resolveSoRefs makes one pass over the pointer-bearing spans and returns, for
// every matched string vaddr, the slots that reference it (as 8-byte or 4-byte
// little-endian values). The 4-byte pass covers Dart AOT object-pool /
// diagnostic-table pointers that t2.py misses by only searching 8-byte
// pointers. A slot whose stored 8-byte value equals the vaddr (high 32 bits
// zero) also satisfies the 4-byte read at the same offset, so refs are
// de-duplicated per string.
func resolveSoRefs(image []byte, spans []patterns.SectionSpan, vaddrs map[uint64]bool) map[uint64][]patterns.Ref {
	out := map[uint64][]patterns.Ref{}
	for _, sp := range spans {
		start, end := sp.Offset, sp.Offset+sp.Size
		if end > uint64(len(image)) {
			end = uint64(len(image))
		}
		for off := start; off < end; off++ {
			if off+8 <= end {
				v := binary.LittleEndian.Uint64(image[off : off+8])
				if vaddrs[v] {
					out[v] = append(out[v], patterns.Ref{Offset: int64(off), Section: sp.Name})
				}
			}
			if off+4 <= end {
				v := uint64(binary.LittleEndian.Uint32(image[off : off+4]))
				if vaddrs[v] {
					out[v] = append(out[v], patterns.Ref{Offset: int64(off), Section: sp.Name})
				}
			}
		}
	}
	for v, rr := range out {
		seen := map[int64]bool{}
		uniq := rr[:0]
		for _, rf := range rr {
			if !seen[rf.Offset] {
				seen[rf.Offset] = true
				uniq = append(uniq, rf)
			}
		}
		out[v] = uniq
	}
	return out
}
