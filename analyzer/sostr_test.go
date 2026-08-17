package analyzer

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"antox/patterns"
)

func TestResolveSoRefs_4ByteAnd8Byte(t *testing.T) {
	image := make([]byte, 24)
	copy(image[0:8], []byte("xxxxxxxx"))
	binary.LittleEndian.PutUint32(image[8:12], 0x100) // 4-byte slot
	binary.LittleEndian.PutUint64(image[12:20], 0x200)
	copy(image[20:24], []byte("zzzz"))

	spans := []patterns.SectionSpan{{Name: ".rodata", Offset: 0, Size: 24}}
	vaddrs := map[uint64]bool{0x100: true, 0x200: true, 0x999: true}

	refs := resolveSoRefs(image, spans, vaddrs)

	if len(refs[0x100]) != 1 || refs[0x100][0].Offset != 8 {
		t.Fatalf("4-byte ref for 0x100: %+v", refs[0x100])
	}
	if len(refs[0x200]) != 1 || refs[0x200][0].Offset != 12 {
		t.Fatalf("8-byte ref for 0x200: %+v", refs[0x200])
	}
	if len(refs[0x999]) != 0 {
		t.Fatalf("unexpected refs for 0x999: %+v", refs[0x999])
	}
}

func TestZipSoPayloads(t *testing.T) {
	// Build a fake APK in a temp file: two ABIs of the same lib plus a dex.
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	write := func(name string, data []byte) {
		w, _ := zw.Create(name)
		w.Write(data)
	}
	write("lib/arm64-v8a/libapp.so", []byte{1, 2, 3})
	write("lib/armeabi-v7a/libapp.so", []byte{4, 5, 6})
	write("classes.dex", []byte{9})
	zw.Close()

	dir := t.TempDir()
	apk := filepath.Join(dir, "app.apk")
	if err := os.WriteFile(apk, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	e := &Engine{}
	payloads := e.zipSoPayloads(apk, map[string]bool{})
	if len(payloads) != 1 {
		t.Fatalf("expected 1 deduped .so payload (per basename), got %d: %+v", len(payloads), payloads)
	}
	if payloads[0].name != "lib/arm64-v8a/libapp.so" {
		t.Fatalf("expected first ABI entry kept, got %q", payloads[0].name)
	}
}

func TestZipSoPayloads_NotAZip(t *testing.T) {
	dir := t.TempDir()
	apk := filepath.Join(dir, "junk.apk")
	if err := os.WriteFile(apk, []byte("not a zip"), 0o644); err != nil {
		t.Fatal(err)
	}
	e := &Engine{}
	payloads := e.zipSoPayloads(apk, map[string]bool{})
	if len(payloads) != 0 {
		t.Fatalf("expected no payloads from a non-zip, got %d", len(payloads))
	}
	if len(e.Errs) == 0 {
		t.Fatal("expected an error recorded for the non-zip input")
	}
}

func TestResolveSoRefs_Dedup8And4(t *testing.T) {
	// An 8-byte slot storing exactly vaddr (high 32 bits zero) satisfies both
	// the 8-byte and 4-byte reads at the same offset -> must dedupe to one ref.
	image := make([]byte, 16)
	binary.LittleEndian.PutUint64(image[4:12], 0x1234)
	spans := []patterns.SectionSpan{{Name: ".rodata", Offset: 0, Size: 16}}

	refs := resolveSoRefs(image, spans, map[uint64]bool{0x1234: true})

	if len(refs[0x1234]) != 1 {
		t.Fatalf("expected one deduped ref, got %+v", refs[0x1234])
	}
	if refs[0x1234][0].Offset != 4 {
		t.Fatalf("expected ref at offset 4, got %+v", refs[0x1234])
	}
}
