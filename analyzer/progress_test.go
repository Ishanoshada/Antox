package analyzer

import (
	"bytes"
	"strings"
	"testing"
)

func TestProgressBarBlockGlyphs(t *testing.T) {
	var buf bytes.Buffer
	p := NewProgress(&buf, 4, "scan", false)
	p.Update(0)
	p.Update(1)
	p.Update(2)
	p.Update(3)
	p.Finish()
	out := buf.String()
	// Honest final frame: Finish reports the last actual count (3/4 = 75%),
	// not a forced 100% — that is what makes interrupted runs truthful.
	if !strings.Contains(out, "3/4") || !strings.Contains(out, "75%") {
		t.Fatalf("final frame should report last actual count 3/4 75%%, got: %q", out)
	}
	// The track must use the block glyphs (▰ for filled cells).
	if !strings.Contains(out, "▰") {
		t.Fatalf("expected filled block glyphs, got: %q", out)
	}
}

func TestProgressBarFullRunReaches100(t *testing.T) {
	var buf bytes.Buffer
	p := NewProgress(&buf, 4, "scan", false)
	for i := 0; i <= 4; i++ { // a normal run always Update()s to total
		p.Update(i)
	}
	p.Finish()
	out := buf.String()
	if !strings.Contains(out, "100%") || !strings.Contains(out, "4/4") {
		t.Fatalf("full run must reach 100%% 4/4: %q", out)
	}
	// All cells filled: full block track at completion.
	if !strings.Contains(out, "▰▰▰▰") {
		t.Fatalf("expected full block track, got: %q", out)
	}
}

func TestProgressBarPartialEdge(t *testing.T) {
	var buf bytes.Buffer
	p := NewProgress(&buf, 100, "", false)
	// 1/100 of a 28-cell bar fills less than one cell -> partial block glyph
	// (▁▂▃...) present, with trailing ▱ empties.
	p.Update(1)
	p.Finish()
	out := buf.String()
	if !strings.Contains(out, "▱") {
		t.Fatalf("expected trailing empty blocks: %q", out)
	}
	if !strings.Contains(out, "1%") {
		t.Fatalf("expected 1%% label: %q", out)
	}
}

func TestProgressBarNoTotalNoCrash(t *testing.T) {
	var buf bytes.Buffer
	p := NewProgress(&buf, 0, "none", false)
	p.Update(5)   // must not render / divide by zero
	p.Finish()    // must be a no-op too
	if buf.Len() != 0 {
		t.Fatalf("expected no output for zero-total bar, got: %q", buf.String())
	}
}

func TestProgressBarColorRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	p := NewProgress(&buf, 2, "scan", true)
	p.Update(1)
	p.Finish()
	out := buf.String()
	// ANSI color open/close sequences present.
	if !strings.Contains(out, "\x1b[") {
		t.Fatalf("expected ANSI sequences with color on: %q", out)
	}
	if !strings.Contains(out, "\x1b[0m") {
		t.Fatalf("expected ANSI reset: %q", out)
	}
}

func TestProgressBarLabelPrefix(t *testing.T) {
	var buf bytes.Buffer
	p := NewProgress(&buf, 2, "fetching", false)
	p.Finish()
	// The bar prefixes each frame with \r + erase-line; strip it for the check.
	got := strings.TrimPrefix(buf.String(), "\r\x1b[K")
	if !strings.HasPrefix(got, "fetching ") {
		t.Fatalf("label prefix missing: %q", got)
	}
}
