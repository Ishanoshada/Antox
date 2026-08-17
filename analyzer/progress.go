package analyzer

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

// Progress renders a tqdm-style single-line progress bar to a writer (normally
// stderr). A filled block track (▰) fills toward empty cells (▱) with a partial
// block on the moving edge, plus a percentage, count/total and elapsed time.
// The whole line redraws in place with a carriage return so long scans stay
// alive on screen without spamming the log. The partial edge cell uses the
// eighth-blocks gradient ▱▁▂▃▄▅▆▇█ so the bar visibly "fills in" as work
// completes instead of jumping cell by cell.
type Progress struct {
	mu       sync.Mutex
	w        io.Writer
	label    string
	total    int
	width    int  // bar width in cells
	color    bool // ANSI colors on the track / percent / meta
	start    time.Time
	lastDraw time.Time
	lastLine string
	lastN    int // last completed count (Finish renders this, not a forced 100%)
	finished bool
}

// NewProgress returns a bar for total units. Passing a nil writer discards all
// output (used to fully suppress the bar when Quiet is set).
func NewProgress(w io.Writer, total int, label string, color bool) *Progress {
	if w == nil {
		w = io.Discard
	}
	if label != "" {
		label += " "
	}
	return &Progress{w: w, label: label, total: total, width: 28, color: color, start: time.Now()}
}

// partialGradient maps a fraction inside one cell to an eighth-block glyph.
var partialGradient = []string{"▱", "▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"}

// Update redraws the bar for n completed units. Redraws are throttled to
// roughly 10 Hz and skipped when the rendered line is unchanged, so fast
// completions don't flicker. The final cell count is always rendered.
func (p *Progress) Update(n int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.finished || p.total <= 0 {
		return
	}
	// Always render the final frame; throttle only mid-progress frames so fast
	// completions don't flicker.
	if n < p.total && time.Since(p.lastDraw) < 90*time.Millisecond {
		p.lastN = n // still track the count so Finish reports truthfully
		return
	}
	p.lastN = n
	p.lastDraw = time.Now()
	line := p.render(n)
	if line == p.lastLine {
		return
	}
	p.lastLine = line
	fmt.Fprintf(p.w, "\r\x1b[K%s", line)
}

// Finish completes the bar at 100%, printing a trailing newline so subsequent
// output starts on a fresh line (tqdm keeps its final line visible too).
func (p *Progress) Finish() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.finished || p.total <= 0 {
		return
	}
	p.finished = true
	// Render at the last actual count: on a normal run that is total (100%);
	// on an interrupted run it truthfully shows how far it got.
	fmt.Fprintf(p.w, "\r\x1b[K%s\n", p.render(p.lastN))
}

// render composes the bar line for n completed units.
func (p *Progress) render(n int) string {
	frac := 1.0
	if p.total > 0 {
		frac = float64(n) / float64(p.total)
	}
	if frac < 0 {
		frac = 0
	}
	if frac > 1 {
		frac = 1
	}
	pct := int(frac*100 + 0.5)
	full := int(float64(p.width) * frac)
	if full > p.width {
		full = p.width
	}
	var track strings.Builder
	for i := 0; i < full; i++ {
		track.WriteString("▰")
	}
	if full < p.width {
		// fraction of the boundary cell already filled
		edge := frac*float64(p.width) - float64(full)
		idx := int(edge*8 + 0.5)
		if idx > 8 {
			idx = 8
		}
		track.WriteString(partialGradient[idx])
		for i := full + 1; i < p.width; i++ {
			track.WriteString("▱")
		}
	}
	elapsed := time.Since(p.start).Round(time.Millisecond)
	if !p.color {
		return fmt.Sprintf("%s%s %3d%%  %d/%d  %s",
			p.label, track.String(), pct, n, p.total, elapsed)
	}
	return fmt.Sprintf("%s\x1b[36m%s\x1b[0m \x1b[33m%3d%%\x1b[0m  \x1b[2m%d/%d %s\x1b[0m",
		p.label, track.String(), pct, n, p.total, elapsed)
}
