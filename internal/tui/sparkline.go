package tui

import (
	"fmt"
	"strings"

	"github.com/justinmaks/hoo/internal/aggregate"
)

// Unicode block characters for sparkline (8 levels).
var sparkBlocks = []rune{' ', '▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'}

func renderSparkline(buckets []aggregate.BandwidthBucket, width int, totalIn, totalOut uint64) string {
	if width < 10 {
		width = 10
	}

	// Extract RX and TX values for the last `width` buckets.
	rxVals := make([]uint64, width)
	txVals := make([]uint64, width)
	start := 0
	if len(buckets) > width {
		start = len(buckets) - width
	}
	for i := start; i < len(buckets); i++ {
		idx := i - start
		if idx >= width {
			break
		}
		rxVals[idx] = buckets[i].BytesIn
		txVals[idx] = buckets[i].BytesOut
	}

	// Find max for scaling.
	var maxVal uint64
	for _, v := range rxVals {
		if v > maxVal {
			maxVal = v
		}
	}
	for _, v := range txVals {
		if v > maxVal {
			maxVal = v
		}
	}

	// Current rates.
	var currentRX, currentTX uint64
	if len(buckets) > 0 {
		last := buckets[len(buckets)-1]
		currentRX = last.BytesIn
		currentTX = last.BytesOut
	}

	var sb strings.Builder
	sb.WriteString(titleStyle.Render("Bandwidth"))
	sb.WriteString(fmt.Sprintf("  RX: %s/s  TX: %s/s\n", formatBytes(currentRX), formatBytes(currentTX)))

	// RX sparkline.
	sb.WriteString(sparkRXStyle.Render("RX "))
	sb.WriteString(sparkRXStyle.Render(buildSparkline(rxVals, maxVal)))
	sb.WriteByte('\n')

	// TX sparkline.
	sb.WriteString(sparkTXStyle.Render("TX "))
	sb.WriteString(sparkTXStyle.Render(buildSparkline(txVals, maxVal)))
	sb.WriteByte('\n')

	sb.WriteString(dimStyle.Render(fmt.Sprintf("Total: ↓%s  ↑%s", formatBytes(totalIn), formatBytes(totalOut))))

	return sb.String()
}

func buildSparkline(values []uint64, maxVal uint64) string {
	var sb strings.Builder
	for _, v := range values {
		level := 0
		if maxVal > 0 {
			level = int(v * 8 / maxVal)
			if level > 8 {
				level = 8
			}
		}
		sb.WriteRune(sparkBlocks[level])
	}
	return sb.String()
}

func formatBytes(b uint64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(b)/float64(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(b)/float64(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(b)/float64(1<<10))
	default:
		return fmt.Sprintf("%d B", b)
	}
}
