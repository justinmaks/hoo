package export

import (
	"encoding/csv"
	"fmt"
	"os"
	"time"

	"github.com/justinmaks/hoo/internal/aggregate"
	"github.com/justinmaks/hoo/internal/resolve"
)

const schemaVersion = "v1"

// CSVWriter writes session data in various CSV schemas.
type CSVWriter struct {
	resolver *resolve.Resolver
}

// NewCSVWriter creates a CSV writer.
func NewCSVWriter(resolver *resolve.Resolver) *CSVWriter {
	return &CSVWriter{resolver: resolver}
}

// WriteConnections exports connection data.
func (w *CSVWriter) WriteConnections(path string, snap *aggregate.Snapshot, append bool) error {
	f, isNew, err := openFile(path, append)
	if err != nil {
		return err
	}
	defer f.Close()

	writer := csv.NewWriter(f)
	defer writer.Flush()

	if isNew {
		fmt.Fprintf(f, "# hoo export %s connections\n", schemaVersion)
		writer.Write([]string{
			"timestamp", "protocol", "local_addr", "remote_addr", "remote_hostname",
			"bytes_in", "bytes_out", "packets_in", "packets_out", "state", "duration_ms",
		})
	}

	now := time.Now().Format(time.RFC3339)
	for _, c := range snap.Connections {
		hostname := c.RemoteIP.String()
		if w.resolver != nil {
			hostname = w.resolver.Lookup(hostname)
		}

		duration := c.LastActivity.Sub(c.StartTime).Milliseconds()
		state := ""
		if c.Key.Proto == "TCP" {
			state = c.TCPState.String()
		}

		writer.Write([]string{
			now,
			c.Key.Proto,
			fmt.Sprintf(":%d", c.LocalPort),
			fmt.Sprintf("%s:%d", c.RemoteIP, c.RemotePort),
			hostname,
			fmt.Sprintf("%d", c.BytesIn),
			fmt.Sprintf("%d", c.BytesOut),
			fmt.Sprintf("%d", c.PacketsIn),
			fmt.Sprintf("%d", c.PacketsOut),
			state,
			fmt.Sprintf("%d", duration),
		})
	}

	return writer.Error()
}

// WriteStats exports time-series bandwidth statistics.
func (w *CSVWriter) WriteStats(path string, snap *aggregate.Snapshot, append bool) error {
	f, isNew, err := openFile(path, append)
	if err != nil {
		return err
	}
	defer f.Close()

	writer := csv.NewWriter(f)
	defer writer.Flush()

	if isNew {
		fmt.Fprintf(f, "# hoo export %s stats\n", schemaVersion)
		writer.Write([]string{
			"timestamp", "bytes_in", "bytes_out", "packets_in", "packets_out",
			"active_connections", "new_connections", "closed_connections",
		})
	}

	for _, b := range snap.Bandwidth {
		writer.Write([]string{
			b.Timestamp.Format(time.RFC3339),
			fmt.Sprintf("%d", b.BytesIn),
			fmt.Sprintf("%d", b.BytesOut),
			fmt.Sprintf("%d", b.PacketsIn),
			fmt.Sprintf("%d", b.PacketsOut),
			fmt.Sprintf("%d", snap.ActiveConns),
			"0", // Tracked at snapshot level, not per-bucket.
			"0",
		})
	}

	return writer.Error()
}

// WriteFlows exports per-flow data.
func (w *CSVWriter) WriteFlows(path string, snap *aggregate.Snapshot, append bool) error {
	f, isNew, err := openFile(path, append)
	if err != nil {
		return err
	}
	defer f.Close()

	writer := csv.NewWriter(f)
	defer writer.Flush()

	if isNew {
		fmt.Fprintf(f, "# hoo export %s flows\n", schemaVersion)
		writer.Write([]string{
			"start_time", "end_time", "protocol", "local_addr", "remote_addr",
			"remote_hostname", "bytes_in", "bytes_out", "packets_in", "packets_out", "tcp_flags_seen",
		})
	}

	for _, c := range snap.Connections {
		hostname := c.RemoteIP.String()
		if w.resolver != nil {
			hostname = w.resolver.Lookup(hostname)
		}

		flags := ""
		if c.Key.Proto == "TCP" {
			flags = c.TCPState.String()
		}

		writer.Write([]string{
			c.StartTime.Format(time.RFC3339),
			c.LastActivity.Format(time.RFC3339),
			c.Key.Proto,
			fmt.Sprintf(":%d", c.LocalPort),
			fmt.Sprintf("%s:%d", c.RemoteIP, c.RemotePort),
			hostname,
			fmt.Sprintf("%d", c.BytesIn),
			fmt.Sprintf("%d", c.BytesOut),
			fmt.Sprintf("%d", c.PacketsIn),
			fmt.Sprintf("%d", c.PacketsOut),
			flags,
		})
	}

	return writer.Error()
}

// Export writes data using the specified schema type.
func (w *CSVWriter) Export(path, schemaType string, snap *aggregate.Snapshot, appendMode bool) error {
	switch schemaType {
	case "connections":
		return w.WriteConnections(path, snap, appendMode)
	case "stats":
		return w.WriteStats(path, snap, appendMode)
	case "flows":
		return w.WriteFlows(path, snap, appendMode)
	default:
		return fmt.Errorf("unknown export type: %s", schemaType)
	}
}

// TimestampedFilename generates a unique filename for on-demand exports.
func TimestampedFilename(prefix, ext string) string {
	return fmt.Sprintf("%s_%s.%s", prefix, time.Now().Format("20060102_150405"), ext)
}

func openFile(path string, appendMode bool) (*os.File, bool, error) {
	if appendMode {
		_, err := os.Stat(path)
		if err == nil {
			// File exists — append.
			f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0644)
			return f, false, err
		}
	}

	// Create new file.
	f, err := os.Create(path)
	return f, true, err
}

// CheckFileExists returns an error if the file exists and overwrite is not allowed.
func CheckFileExists(path string, overwrite bool) error {
	if overwrite {
		return nil
	}
	_, err := os.Stat(path)
	if err == nil {
		return fmt.Errorf("file %q already exists (use --overwrite to replace, or --append for CSV)", path)
	}
	return nil
}
