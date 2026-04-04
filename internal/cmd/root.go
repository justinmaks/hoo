package cmd

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/justinmaks/hoo/internal/aggregate"
	"github.com/justinmaks/hoo/internal/anomaly"
	"github.com/justinmaks/hoo/internal/capture"
	"github.com/justinmaks/hoo/internal/config"
	"github.com/justinmaks/hoo/internal/decode"
	"github.com/justinmaks/hoo/internal/export"
	"github.com/justinmaks/hoo/internal/resolve"
	"github.com/justinmaks/hoo/internal/tui"
	"github.com/spf13/cobra"
)

// Build-time variables set via ldflags.
var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

// Flag variables.
var (
	flagInterface      string
	flagFilter         string
	flagHeadless       bool
	flagDuration       time.Duration
	flagListInterfaces bool
	flagBackend        string
	flagDirection      string
	flagExport         string
	flagExportType     string
	flagAppend         bool
	flagOverwrite      bool
	flagReport         string
	flagReportFormat   string
	flagInterval       time.Duration
	flagTickRate       int
)

var rootCmd = &cobra.Command{
	Use:   "hoo",
	Short: "Real-time network traffic monitor for the terminal",
	Long: `hoo is a single-binary CLI tool that captures live network traffic,
visualizes it in a rich terminal UI, and generates exportable reports.

Think htop meets tcpdump — live dashboard with bandwidth graphs, active
connections, protocol breakdown, and top talkers, plus CSV export and
Markdown/JSON reports.

Privileges:
  Linux   — Run with sudo, or grant capabilities:
            sudo setcap cap_net_raw,cap_net_admin=eip $(which hoo)
  macOS   — Run with sudo, or add your user to the access_bpf group
  Windows — Run as Administrator, or install Npcap in non-admin mode`,
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE:          run,
}

func init() {
	f := rootCmd.Flags()
	f.StringVarP(&flagInterface, "interface", "i", "", "network interface to capture on (auto-detect if omitted)")
	f.StringVar(&flagFilter, "filter", "", "BPF filter expression (tcpdump syntax)")
	f.BoolVar(&flagHeadless, "headless", false, "run without TUI (for scripting and automation)")
	f.DurationVar(&flagDuration, "duration", 0, "capture duration (e.g. 5m, 1h); 0 means unlimited")
	f.BoolVar(&flagListInterfaces, "list-interfaces", false, "list available network interfaces and exit")
	f.StringVar(&flagBackend, "backend", "libpcap", "capture backend: libpcap or afpacket (Linux only)")
	f.StringVar(&flagDirection, "direction", "both", "traffic direction filter: inbound, outbound, or both")
	f.StringVar(&flagExport, "export", "", "export CSV to this file path")
	f.StringVar(&flagExportType, "export-type", "connections", "CSV export schema: connections, stats, or flows")
	f.BoolVar(&flagAppend, "append", false, "append to existing CSV file instead of overwriting")
	f.BoolVar(&flagOverwrite, "overwrite", false, "overwrite existing export/report files")
	f.StringVar(&flagReport, "report", "", "generate report to this file path")
	f.StringVar(&flagReportFormat, "report-format", "markdown", "report format: markdown or json")
	f.DurationVar(&flagInterval, "interval", 0, "export interval for headless mode (e.g. 30s)")
	f.IntVar(&flagTickRate, "tick-rate", 1, "TUI refresh rate in Hz (1-10)")

	rootCmd.Version = fmt.Sprintf("%s (commit: %s, built: %s)", version, commit, date)
}

// buildConfig loads the config file and applies CLI flag overrides.
func buildConfig(cmd *cobra.Command) (config.Config, error) {
	cfg, err := config.LoadFile()
	if err != nil {
		return cfg, fmt.Errorf("loading config: %w", err)
	}

	if cmd.Flags().Changed("interface") {
		cfg.Interface = flagInterface
	}
	if cmd.Flags().Changed("filter") {
		cfg.Filter = flagFilter
	}
	if cmd.Flags().Changed("headless") {
		cfg.Headless = flagHeadless
	}
	if cmd.Flags().Changed("duration") {
		cfg.Duration = flagDuration
	}
	if cmd.Flags().Changed("backend") {
		cfg.Backend = flagBackend
	}
	if cmd.Flags().Changed("direction") {
		cfg.Direction = flagDirection
	}
	if cmd.Flags().Changed("export") {
		cfg.Export = flagExport
	}
	if cmd.Flags().Changed("export-type") {
		cfg.ExportType = flagExportType
	}
	if cmd.Flags().Changed("append") {
		cfg.Append = flagAppend
	}
	if cmd.Flags().Changed("overwrite") {
		cfg.Overwrite = flagOverwrite
	}
	if cmd.Flags().Changed("report") {
		cfg.Report = flagReport
	}
	if cmd.Flags().Changed("report-format") {
		cfg.ReportFormat = flagReportFormat
	}
	if cmd.Flags().Changed("interval") {
		cfg.Interval = flagInterval
	}
	if cmd.Flags().Changed("tick-rate") {
		cfg.TickRate = flagTickRate
	}

	return cfg, nil
}

func run(cmd *cobra.Command, args []string) error {
	// Handle --list-interfaces.
	if flagListInterfaces {
		ifaces, err := capture.ListInterfaces()
		if err != nil {
			return err
		}
		fmt.Print(capture.FormatInterfaceTable(ifaces))
		return nil
	}

	cfg, err := buildConfig(cmd)
	if err != nil {
		return err
	}

	// Check privilege.
	if err := capture.CheckPrivileges(); err != nil {
		return err
	}

	// Detect interface.
	iface := cfg.Interface
	if iface == "" {
		iface, err = capture.DetectDefaultInterface()
		if err != nil {
			return err
		}
	}

	// Get local IPs for direction detection.
	localIPs, err := capture.InterfaceIPs(iface)
	if err != nil {
		return fmt.Errorf("getting interface IPs: %w", err)
	}

	// Check file safety for headless exports.
	if cfg.Headless {
		if cfg.Export != "" && !cfg.Append {
			if err := export.CheckFileExists(cfg.Export, cfg.Overwrite); err != nil {
				return err
			}
		}
		if cfg.Report != "" {
			if err := export.CheckFileExists(cfg.Report, cfg.Overwrite); err != nil {
				return err
			}
		}
		if cfg.Export == "" && cfg.Report == "" {
			fmt.Fprintln(os.Stderr, "Warning: headless mode with no --export or --report; capture data will be discarded")
		}
	}

	// Set up signal handling.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
		<-sigCh
		os.Exit(130)
	}()

	// Duration limit.
	if cfg.Duration > 0 {
		ctx, cancel = context.WithTimeout(ctx, cfg.Duration)
		defer cancel()
	}

	// Create components.
	packetCh := make(chan capture.PacketData, 10000)

	// Select capture backend.
	engine := capture.NewBackend(cfg.Backend, iface, cfg.Filter, packetCh)
	decoder := decode.NewDecoder(localIPs, cfg.Direction)
	agg := aggregate.NewAggregator(
		aggregate.DefaultMaxConnections,
		aggregate.DefaultHoldTime,
		aggregate.DefaultStatsWindow,
		aggregate.DefaultTopN,
	)
	detector := anomaly.NewDetector(cfg.Anomaly)
	resolver := resolve.NewResolver(resolve.DefaultWorkers, resolve.DefaultCacheMax, resolve.DefaultTTL)
	defer resolver.Stop()

	startTime := time.Now()

	// Start capture engine.
	captureErrCh := make(chan error, 1)
	go func() {
		captureErrCh <- engine.Start(ctx)
	}()

	// Start decode + aggregate pipeline.
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case pd, ok := <-packetCh:
				if !ok {
					return
				}
				pkt := decoder.Decode(pd)
				if pkt == nil {
					continue
				}

				agg.Process(pkt)

				// Feed anomaly detection.
				now := time.Unix(0, pkt.Timestamp)
				if pkt.Transport == "TCP" && pkt.TCPFlags.SYN && !pkt.TCPFlags.ACK {
					detector.CheckPortScan(pkt.SrcIP.String(), pkt.DstPort, true, now)
					detector.CheckConnectionFlood(pkt.SrcIP.String(), now)
				}
				if pkt.Protocol == decode.ProtoDNS {
					detector.CheckDNS(now)
				}
				if pkt.Transport == "TCP" || pkt.Transport == "UDP" {
					detector.CheckUnexpectedProtocol(pkt.SrcPort, pkt.DstPort, pkt.Length, now)
				}
			}
		}
	}()

	// Periodic aggregation tick (1 Hz).
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				agg.EvictExpired()
				agg.PublishSnapshot()
				detector.Cleanup(time.Now())
			}
		}
	}()

	csvWriter := export.NewCSVWriter(resolver)
	reportGen := export.NewReportGenerator(resolver, iface, startTime)

	if cfg.Headless {
		return runHeadless(ctx, cfg, agg, detector, csvWriter, reportGen, captureErrCh)
	}

	return runTUI(ctx, cancel, cfg, agg, detector, resolver, engine, csvWriter, reportGen, captureErrCh, localIPs, iface)
}

func runHeadless(ctx context.Context, cfg config.Config, agg *aggregate.Aggregator, detector *anomaly.Detector, csvWriter *export.CSVWriter, reportGen *export.ReportGenerator, captureErrCh <-chan error) error {
	// Periodic export if interval set.
	if cfg.Interval > 0 && cfg.Export != "" {
		go func() {
			ticker := time.NewTicker(cfg.Interval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					snap := agg.ReadSnapshot()
					if snap != nil {
						csvWriter.Export(cfg.Export, cfg.ExportType, snap, cfg.Append)
					}
				}
			}
		}()
	}

	// Wait for capture to finish.
	select {
	case err := <-captureErrCh:
		if err != nil {
			return err
		}
	case <-ctx.Done():
	}

	// Final export.
	agg.PublishSnapshot()
	snap := agg.ReadSnapshot()

	if cfg.Export != "" && snap != nil {
		if err := csvWriter.Export(cfg.Export, cfg.ExportType, snap, cfg.Append); err != nil {
			fmt.Fprintf(os.Stderr, "Export error: %v\n", err)
		}
	}

	if cfg.Report != "" && snap != nil {
		data := reportGen.BuildReportData(snap, detector.Alerts())
		if err := reportGen.WriteReport(cfg.Report, cfg.ReportFormat, data); err != nil {
			fmt.Fprintf(os.Stderr, "Report error: %v\n", err)
		}
	}

	return nil
}

func runTUI(ctx context.Context, cancel context.CancelFunc, cfg config.Config, agg *aggregate.Aggregator, detector *anomaly.Detector, resolver *resolve.Resolver, engine capture.CaptureEngine, csvWriter *export.CSVWriter, reportGen *export.ReportGenerator, captureErrCh <-chan error, localIPs []net.IP, iface string) error {
	localIPStr := ""
	if len(localIPs) > 0 {
		localIPStr = localIPs[0].String()
	}
	model := tui.NewModel(agg, detector, resolver, engine, cfg.Filter, cfg.TickRate, localIPStr, iface)

	model.OnExport = func() string {
		snap := agg.ReadSnapshot()
		if snap == nil {
			return "Export failed: no data yet"
		}
		path := export.TimestampedFilename("hoo_export", "csv")
		if err := csvWriter.Export(path, cfg.ExportType, snap, false); err != nil {
			return fmt.Sprintf("Export error: %v", err)
		}
		return fmt.Sprintf("Exported to %s", path)
	}

	model.OnReport = func() string {
		snap := agg.ReadSnapshot()
		if snap == nil {
			return "Report failed: no data yet"
		}
		ext := "md"
		if cfg.ReportFormat == "json" {
			ext = "json"
		}
		path := export.TimestampedFilename("hoo_report", ext)
		data := reportGen.BuildReportData(snap, detector.Alerts())
		if err := reportGen.WriteReport(path, cfg.ReportFormat, data); err != nil {
			return fmt.Sprintf("Report error: %v", err)
		}
		return fmt.Sprintf("Report saved to %s", path)
	}

	model.OnQuit = func() {
		cancel()
	}

	p := tea.NewProgram(model, tea.WithAltScreen())

	// Stop TUI if capture fails.
	go func() {
		select {
		case err := <-captureErrCh:
			if err != nil {
				p.Quit()
			}
		case <-ctx.Done():
		}
	}()

	if _, err := p.Run(); err != nil {
		return err
	}

	cancel()

	// Final export/report if configured.
	agg.PublishSnapshot()
	snap := agg.ReadSnapshot()

	if cfg.Export != "" && snap != nil {
		if err := csvWriter.Export(cfg.Export, cfg.ExportType, snap, cfg.Append); err != nil {
			fmt.Fprintf(os.Stderr, "Export error: %v\n", err)
		}
	}

	if cfg.Report != "" && snap != nil {
		data := reportGen.BuildReportData(snap, detector.Alerts())
		if err := reportGen.WriteReport(cfg.Report, cfg.ReportFormat, data); err != nil {
			fmt.Fprintf(os.Stderr, "Report error: %v\n", err)
		}
	}

	return nil
}

// Execute runs the root command.
func Execute() error {
	return rootCmd.Execute()
}
