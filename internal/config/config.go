package config

import (
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// Config holds all hoo configuration.
type Config struct {
	Interface string `yaml:"interface"`
	Filter    string `yaml:"filter"`
	Backend   string `yaml:"backend"`
	Direction string `yaml:"direction"`
	TickRate  int    `yaml:"tick_rate"`

	Headless bool          `yaml:"headless"`
	Duration time.Duration `yaml:"duration"`

	Export     string        `yaml:"export"`
	ExportType string       `yaml:"export_type"`
	Append     bool          `yaml:"append"`
	Overwrite  bool          `yaml:"overwrite"`
	Interval   time.Duration `yaml:"interval"`

	Report       string `yaml:"report"`
	ReportFormat string `yaml:"report_format"`

	Anomaly AnomalyConfig `yaml:"anomaly"`
}

// AnomalyConfig holds anomaly detection thresholds.
type AnomalyConfig struct {
	PortScanPorts      int           `yaml:"port_scan_ports"`
	PortScanWindow     time.Duration `yaml:"port_scan_window"`
	DNSSpikeMultiplier float64       `yaml:"dns_spike_multiplier"`
	DNSSpikeWindow     time.Duration `yaml:"dns_spike_window"`
	ConnFloodCount     int           `yaml:"conn_flood_count"`
	ConnFloodWindow    time.Duration `yaml:"conn_flood_window"`
	AllowedPorts       []int         `yaml:"allowed_ports"`
}

// Default returns a Config with sane defaults.
func Default() Config {
	return Config{
		Backend:    "libpcap",
		Direction:  "both",
		TickRate:   1,
		ExportType: "connections",
		ReportFormat: "markdown",
		Anomaly: AnomalyConfig{
			PortScanPorts:      10,
			PortScanWindow:     60 * time.Second,
			DNSSpikeMultiplier: 10,
			DNSSpikeWindow:     30 * time.Second,
			ConnFloodCount:     50,
			ConnFloodWindow:    10 * time.Second,
			AllowedPorts:       []int{80, 443, 53, 22},
		},
	}
}

// LoadFile reads the config file from the standard path if it exists.
// Returns default config if no file is found.
func LoadFile() (Config, error) {
	cfg := Default()

	path := configPath()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return cfg, err
	}

	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Default(), err
	}

	return cfg, nil
}

// configPath returns the path to the config file, respecting XDG_CONFIG_HOME.
func configPath() string {
	dir := os.Getenv("XDG_CONFIG_HOME")
	if dir == "" {
		home, _ := os.UserHomeDir()
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "hoo", "config.yaml")
}
