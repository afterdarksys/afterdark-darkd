package dnstunnel

import (
	"bufio"
	"context"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/afterdarksys/afterdark-darkd/internal/models"
	"go.uber.org/zap"
)

// LogCapture captures DNS queries from system logs
type LogCapture struct {
	logger   *zap.Logger
	queries  chan models.TunnelDNSQuery
	stopChan chan struct{}
}

// NewLogCapture creates a new log-based DNS capture
func NewLogCapture(logger *zap.Logger) (*LogCapture, error) {
	return &LogCapture{
		logger:   logger.Named("log-capture"),
		queries:  make(chan models.TunnelDNSQuery, 1000),
		stopChan: make(chan struct{}),
	}, nil
}

// Start starts capturing DNS queries from logs
func (c *LogCapture) Start(ctx context.Context) error {
	go c.watchLogs(ctx)
	return nil
}

// Stop stops the capture
func (c *LogCapture) Stop() error {
	close(c.stopChan)
	return nil
}

// Queries returns the channel of captured queries
func (c *LogCapture) Queries() <-chan models.TunnelDNSQuery {
	return c.queries
}

// watchLogs monitors DNS-related log files
func (c *LogCapture) watchLogs(ctx context.Context) {
	// Try common DNS log locations
	logPaths := []string{
		"/var/log/syslog",
		"/var/log/messages",
		"/var/log/dnsmasq.log",
		"/var/log/named/query.log",
	}

	for _, path := range logPaths {
		if _, err := os.Stat(path); err == nil {
			go c.tailLog(ctx, path)
			c.logger.Info("watching DNS log", zap.String("path", path))
		}
	}
}

// tailLog tails a log file for DNS queries
func (c *LogCapture) tailLog(ctx context.Context, path string) {
	// DNS query patterns for common resolvers
	patterns := []*regexp.Regexp{
		// systemd-resolved
		regexp.MustCompile(`query\[(\w+)\]\s+(\S+)\s+from`),
		// dnsmasq
		regexp.MustCompile(`query\[(\w+)\]\s+(\S+)\s+from`),
		// BIND
		regexp.MustCompile(`client.*query:\s+(\S+)\s+IN\s+(\w+)`),
	}

	file, err := os.Open(path)
	if err != nil {
		c.logger.Debug("could not open log file", zap.String("path", path), zap.Error(err))
		return
	}
	defer file.Close()

	// Seek to end
	file.Seek(0, 2)

	scanner := bufio.NewScanner(file)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stopChan:
			return
		case <-ticker.C:
			for scanner.Scan() {
				line := scanner.Text()
				if query := c.parseLogLine(line, patterns); query != nil {
					select {
					case c.queries <- *query:
					default:
						// Channel full, drop query
					}
				}
			}
		}
	}
}

// parseLogLine parses a log line for DNS query information
func (c *LogCapture) parseLogLine(line string, patterns []*regexp.Regexp) *models.TunnelDNSQuery {
	for _, pattern := range patterns {
		matches := pattern.FindStringSubmatch(line)
		if len(matches) >= 3 {
			return &models.TunnelDNSQuery{
				Timestamp:    time.Now(),
				Domain:       strings.TrimSuffix(matches[2], "."),
				RecordType:   strings.ToUpper(matches[1]),
				ResponseCode: models.DNSResponseNOERROR, // Assume success from logs
			}
		}
	}
	return nil
}

// PcapCapture captures DNS queries using packet capture
type PcapCapture struct {
	logger   *zap.Logger
	queries  chan models.TunnelDNSQuery
	stopChan chan struct{}
}

// NewPcapCapture creates a new pcap-based DNS capture
func NewPcapCapture(logger *zap.Logger) (*PcapCapture, error) {
	return &PcapCapture{
		logger:   logger.Named("pcap-capture"),
		queries:  make(chan models.TunnelDNSQuery, 1000),
		stopChan: make(chan struct{}),
	}, nil
}

// Start starts capturing DNS packets
func (c *PcapCapture) Start(ctx context.Context) error {
	// Note: Full pcap implementation requires CGO and libpcap
	// This is a placeholder - real implementation would use gopacket
	c.logger.Info("pcap capture started (placeholder)")
	return nil
}

// Stop stops the capture
func (c *PcapCapture) Stop() error {
	close(c.stopChan)
	return nil
}

// Queries returns the channel of captured queries
func (c *PcapCapture) Queries() <-chan models.TunnelDNSQuery {
	return c.queries
}

// ETWCapture captures DNS queries using Windows ETW (Event Tracing for Windows)
type ETWCapture struct {
	logger   *zap.Logger
	queries  chan models.TunnelDNSQuery
	stopChan chan struct{}
}

// NewETWCapture creates a new ETW-based DNS capture (Windows only)
func NewETWCapture(logger *zap.Logger) (*ETWCapture, error) {
	return &ETWCapture{
		logger:   logger.Named("etw-capture"),
		queries:  make(chan models.TunnelDNSQuery, 1000),
		stopChan: make(chan struct{}),
	}, nil
}

// Start starts capturing DNS events via ETW
func (c *ETWCapture) Start(ctx context.Context) error {
	// Note: ETW implementation requires Windows-specific code
	// This is a placeholder
	c.logger.Info("ETW capture started (placeholder - Windows only)")
	return nil
}

// Stop stops the capture
func (c *ETWCapture) Stop() error {
	close(c.stopChan)
	return nil
}

// Queries returns the channel of captured queries
func (c *ETWCapture) Queries() <-chan models.TunnelDNSQuery {
	return c.queries
}

// PassiveCapture integrates with existing DNS resolver hooks
type PassiveCapture struct {
	logger  *zap.Logger
	queries chan models.TunnelDNSQuery
}

// NewPassiveCapture creates a passive capture that receives queries from external sources
func NewPassiveCapture(logger *zap.Logger) *PassiveCapture {
	return &PassiveCapture{
		logger:  logger.Named("passive-capture"),
		queries: make(chan models.TunnelDNSQuery, 1000),
	}
}

// Start starts the passive capture (no-op, waits for external input)
func (c *PassiveCapture) Start(ctx context.Context) error {
	return nil
}

// Stop stops the capture
func (c *PassiveCapture) Stop() error {
	return nil
}

// Queries returns the channel of captured queries
func (c *PassiveCapture) Queries() <-chan models.TunnelDNSQuery {
	return c.queries
}

// InjectQuery allows external code to inject DNS queries for analysis
func (c *PassiveCapture) InjectQuery(query models.TunnelDNSQuery) {
	select {
	case c.queries <- query:
	default:
		// Channel full
	}
}
