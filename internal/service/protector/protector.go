// Package protector provides integration with DarkAPI Protector platform
// Sends real-time telemetry, alerts, and receives commands via WebSocket
package protector

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"nhooyr.io/websocket"
	"nhooyr.io/websocket/wsjson"
)

// Service handles communication with DarkAPI Protector platform
type Service struct {
	config       *Config
	conn         *websocket.Conn
	connected    bool
	reconnecting bool
	mu           sync.RWMutex

	// Channels
	alertQueue      chan Alert
	telemetryQueue  chan TelemetryData
	commandResponse chan CommandResponse

	// Context for graceful shutdown
	ctx    context.Context
	cancel context.CancelFunc

	// Service registry (to access other services)
	registry ServiceRegistry
}

// Config holds protector service configuration
type Config struct {
	Enabled           bool          `yaml:"enabled"`
	ProtectorURL      string        `yaml:"protector_url"`
	ClientID          string        `yaml:"client_id"`
	AgentID           string        `yaml:"agent_id"`
	APIKey            string        `yaml:"api_key"`
	ReconnectDelay    time.Duration `yaml:"reconnect_delay"`
	HeartbeatInterval time.Duration `yaml:"heartbeat_interval"`

	// Collection intervals
	ProcessInterval       time.Duration `yaml:"process_interval"`
	NetworkInterval       time.Duration `yaml:"network_interval"`
	FileIntegrityInterval time.Duration `yaml:"file_integrity_interval"`
	BehaviorInterval      time.Duration `yaml:"behavior_interval"`

	// Alert settings
	AlertOnSuspiciousProcess bool `yaml:"alert_on_suspicious_process"`
	AlertOnNetworkAnomaly    bool `yaml:"alert_on_network_anomaly"`
	AlertOnFileModification  bool `yaml:"alert_on_file_modification"`
	AlertOnHighRiskBehavior  bool `yaml:"alert_on_high_risk_behavior"`
}

// ServiceRegistry interface for accessing other services
type ServiceRegistry interface {
	GetService(name string) (interface{}, error)
}

// Alert represents a security alert to be sent to platform
type Alert struct {
	Type        string                 `json:"type"`
	Severity    string                 `json:"severity"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Source      string                 `json:"source"`
	Metadata    map[string]interface{} `json:"metadata"`
	Timestamp   time.Time              `json:"timestamp"`
}

// TelemetryData represents telemetry data to be sent
type TelemetryData struct {
	DataType  string      `json:"data_type"`
	Data      interface{} `json:"data"`
	Timestamp time.Time   `json:"timestamp"`
}

// Command represents a command from the platform
type Command struct {
	ID        string                 `json:"id"`
	Type      string                 `json:"type"`
	Params    map[string]interface{} `json:"params"`
	Timestamp time.Time              `json:"timestamp"`
}

// CommandResponse represents the response to a command
type CommandResponse struct {
	CommandID string                 `json:"command_id"`
	Success   bool                   `json:"success"`
	Data      map[string]interface{} `json:"data"`
	Error     string                 `json:"error,omitempty"`
	Timestamp time.Time              `json:"timestamp"`
}

// Message types for WebSocket communication
type Message struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
}

// NewService creates a new protector service
func NewService(config *Config, registry ServiceRegistry) *Service {
	ctx, cancel := context.WithCancel(context.Background())

	return &Service{
		config:          config,
		registry:        registry,
		alertQueue:      make(chan Alert, 1000),
		telemetryQueue:  make(chan TelemetryData, 1000),
		commandResponse: make(chan CommandResponse, 100),
		ctx:             ctx,
		cancel:          cancel,
	}
}

// Start initializes the protector service
func (s *Service) Start() error {
	if !s.config.Enabled {
		log.Println("[Protector] Service disabled in configuration")
		return nil
	}

	log.Println("[Protector] Starting service...")

	// Connect to platform
	if err := s.connect(); err != nil {
		log.Printf("[Protector] Failed to connect: %v", err)
		// Start reconnection loop
		go s.reconnectLoop()
	}

	// Start goroutines
	go s.messageReceiver()
	go s.messageSender()
	go s.heartbeatLoop()

	// Start data collectors
	go s.collectProcessData()
	go s.collectNetworkData()
	go s.collectBehaviorData()

	log.Println("[Protector] Service started successfully")
	return nil
}

// Stop gracefully shuts down the service
func (s *Service) Stop() error {
	log.Println("[Protector] Stopping service...")
	s.cancel()

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.conn != nil {
		s.conn.Close(websocket.StatusNormalClosure, "agent shutting down")
	}

	close(s.alertQueue)
	close(s.telemetryQueue)
	close(s.commandResponse)

	log.Println("[Protector] Service stopped")
	return nil
}

// connect establishes WebSocket connection to platform
func (s *Service) connect() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.connected {
		return nil
	}

	log.Printf("[Protector] Connecting to %s...", s.config.ProtectorURL)

	// Build connection URL with auth
	url := fmt.Sprintf("%s?client_id=%s&agent_id=%s&api_key=%s",
		s.config.ProtectorURL,
		s.config.ClientID,
		s.config.AgentID,
		s.config.APIKey,
	)

	conn, _, err := websocket.Dial(s.ctx, url, nil)
	if err != nil {
		return fmt.Errorf("dial failed: %w", err)
	}

	s.conn = conn
	s.connected = true

	log.Println("[Protector] Connected successfully")
	return nil
}

// reconnectLoop handles automatic reconnection
func (s *Service) reconnectLoop() {
	ticker := time.NewTicker(s.config.ReconnectDelay)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			if !s.isConnected() {
				log.Println("[Protector] Attempting to reconnect...")
				if err := s.connect(); err != nil {
					log.Printf("[Protector] Reconnection failed: %v", err)
				}
			}
		}
	}
}

// heartbeatLoop sends periodic heartbeats
func (s *Service) heartbeatLoop() {
	ticker := time.NewTicker(s.config.HeartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			if s.isConnected() {
				s.sendHeartbeat()
			}
		}
	}
}

// sendHeartbeat sends a heartbeat message
func (s *Service) sendHeartbeat() {
	msg := Message{
		Type: "heartbeat",
		Data: json.RawMessage(`{"status":"alive"}`),
	}

	s.mu.RLock()
	conn := s.conn
	s.mu.RUnlock()

	if conn != nil {
		_ = wsjson.Write(s.ctx, conn, msg)
	}
}

// messageReceiver handles incoming messages from platform
func (s *Service) messageReceiver() {
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
			if !s.isConnected() {
				time.Sleep(1 * time.Second)
				continue
			}

			var msg Message
			s.mu.RLock()
			conn := s.conn
			s.mu.RUnlock()

			if err := wsjson.Read(s.ctx, conn, &msg); err != nil {
				log.Printf("[Protector] Read error: %v", err)
				s.setDisconnected()
				continue
			}

			s.handleMessage(msg)
		}
	}
}

// handleMessage processes incoming messages
func (s *Service) handleMessage(msg Message) {
	switch msg.Type {
	case "command":
		var cmd Command
		if err := json.Unmarshal(msg.Data, &cmd); err != nil {
			log.Printf("[Protector] Failed to unmarshal command: %v", err)
			return
		}
		s.executeCommand(cmd)

	case "ping":
		s.sendPong()

	default:
		log.Printf("[Protector] Unknown message type: %s", msg.Type)
	}
}

// executeCommand executes a command from the platform
func (s *Service) executeCommand(cmd Command) {
	log.Printf("[Protector] Executing command: %s (ID: %s)", cmd.Type, cmd.ID)

	response := CommandResponse{
		CommandID: cmd.ID,
		Timestamp: time.Now(),
		Data:      make(map[string]interface{}),
	}

	switch cmd.Type {
	case "kill_process":
		// TODO: Implement process killing
		response.Success = true
		response.Data["message"] = "Process kill not yet implemented"

	case "block_connection":
		// TODO: Implement connection blocking
		response.Success = true
		response.Data["message"] = "Connection blocking not yet implemented"

	case "collect_forensics":
		// TODO: Implement forensics collection
		response.Success = true
		response.Data["message"] = "Forensics collection not yet implemented"

	default:
		response.Success = false
		response.Error = fmt.Sprintf("Unknown command type: %s", cmd.Type)
	}

	s.commandResponse <- response
}

// messageSender sends queued messages to platform
func (s *Service) messageSender() {
	for {
		select {
		case <-s.ctx.Done():
			return

		case alert := <-s.alertQueue:
			s.sendMessage("alert", alert)

		case telemetry := <-s.telemetryQueue:
			s.sendMessage("telemetry", telemetry)

		case response := <-s.commandResponse:
			s.sendMessage("command_response", response)
		}
	}
}

// sendMessage sends a message to the platform
func (s *Service) sendMessage(msgType string, data interface{}) {
	if !s.isConnected() {
		return
	}

	dataJSON, err := json.Marshal(data)
	if err != nil {
		log.Printf("[Protector] Failed to marshal message: %v", err)
		return
	}

	msg := Message{
		Type: msgType,
		Data: dataJSON,
	}

	s.mu.RLock()
	conn := s.conn
	s.mu.RUnlock()

	if conn != nil {
		if err := wsjson.Write(s.ctx, conn, msg); err != nil {
			log.Printf("[Protector] Failed to send message: %v", err)
			s.setDisconnected()
		}
	}
}

// sendPong sends a pong response
func (s *Service) sendPong() {
	msg := Message{
		Type: "pong",
		Data: json.RawMessage(`{}`),
	}

	s.mu.RLock()
	conn := s.conn
	s.mu.RUnlock()

	if conn != nil {
		_ = wsjson.Write(s.ctx, conn, msg)
	}
}

// QueueAlert queues an alert to be sent to the platform
func (s *Service) QueueAlert(alert Alert) {
	if !s.config.Enabled {
		return
	}

	alert.Timestamp = time.Now()
	select {
	case s.alertQueue <- alert:
	default:
		log.Println("[Protector] Alert queue full, dropping alert")
	}
}

// QueueTelemetry queues telemetry data to be sent
func (s *Service) QueueTelemetry(dataType string, data interface{}) {
	if !s.config.Enabled {
		return
	}

	telemetry := TelemetryData{
		DataType:  dataType,
		Data:      data,
		Timestamp: time.Now(),
	}

	select {
	case s.telemetryQueue <- telemetry:
	default:
		log.Println("[Protector] Telemetry queue full, dropping data")
	}
}

// isConnected checks if connected to platform
func (s *Service) isConnected() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.connected
}

// setDisconnected marks the connection as disconnected
func (s *Service) setDisconnected() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.connected = false
	if s.conn != nil {
		s.conn.Close(websocket.StatusInternalError, "")
		s.conn = nil
	}
}

// Data collection methods (stub implementations)

func (s *Service) collectProcessData() {
	ticker := time.NewTicker(s.config.ProcessInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			// TODO: Collect process data from process service
			// For now, send empty placeholder
			s.QueueTelemetry("process_snapshot", map[string]interface{}{
				"processes": []interface{}{},
			})
		}
	}
}

func (s *Service) collectNetworkData() {
	ticker := time.NewTicker(s.config.NetworkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			// TODO: Collect network data from network service
			s.QueueTelemetry("network_snapshot", map[string]interface{}{
				"connections": []interface{}{},
			})
		}
	}
}

func (s *Service) collectBehaviorData() {
	ticker := time.NewTicker(s.config.BehaviorInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			// TODO: Collect behavior data from behavior service
			s.QueueTelemetry("behavior_analysis", map[string]interface{}{
				"risk_score": 0,
			})
		}
	}
}

// Name returns the service name
func (s *Service) Name() string {
	return "protector"
}

// Status returns the service status
func (s *Service) Status() string {
	if s.isConnected() {
		return "connected"
	}
	return "disconnected"
}
