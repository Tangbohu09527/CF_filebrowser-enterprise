package filebridge

import (
	"encoding/json"
	"io"
	"os"
	"sync"
	"time"
)

type AuditLogger struct {
	writer io.Writer
	closer io.Closer
	mu     sync.Mutex
}

type AuditEvent struct {
	Timestamp   string `json:"timestamp"`
	OperationID string `json:"operation_id"`
	RequestID   string `json:"request_id"`
	Command     string `json:"command"`
	Source      string `json:"source,omitempty"`
	Path        string `json:"path,omitempty"`
	Result      string `json:"result"`
	HTTPStatus  int    `json:"http_status,omitempty"`
	DurationMS  int64  `json:"duration_ms"`
	Bytes       int64  `json:"bytes"`
	DryRun      bool   `json:"dry_run"`
}

func NewAuditLogger(config *Config, fallback io.Writer) (*AuditLogger, error) {
	if config.AuditLog == "" {
		return &AuditLogger{writer: fallback}, nil
	}
	file, err := os.OpenFile(config.AuditLog, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return nil, bridgeError("audit_unavailable", "cannot open audit_log")
	}
	return &AuditLogger{writer: file, closer: file}, nil
}

func (l *AuditLogger) Log(event AuditEvent) error {
	if l == nil || l.writer == nil {
		return bridgeError("audit_unavailable", "audit logger is not configured")
	}
	event.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	data, err := json.Marshal(event)
	if err != nil {
		return bridgeError("audit_failed", "could not encode audit event")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, err := l.writer.Write(append(data, '\n')); err != nil {
		return bridgeError("audit_failed", "could not write audit event")
	}
	return nil
}

func (l *AuditLogger) Close() error {
	if l == nil || l.closer == nil {
		return nil
	}
	return l.closer.Close()
}
