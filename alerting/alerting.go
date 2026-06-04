package alerting

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// Alert represents a single alert event.
type Alert struct {
	Timestamp time.Time `json:"timestamp"`
	Level     string    `json:"level"`
	Message   string    `json:"message"`
	Details   string    `json:"details,omitempty"`
}

// Notifier is an interface for alert delivery mechanisms.
type Notifier interface {
	Name() string
	Send(alert Alert) error
}

// WebhookNotifier sends alerts to a HTTP endpoint.
type WebhookNotifier struct {
	URL string
}

func (w *WebhookNotifier) Name() string { return "webhook" }

func (w *WebhookNotifier) Send(alert Alert) error {
	payload, err := json.Marshal(alert)
	if err != nil {
		return fmt.Errorf("marshal alert: %w", err)
	}
	resp, err := http.Post(w.URL, "application/json", bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("webhook POST: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook status: %d", resp.StatusCode)
	}
	return nil
}

// SyslogNotifier logs alerts to stdout (simulates syslog for cross-platform).
type SyslogNotifier struct{}

func (s *SyslogNotifier) Name() string { return "stdout" }

func (s *SyslogNotifier) Send(alert Alert) error {
	fmt.Fprintf(os.Stderr, "[%s] [%s] %s: %s\n",
		alert.Timestamp.Format("2006-01-02 15:04:05"),
		strings.ToUpper(alert.Level),
		s.Name(),
		alert.Message)
	return nil
}

// Registry manages multiple notifiers.
type Registry struct {
	notifiers []Notifier
}

// NewRegistry creates a new alert registry.
func NewRegistry() *Registry {
	return &Registry{}
}

// AddNotifier registers a notifier.
func (r *Registry) AddNotifier(n Notifier) {
	r.notifiers = append(r.notifiers, n)
}

// Send broadcasts an alert to all registered notifiers.
func (r *Registry) Send(alert Alert) {
	for _, n := range r.notifiers {
		if err := n.Send(alert); err != nil {
			fmt.Fprintf(os.Stderr, "alert %s failed: %v\n", n.Name(), err)
		}
	}
}
