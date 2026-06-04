package alerting

import (
	"testing"
	"time"
)

func TestWebhookNotifier_Name(t *testing.T) {
	w := &WebhookNotifier{URL: "http://example.com/alert"}
	if w.Name() != "webhook" {
		t.Errorf("expected 'webhook', got '%s'", w.Name())
	}
}

func TestSyslogNotifier_Name(t *testing.T) {
	s := &SyslogNotifier{}
	if s.Name() != "stdout" {
		t.Errorf("expected 'stdout', got '%s'", s.Name())
	}
}

func TestRegistry_Send(t *testing.T) {
	reg := NewRegistry()
	reg.AddNotifier(&SyslogNotifier{})
	alert := Alert{
		Timestamp: time.Now(),
		Level:     "critical",
		Message:   "test alert",
	}
	// Should not panic
	reg.Send(alert)
}

func TestRegistry_MultipleNotifiers(t *testing.T) {
	reg := NewRegistry()
	reg.AddNotifier(&SyslogNotifier{})
	reg.AddNotifier(&WebhookNotifier{URL: "http://localhost:9999"})
	alert := Alert{
		Timestamp: time.Now(),
		Level:     "high",
		Message:   "multi notifier test",
	}
	// Should not panic even if webhook fails
	reg.Send(alert)
}
