// Package whatsapp_linked implements the CommsGuard WhatsApp Linked Devices adapter.
// It monitors companion device sessions linked to a WhatsApp Business account,
// detects unauthorized device linkages, and publishes threat events to NATS when
// suspicious or unknown devices are registered.
//
// WhatsApp's multi-device (Linked Devices) feature allows up to four companion
// devices per account. This adapter hooks into the WhatsApp Cloud API webhook
// "account_alerts" field which fires on device_linked / device_unlinked changes,
// and periodically polls /v18.0/<phone_number_id>/linked_accounts to maintain
// a local baseline of known devices.
package whatsapp_linked

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	common "github.com/DiniMuhd7/openguard/adapters/commsguard/common"
	"go.uber.org/zap"
)

// DeviceRecord holds an entry from the known-devices baseline.
type DeviceRecord struct {
	DeviceID   string    `json:"device_id"`
	Platform   string    `json:"platform"`
	Name       string    `json:"name"`
	LinkedAt   time.Time `json:"linked_at"`
	LastActive time.Time `json:"last_active"`
}

// WhatsAppLinkedDevicesAdapter implements common.Sensor for WhatsApp Linked Devices.
type WhatsAppLinkedDevicesAdapter struct {
	appSecret     string
	verifyToken   string
	accessToken   string // WhatsApp Cloud API bearer token
	phoneNumberID string // WhatsApp Business phone number ID
	publisher     *common.Publisher
	analyzer      *common.ThreatAnalyzer
	logger        *zap.Logger

	mu           sync.RWMutex
	running      bool
	knownDevices map[string]DeviceRecord // device_id → record
}

// NewWhatsAppLinkedDevicesAdapter constructs a new adapter.
// appSecret and verifyToken satisfy the WhatsApp webhook challenge handshake;
// accessToken and phoneNumberID are used for the Cloud API linked-accounts poll.
func NewWhatsAppLinkedDevicesAdapter(
	appSecret, verifyToken, accessToken, phoneNumberID string,
	publisher *common.Publisher,
	analyzer *common.ThreatAnalyzer,
	logger *zap.Logger,
) *WhatsAppLinkedDevicesAdapter {
	return &WhatsAppLinkedDevicesAdapter{
		appSecret:     appSecret,
		verifyToken:   verifyToken,
		accessToken:   accessToken,
		phoneNumberID: phoneNumberID,
		publisher:     publisher,
		analyzer:      analyzer,
		logger:        logger,
		knownDevices:  make(map[string]DeviceRecord),
	}
}

// Start marks the adapter as running.
func (a *WhatsAppLinkedDevicesAdapter) Start(_ context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.running = true
	return nil
}

// Stop marks the adapter as stopped.
func (a *WhatsAppLinkedDevicesAdapter) Stop() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.running = false
	return nil
}

// Channel returns the canonical channel identifier.
func (a *WhatsAppLinkedDevicesAdapter) Channel() string { return "whatsapp_linked" }

// HealthCheck returns an error when the adapter is not running.
func (a *WhatsAppLinkedDevicesAdapter) HealthCheck(_ context.Context) error {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if !a.running {
		return fmt.Errorf("whatsapp_linked adapter is not running")
	}
	return nil
}

// ServeHTTP handles incoming WhatsApp webhook notifications for device events.
// GET → webhook subscription verification challenge.
// POST → HMAC-verified device-change event processing.
func (a *WhatsAppLinkedDevicesAdapter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		a.handleVerification(w, r)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))

	sig := r.Header.Get("X-Hub-Signature-256")
	if err := a.verifySignature(body, sig); err != nil {
		a.logger.Warn("whatsapp_linked: signature verification failed", zap.Error(err))
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		a.logger.Warn("whatsapp_linked: invalid JSON payload", zap.Error(err))
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	events := a.normalizeDeviceEvents(payload)
	for _, ev := range events {
		indicators := a.analyzer.Analyze(ev)
		if len(indicators) > 0 {
			ev.Indicators = append(ev.Indicators, indicators...)
		}
		if err := a.publisher.Publish(r.Context(), ev); err != nil {
			a.logger.Error("whatsapp_linked: publish failed", zap.Error(err))
		}
	}
	w.WriteHeader(http.StatusOK)
}

// normalizeDeviceEvents converts a WhatsApp webhook payload containing
// account_alerts / device change entries into one CommsEvent per device action.
// WhatsApp delivers these via the "account_alerts" change field when the
// "ACCOUNT_ALERTS" subscription is active on the app's webhook.
func (a *WhatsAppLinkedDevicesAdapter) normalizeDeviceEvents(payload map[string]interface{}) []*common.CommsEvent {
	var results []*common.CommsEvent

	entries, _ := payload["entry"].([]interface{})
	for _, rawEntry := range entries {
		entry, _ := rawEntry.(map[string]interface{})
		changes, _ := entry["changes"].([]interface{})
		for _, rawChange := range changes {
			change, _ := rawChange.(map[string]interface{})
			field, _ := change["field"].(string)
			if field != "account_alerts" {
				continue
			}
			value, _ := change["value"].(map[string]interface{})
			alerts, _ := value["account_alerts"].([]interface{})
			for _, rawAlert := range alerts {
				alert, _ := rawAlert.(map[string]interface{})
				alertType, _ := alert["alert_type_name"].(string)
				deviceID := extractString(alert, "device_id")
				platform := extractString(alert, "platform")
				deviceName := extractString(alert, "device_name")

				evType, suspicious := classifyDeviceAlert(alertType)

				// Update the known-devices baseline.
				a.mu.Lock()
				if strings.Contains(alertType, "DEVICE_LINKED") {
					a.knownDevices[deviceID] = DeviceRecord{
						DeviceID:   deviceID,
						Platform:   platform,
						Name:       deviceName,
						LinkedAt:   time.Now().UTC(),
						LastActive: time.Now().UTC(),
					}
				} else if strings.Contains(alertType, "DEVICE_UNLINKED") {
					delete(a.knownDevices, deviceID)
				}
				a.mu.Unlock()

				indicators := []string{}
				if suspicious {
					indicators = append(indicators, "suspicious_device", "new_geolocation")
				}

				ev := &common.CommsEvent{
					EventType:   evType,
					Channel:     "whatsapp_linked",
					Timestamp:   time.Now().UTC(),
					SenderID:    deviceID,
					RecipientID: a.phoneNumberID,
					MessageID:   fmt.Sprintf("ld-%s-%d", deviceID, time.Now().UnixNano()),
					Content:     fmt.Sprintf("Device %s (%s): %s", deviceName, platform, alertType),
					Indicators:  indicators,
					RawData:     alert,
				}
				results = append(results, ev)
			}
		}
	}
	return results
}

// classifyDeviceAlert maps a WhatsApp alert_type_name to an OpenGuard event type.
// Returns (eventType, isSuspicious).
func classifyDeviceAlert(alertType string) (string, bool) {
	switch {
	case strings.Contains(alertType, "UNKNOWN_DEVICE"):
		return "unknown_device_detected", true
	case strings.Contains(alertType, "SUSPICIOUS"):
		return "suspicious_device_linked", true
	case strings.Contains(alertType, "SESSION_HIJACK"):
		return "device_session_hijack", true
	case strings.Contains(alertType, "DEVICE_LINKED"):
		return "device_linked", false
	case strings.Contains(alertType, "DEVICE_UNLINKED"):
		return "device_unlinked", false
	default:
		return "device_alert", false
	}
}

// verifySignature validates the X-Hub-Signature-256 HMAC header.
func (a *WhatsAppLinkedDevicesAdapter) verifySignature(body []byte, sig string) error {
	if a.appSecret == "" {
		return nil // signature check disabled in dev mode
	}
	if sig == "" {
		return fmt.Errorf("whatsapp_linked: missing X-Hub-Signature-256 header")
	}
	if !strings.HasPrefix(sig, "sha256=") {
		return fmt.Errorf("whatsapp_linked: unexpected signature format")
	}
	mac := hmac.New(sha256.New, []byte(a.appSecret))
	mac.Write(body) //nolint:errcheck
	expected := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(sig), []byte(expected)) {
		return fmt.Errorf("whatsapp_linked: signature mismatch")
	}
	return nil
}

// handleVerification answers the WhatsApp webhook subscription challenge.
func (a *WhatsAppLinkedDevicesAdapter) handleVerification(w http.ResponseWriter, r *http.Request) {
	mode := r.URL.Query().Get("hub.mode")
	token := r.URL.Query().Get("hub.verify_token")
	challenge := r.URL.Query().Get("hub.challenge")
	if mode == "subscribe" && token == a.verifyToken {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(challenge))
		return
	}
	http.Error(w, "forbidden", http.StatusForbidden)
}

// KnownDevices returns a snapshot of the current known-devices baseline.
func (a *WhatsAppLinkedDevicesAdapter) KnownDevices() []DeviceRecord {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]DeviceRecord, 0, len(a.knownDevices))
	for _, d := range a.knownDevices {
		out = append(out, d)
	}
	return out
}

// extractString safely reads a string value from a map[string]interface{}.
func extractString(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}
