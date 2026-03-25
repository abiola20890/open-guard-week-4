// Package consoleapi — commsguard_tg.go implements the Telegram Bot live
// session for CommsGuard.
//
// Unlike the WhatsApp integration (which uses the multi-device companion
// protocol with QR-code pairing), Telegram operates through the official
// Bot API. A bot token must be provided via the OPENGUARD_TELEGRAM_BOT_TOKEN
// environment variable. When the token is present the session auto-starts
// long-polling on startup; the connect/disconnect endpoints allow manual
// control from the UI.
//
// Security note: the bot token is treated as a secret — it is never echoed
// in API responses. Store it using a secrets manager or injected environment
// variable in production.
package consoleapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"go.uber.org/zap"
)

// ─── State types ──────────────────────────────────────────────────────────────

// TGSessionState is the connection state of the Telegram bot session.
type TGSessionState string

const (
	TGStateDisconnected TGSessionState = "disconnected"
	TGStateConnecting   TGSessionState = "connecting"
	TGStatePolling      TGSessionState = "polling"
)

// ─── Message types ────────────────────────────────────────────────────────────

// TGMessage is an intercepted Telegram message stored in the ring buffer.
type TGMessage struct {
	ID        string   `json:"id"`
	ChatID    int64    `json:"chat_id"`
	ChatTitle string   `json:"chat_title,omitempty"` // populated for groups/channels
	Sender    string   `json:"sender"`               // display name of sender
	Username  string   `json:"username,omitempty"`   // @handle, if any
	Content   string   `json:"content"`
	Timestamp string   `json:"timestamp"` // RFC3339
	IsGroup   bool     `json:"is_group"`
	IsFlagged bool     `json:"is_flagged"`
	Threats   []string `json:"threats"`
}

// ─── Response shapes ──────────────────────────────────────────────────────────

// TGStatusResponse is the JSON body returned by the Telegram status endpoint.
type TGStatusResponse struct {
	State          TGSessionState `json:"state"`
	BotUsername    string         `json:"bot_username,omitempty"`
	BotID          int64          `json:"bot_id,omitempty"`
	ConnectedSince string         `json:"connected_since,omitempty"` // RFC3339
	MessageCount   int            `json:"message_count"`
}

// TGMessagesResponse is the JSON body returned by the Telegram messages endpoint.
type TGMessagesResponse struct {
	Messages []TGMessage `json:"messages"`
	Total    int         `json:"total"`
}

// ─── Internal Telegram Bot API types ─────────────────────────────────────────

type tgGetMeResult struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
}

type tgGetMeResp struct {
	OK     bool          `json:"ok"`
	Result tgGetMeResult `json:"result"`
}

type tgUpdateMessage struct {
	MessageID int   `json:"message_id"`
	Date      int64 `json:"date"`
	From      *struct {
		ID        int64  `json:"id"`
		FirstName string `json:"first_name"`
		LastName  string `json:"last_name,omitempty"`
		Username  string `json:"username,omitempty"`
	} `json:"from"`
	Chat struct {
		ID    int64  `json:"id"`
		Title string `json:"title,omitempty"`
		Type  string `json:"type"` // "private","group","supergroup","channel"
	} `json:"chat"`
	Text string `json:"text,omitempty"`
}

type tgRawUpdate struct {
	UpdateID int              `json:"update_id"`
	Message  *tgUpdateMessage `json:"message"`
}

type tgGetUpdatesResp struct {
	OK     bool          `json:"ok"`
	Result []tgRawUpdate `json:"result"`
}

// ─── Session constants ────────────────────────────────────────────────────────

const (
	tgMaxMessages  = 50
	tgAPIBase      = "https://api.telegram.org/bot"
	tgPollTimeout  = 25 // seconds — Telegram long-poll timeout
	tgClientTimout = 35 * time.Second
	tgQuickTimeout = 10 * time.Second
)

// ─── Session manager ──────────────────────────────────────────────────────────

// tgSession manages a Telegram Bot API long-polling session.
// All exported state is protected by mu; the message ring-buffer uses msgMu.
type tgSession struct {
	mu sync.RWMutex

	botToken    string
	botUsername string
	botID       int64

	state          TGSessionState
	connectedSince time.Time
	lastUpdateID   int

	// lifecycle context — set by Start(); held so connect() can start goroutines
	// that outlive individual HTTP request contexts.
	ctx        context.Context    //nolint:containedctx
	pollCancel context.CancelFunc // cancels the current poll goroutine

	msgMu    sync.RWMutex
	messages []TGMessage // ring buffer, newest at end

	logger     *zap.Logger
	httpClient *http.Client // long-poll client (35s timeout)
}

// newTGSession creates a tgSession.  The bot token is read from the
// OPENGUARD_TELEGRAM_BOT_TOKEN environment variable at construction time.
func newTGSession(logger *zap.Logger) *tgSession {
	return &tgSession{
		botToken:   os.Getenv("OPENGUARD_TELEGRAM_BOT_TOKEN"),
		state:      TGStateDisconnected,
		logger:     logger,
		messages:   make([]TGMessage, 0, tgMaxMessages),
		httpClient: &http.Client{Timeout: tgClientTimout},
	}
}

// Start stores the lifecycle context and auto-starts polling when a token is
// configured.  It should be called in a goroutine.
func (ts *tgSession) Start(ctx context.Context) {
	ts.mu.Lock()
	ts.ctx = ctx
	ts.mu.Unlock()

	if ts.botToken == "" {
		ts.logger.Info("telegram: no bot token configured — session inactive (set OPENGUARD_TELEGRAM_BOT_TOKEN to enable)")
		return
	}
	if err := ts.connect(); err != nil {
		ts.logger.Warn("telegram: auto-connect on startup failed", zap.Error(err))
	}
}

// Stop cancels the active poll goroutine.
func (ts *tgSession) Stop() {
	ts.mu.Lock()
	cancel := ts.pollCancel
	ts.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// connect verifies the bot token with getMe, then starts long-polling.
// It is idempotent — calling it while already polling is a no-op.
func (ts *tgSession) connect() error {
	ts.mu.Lock()
	if ts.state == TGStatePolling {
		ts.mu.Unlock()
		return nil
	}
	if ts.botToken == "" {
		ts.mu.Unlock()
		return fmt.Errorf("no Telegram bot token configured (OPENGUARD_TELEGRAM_BOT_TOKEN)")
	}
	parentCtx := ts.ctx
	ts.state = TGStateConnecting
	ts.mu.Unlock()

	// Verify the token with a quick getMe call.
	info, err := ts.getMe(parentCtx)
	if err != nil {
		ts.mu.Lock()
		ts.state = TGStateDisconnected
		ts.mu.Unlock()
		return fmt.Errorf("telegram: getMe: %w", err)
	}

	ts.mu.Lock()
	ts.botUsername = info.Username
	ts.botID = info.ID
	ts.state = TGStatePolling
	ts.connectedSince = time.Now()
	// Cancel any previous poll goroutine before starting a new one.
	if ts.pollCancel != nil {
		ts.pollCancel()
	}
	pollCtx, cancel := context.WithCancel(parentCtx)
	ts.pollCancel = cancel
	ts.mu.Unlock()

	ts.logger.Info("telegram: bot session started",
		zap.String("username", info.Username),
		zap.Int64("id", info.ID),
	)
	go ts.pollLoop(pollCtx)
	return nil
}

// disconnect stops long-polling and resets session state.
func (ts *tgSession) disconnect() {
	ts.mu.Lock()
	cancel := ts.pollCancel
	ts.pollCancel = nil
	ts.state = TGStateDisconnected
	ts.botUsername = ""
	ts.botID = 0
	ts.connectedSince = time.Time{}
	ts.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	ts.logger.Info("telegram: session disconnected")
}

// ─── Bot API helpers ──────────────────────────────────────────────────────────

func (ts *tgSession) apiURL(method string) string {
	ts.mu.RLock()
	token := ts.botToken
	ts.mu.RUnlock()
	return tgAPIBase + token + "/" + method
}

// getMe fetches bot identity from Telegram.
func (ts *tgSession) getMe(ctx context.Context) (*tgGetMeResult, error) {
	ctx2, cancel := context.WithTimeout(ctx, tgQuickTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx2, http.MethodGet, ts.apiURL("getMe"), nil)
	if err != nil {
		return nil, err
	}
	// Use a temporary client with a short timeout for quick calls.
	resp, err := (&http.Client{Timeout: tgQuickTimeout + time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var r tgGetMeResp
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("decode getMe: %w", err)
	}
	if !r.OK {
		return nil, fmt.Errorf("getMe returned ok=false — check bot token")
	}
	return &r.Result, nil
}

// ─── Long-poll loop ───────────────────────────────────────────────────────────

func (ts *tgSession) pollLoop(ctx context.Context) {
	ts.logger.Info("telegram: long-poll loop started")
	for {
		if ctx.Err() != nil {
			ts.mu.Lock()
			if ts.state == TGStatePolling {
				ts.state = TGStateDisconnected
			}
			ts.mu.Unlock()
			return
		}
		if err := ts.pollOnce(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			ts.logger.Warn("telegram: poll error — retrying in 5s", zap.Error(err))
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
		}
	}
}

// pollOnce performs a single getUpdates long-poll request.
func (ts *tgSession) pollOnce(ctx context.Context) error {
	ts.mu.RLock()
	offset := ts.lastUpdateID + 1
	ts.mu.RUnlock()

	url := fmt.Sprintf("%s?offset=%d&timeout=%d", ts.apiURL("getUpdates"), offset, tgPollTimeout)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := ts.httpClient.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil // expected on context cancellation
		}
		return err
	}
	defer resp.Body.Close()

	var upd tgGetUpdatesResp
	if err := json.NewDecoder(resp.Body).Decode(&upd); err != nil {
		return fmt.Errorf("decode getUpdates: %w", err)
	}
	if !upd.OK {
		return fmt.Errorf("getUpdates returned ok=false")
	}

	for i := range upd.Result {
		update := &upd.Result[i]
		ts.mu.Lock()
		if update.UpdateID > ts.lastUpdateID {
			ts.lastUpdateID = update.UpdateID
		}
		ts.mu.Unlock()

		if update.Message != nil {
			ts.ingestMessage(update.Message)
		}
	}
	return nil
}

// ingestMessage converts a raw Telegram message to a TGMessage and appends it
// to the ring buffer.
func (ts *tgSession) ingestMessage(msg *tgUpdateMessage) {
	sender := ""
	username := ""
	if msg.From != nil {
		sender = msg.From.FirstName
		if msg.From.LastName != "" {
			sender += " " + msg.From.LastName
		}
		username = msg.From.Username
	}
	isGroup := msg.Chat.Type == "group" || msg.Chat.Type == "supergroup"

	content := msg.Text
	if runes := []rune(content); len(runes) > 500 {
		content = string(runes[:500])
	}

	tgMsg := TGMessage{
		ID:        fmt.Sprintf("tg-%d-%d", msg.Chat.ID, msg.MessageID),
		ChatID:    msg.Chat.ID,
		ChatTitle: msg.Chat.Title,
		Sender:    sender,
		Username:  username,
		Content:   content,
		Timestamp: time.Unix(msg.Date, 0).UTC().Format(time.RFC3339),
		IsGroup:   isGroup,
		IsFlagged: false,
		Threats:   []string{},
	}

	ts.msgMu.Lock()
	if len(ts.messages) >= tgMaxMessages {
		ts.messages = ts.messages[1:]
	}
	ts.messages = append(ts.messages, tgMsg)
	ts.msgMu.Unlock()

	ts.logger.Info("telegram: message intercepted",
		zap.String("id", tgMsg.ID),
		zap.String("sender", sender),
		zap.Bool("is_group", isGroup),
	)
}

// ─── State accessors ──────────────────────────────────────────────────────────

// Status returns a snapshot of the current session state.
func (ts *tgSession) Status() TGStatusResponse {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	ts.msgMu.RLock()
	msgCount := len(ts.messages)
	ts.msgMu.RUnlock()

	r := TGStatusResponse{
		State:        ts.state,
		BotUsername:  ts.botUsername,
		BotID:        ts.botID,
		MessageCount: msgCount,
	}
	if !ts.connectedSince.IsZero() {
		r.ConnectedSince = ts.connectedSince.UTC().Format(time.RFC3339)
	}
	return r
}

// Messages returns the ring buffer contents, newest first.
func (ts *tgSession) Messages() TGMessagesResponse {
	ts.msgMu.RLock()
	defer ts.msgMu.RUnlock()
	msgs := make([]TGMessage, len(ts.messages))
	copy(msgs, ts.messages)
	// Reverse to newest-first.
	for i, j := 0, len(msgs)-1; i < j; i, j = i+1, j-1 {
		msgs[i], msgs[j] = msgs[j], msgs[i]
	}
	return TGMessagesResponse{Messages: msgs, Total: len(msgs)}
}

// ─── HTTP handlers ────────────────────────────────────────────────────────────

// handleTGStatus returns the current Telegram bot session state.
// GET /api/v1/commsguard/telegram/status
func (s *Server) handleTGStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if s.tgSession == nil {
		_ = json.NewEncoder(w).Encode(TGStatusResponse{State: TGStateDisconnected})
		return
	}
	_ = json.NewEncoder(w).Encode(s.tgSession.Status())
}

// handleTGMessages returns the intercepted Telegram message ring-buffer (newest first).
// GET /api/v1/commsguard/telegram/messages
func (s *Server) handleTGMessages(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if s.tgSession == nil {
		_ = json.NewEncoder(w).Encode(TGMessagesResponse{Messages: []TGMessage{}, Total: 0})
		return
	}
	_ = json.NewEncoder(w).Encode(s.tgSession.Messages())
}

// handleTGConnect starts or resumes the Telegram bot polling session.
// POST /api/v1/commsguard/telegram/connect
func (s *Server) handleTGConnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.tgSession == nil {
		http.Error(w, "telegram session unavailable", http.StatusServiceUnavailable)
		return
	}
	if err := s.tgSession.connect(); err != nil {
		if s.tgSession.Status().State == TGStatePolling {
			// Already polling — treat as success.
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "polling"})
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "polling"})
}

// handleTGDisconnect stops the Telegram bot polling session.
// POST /api/v1/commsguard/telegram/disconnect
func (s *Server) handleTGDisconnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.tgSession != nil {
		s.tgSession.disconnect()
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "disconnected"})
}
