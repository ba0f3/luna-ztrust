package approval

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ba0f3/luna-ztrust/proxy/internal/lease"
)

const defaultPollTimeout = 30 * time.Second

// PollerConfig configures Telegram long polling for inline approve/deny callbacks.
type PollerConfig struct {
	NotifierConfig
	Store       *Store
	PollTimeout time.Duration
	// LogEvent logs poll lifecycle events (route, tx_id, outcome, detail).
	LogEvent func(route, txID, outcome, detail string)
}

// Poller receives Telegram callback_query updates via getUpdates (outbound long poll).
type Poller struct {
	token       string
	chatID      string
	allowedTTLs []int
	baseURL     string
	client      *http.Client
	store       *Store
	pollTimeout time.Duration
	offset      int64
	logEvent    func(route, txID, outcome, detail string)
}

// NewPoller returns a poller. When BotToken is empty, Run is a no-op.
func NewPoller(cfg PollerConfig) *Poller {
	base := cfg.BaseURL
	if base == "" {
		base = telegramAPIBase
	}
	timeout := cfg.PollTimeout
	if timeout <= 0 {
		timeout = defaultPollTimeout
	}
	client := cfg.Client
	if client == nil {
		client = &http.Client{Timeout: timeout + 15*time.Second}
	}
	logEvent := cfg.LogEvent
	if logEvent == nil {
		logEvent = func(route, txID, outcome, detail string) {
			if detail != "" {
				log.Printf("telegram %s tx_id=%s outcome=%s detail=%s", route, txID, outcome, detail)
				return
			}
			log.Printf("telegram %s tx_id=%s outcome=%s", route, txID, outcome)
		}
	}
	return &Poller{
		token:       strings.TrimSpace(cfg.BotToken),
		chatID:      strings.TrimSpace(cfg.ChatID),
		allowedTTLs: cfg.AllowedTTLSeconds,
		baseURL:     base,
		client:      client,
		store:       cfg.Store,
		pollTimeout: timeout,
		logEvent:    logEvent,
	}
}

// Run long-polls Telegram until ctx is cancelled. Clears any webhook on start.
func (p *Poller) Run(ctx context.Context) {
	if p == nil || p.token == "" || p.store == nil {
		return
	}
	if err := DeleteWebhook(ctx, NotifierConfig{
		BotToken: p.token,
		BaseURL:  p.baseURL,
		Client:   p.client,
	}); err != nil {
		p.logEvent("poll", "", "delete_webhook_failed", err.Error())
	} else {
		p.logEvent("poll", "", "started", fmt.Sprintf("timeout=%s", p.pollTimeout))
	}

	for {
		if ctx.Err() != nil {
			return
		}
		if err := p.pollOnce(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			p.logEvent("poll", "", "error", err.Error())
			select {
			case <-ctx.Done():
				return
			case <-time.After(3 * time.Second):
			}
		}
	}
}

func (p *Poller) pollOnce(ctx context.Context) error {
	q := url.Values{}
	q.Set("timeout", fmt.Sprintf("%d", int(p.pollTimeout.Seconds())))
	q.Set("allowed_updates", `["callback_query"]`)
	if p.offset > 0 {
		q.Set("offset", fmt.Sprintf("%d", p.offset))
	}

	reqURL := fmt.Sprintf("%s/bot%s/getUpdates?%s", p.baseURL, p.token, q.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return err
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("telegram getUpdates: %s: %s", resp.Status, body)
	}

	var ack struct {
		OK     bool             `json:"ok"`
		Result []telegramUpdate `json:"result"`
	}
	if err := json.Unmarshal(body, &ack); err != nil {
		return fmt.Errorf("telegram getUpdates response: %w", err)
	}
	if !ack.OK {
		return fmt.Errorf("telegram getUpdates: not ok")
	}

	for _, upd := range ack.Result {
		if upd.UpdateID >= p.offset {
			p.offset = upd.UpdateID + 1
		}
		p.handleUpdate(ctx, upd)
	}
	return nil
}

type telegramUpdate struct {
	UpdateID      int64                  `json:"update_id"`
	CallbackQuery *telegramCallbackQuery `json:"callback_query"`
}

type telegramCallbackQuery struct {
	ID      string           `json:"id"`
	Data    string           `json:"data"`
	Message *telegramMessage `json:"message"`
}

type telegramMessage struct {
	Chat telegramChat `json:"chat"`
}

type telegramChat struct {
	ID int64 `json:"id"`
}

func (p *Poller) handleUpdate(ctx context.Context, upd telegramUpdate) {
	cq := upd.CallbackQuery
	if cq == nil || cq.Data == "" {
		return
	}
	defer func() {
		_ = p.answerCallbackQuery(ctx, cq.ID, "")
	}()

	action, txID, ttl, ok := ParseCallbackData(cq.Data, p.allowedTTLs)
	if !ok {
		p.logEvent("poll", "", "ignored_callback", cq.Data)
		return
	}

	chatID := int64(0)
	if cq.Message != nil {
		chatID = cq.Message.Chat.ID
	}
	if cq.Message == nil || !ChatAllowed(p.chatID, chatID) {
		p.logEvent("poll", txID, "ignored_chat", fmt.Sprintf("chat_id=%d", chatID))
		return
	}

	switch action {
	case "approve":
		if ttl <= 0 {
			ttl = DefaultTTLFromAllowed(p.allowedTTLs)
		}
		approver := lease.FormatApproverChatID(chatID)
		p.store.Approve(txID, ttl, approver)
		p.logEvent("poll", txID, "approved", fmt.Sprintf("ttl=%s", ttl))
	case "deny":
		p.store.Deny(txID)
		p.logEvent("poll", txID, "denied", "")
	}
}

func (p *Poller) answerCallbackQuery(ctx context.Context, callbackQueryID, text string) error {
	if callbackQueryID == "" {
		return nil
	}
	payload := map[string]string{
		"callback_query_id": callbackQueryID,
	}
	if text != "" {
		payload["text"] = text
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	reqURL := fmt.Sprintf("%s/bot%s/answerCallbackQuery", p.baseURL, p.token)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, strings.NewReader(string(raw)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		slurp, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("telegram answerCallbackQuery: %s: %s", resp.Status, slurp)
	}
	return nil
}
