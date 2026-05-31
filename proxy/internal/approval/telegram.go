package approval

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const telegramAPIBase = "https://api.telegram.org"

// Notifier sends one Telegram approval prompt per transaction (idempotent by tx_id).
type Notifier struct {
	token       string
	chatID      string
	allowedTTLs []int
	baseURL     string
	client      *http.Client
	mu          sync.Mutex
	sent        map[string]struct{}
}

// NotifierConfig configures the Telegram Bot API client.
type NotifierConfig struct {
	BotToken          string
	ChatID            string
	AllowedTTLSeconds []int
	BaseURL           string // optional; defaults to telegramAPIBase
	Client            *http.Client
}

// Configured reports whether outbound Telegram notifications can be sent.
func (n *Notifier) Configured() bool {
	return n != nil && n.token != "" && n.chatID != ""
}

// NewNotifier returns a notifier. When BotToken or ChatID is empty, Notify is a no-op.
func NewNotifier(cfg NotifierConfig) *Notifier {
	base := cfg.BaseURL
	if base == "" {
		base = telegramAPIBase
	}
	client := cfg.Client
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	return &Notifier{
		token:       cfg.BotToken,
		chatID:      cfg.ChatID,
		allowedTTLs: cfg.AllowedTTLSeconds,
		baseURL:     base,
		client:      client,
		sent:        make(map[string]struct{}),
	}
}

// Notify sends an approval message with inline Approve/Deny buttons for tx.
// A second call for the same tx.ID does not perform another HTTP request.
func (n *Notifier) Notify(ctx context.Context, tx *Transaction) error {
	if n == nil || tx == nil || n.token == "" || n.chatID == "" {
		return nil
	}

	n.mu.Lock()
	if _, ok := n.sent[tx.ID]; ok {
		n.mu.Unlock()
		return nil
	}
	n.sent[tx.ID] = struct{}{}
	n.mu.Unlock()

	text := fmt.Sprintf(
		"Luna SSH sign request\nUser: %s\nHost: %s\nTx: %s",
		tx.TargetUser, tx.TargetIP, tx.ID,
	)
	body := map[string]any{
		"chat_id": n.chatID,
		"text":    text,
		"reply_markup": map[string]any{
			"inline_keyboard": approvalKeyboard(tx.ID, n.allowedTTLs),
		},
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/bot%s/sendMessage", n.baseURL, n.token)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := n.client.Do(req)
	if err != nil {
		n.forgetSent(tx.ID)
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		slurp, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		n.forgetSent(tx.ID)
		return fmt.Errorf("telegram sendMessage: %s: %s", resp.Status, slurp)
	}
	return nil
}

func approvalKeyboard(txID string, allowedTTLs []int) [][]map[string]string {
	ttls := allowedTTLs
	if len(ttls) == 0 {
		ttls = []int{180, 300, 900}
	}
	row := make([]map[string]string, 0, len(ttls)+1)
	for _, sec := range ttls {
		label := formatTTLLabel(sec)
		row = append(row, map[string]string{
			"text":          label,
			"callback_data": fmt.Sprintf("approve:%s:%d", txID, sec),
		})
	}
	row = append(row, map[string]string{
		"text":          "Deny",
		"callback_data": "deny:" + txID,
	})
	return [][]map[string]string{row}
}

func formatTTLLabel(sec int) string {
	switch {
	case sec%60 == 0 && sec >= 60:
		return fmt.Sprintf("Approve %dm", sec/60)
	default:
		return fmt.Sprintf("Approve %ds", sec)
	}
}

func (n *Notifier) forgetSent(txID string) {
	n.mu.Lock()
	delete(n.sent, txID)
	n.mu.Unlock()
}

// DeleteWebhook clears any Telegram webhook so getUpdates long polling works.
func DeleteWebhook(ctx context.Context, cfg NotifierConfig) error {
	token := strings.TrimSpace(cfg.BotToken)
	if token == "" {
		return fmt.Errorf("telegram bot token not configured")
	}

	base := cfg.BaseURL
	if base == "" {
		base = telegramAPIBase
	}
	client := cfg.Client
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}

	reqURL := fmt.Sprintf("%s/bot%s/deleteWebhook", base, token)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, strings.NewReader("{}"))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	slurp, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("telegram deleteWebhook: %s: %s", resp.Status, slurp)
	}
	var ack struct {
		OK          bool   `json:"ok"`
		Description string `json:"description"`
	}
	if err := json.Unmarshal(slurp, &ack); err != nil {
		return fmt.Errorf("telegram deleteWebhook response: %w", err)
	}
	if !ack.OK {
		if ack.Description != "" {
			return fmt.Errorf("telegram deleteWebhook: %s", ack.Description)
		}
		return fmt.Errorf("telegram deleteWebhook: not ok")
	}
	return nil
}
