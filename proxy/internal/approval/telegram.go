package approval

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

const telegramAPIBase = "https://api.telegram.org"

// Notifier sends one Telegram approval prompt per transaction (idempotent by tx_id).
type Notifier struct {
	token   string
	chatID  string
	baseURL string
	client  *http.Client
	mu      sync.Mutex
	sent    map[string]struct{}
}

// NotifierConfig configures the Telegram Bot API client.
type NotifierConfig struct {
	BotToken string
	ChatID   string
	BaseURL  string // optional; defaults to telegramAPIBase
	Client   *http.Client
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
		token:   cfg.BotToken,
		chatID:  cfg.ChatID,
		baseURL: base,
		client:  client,
		sent:    make(map[string]struct{}),
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
			"inline_keyboard": [][]map[string]string{
				{
					{"text": "Approve", "callback_data": "approve:" + tx.ID},
					{"text": "Deny", "callback_data": "deny:" + tx.ID},
				},
			},
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

func (n *Notifier) forgetSent(txID string) {
	n.mu.Lock()
	delete(n.sent, txID)
	n.mu.Unlock()
}
