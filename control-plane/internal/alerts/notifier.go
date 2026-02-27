// Package alerts sends DDoS attack notifications to external channels.
//
// Supported channels:
// - Discord Webhooks
// - Telegram Bot API
// - Generic Webhooks (Slack, PagerDuty, etc.)
// - Stdout logging (always enabled)
package alerts

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"go.uber.org/zap"
)

// Notifier dispatches alert messages to configured channels.
type Notifier struct {
	logger         *zap.SugaredLogger
	discordWebhook string
	telegramToken  string
	telegramChatID string
	httpClient     *http.Client
}

// Config for alert channels.
type Config struct {
	DiscordWebhook   string
	TelegramBotToken string
	TelegramChatID   string
}

// NewNotifier creates a new alert notifier.
func NewNotifier(cfg Config, logger *zap.SugaredLogger) *Notifier {
	return &Notifier{
		logger:         logger,
		discordWebhook: cfg.DiscordWebhook,
		telegramToken:  cfg.TelegramBotToken,
		telegramChatID: cfg.TelegramChatID,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// RunAlertLoop consumes messages from the alert channel and dispatches them.
func (n *Notifier) RunAlertLoop(ctx context.Context, alertCh <-chan string) {
	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-alertCh:
			n.Send(msg)
		}
	}
}

// Send dispatches an alert message to all configured channels.
func (n *Notifier) Send(message string) {
	// Always log
	n.logger.Infow("📢 Alert", "message", message)

	// Discord
	if n.discordWebhook != "" {
		go n.sendDiscord(message)
	}

	// Telegram
	if n.telegramToken != "" && n.telegramChatID != "" {
		go n.sendTelegram(message)
	}
}

// sendDiscord sends a message via Discord webhook.
func (n *Notifier) sendDiscord(message string) {
	payload := map[string]interface{}{
		"content": nil,
		"embeds": []map[string]interface{}{
			{
				"title":       "🛡️ AegisShield Alert",
				"description": message,
				"color":       16711680, // Red
				"timestamp":   time.Now().UTC().Format(time.RFC3339),
				"footer": map[string]string{
					"text": "AegisShield DDoS Protection",
				},
			},
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		n.logger.Errorw("Failed to marshal Discord payload", "error", err)
		return
	}

	resp, err := n.httpClient.Post(n.discordWebhook, "application/json", bytes.NewReader(body))
	if err != nil {
		n.logger.Errorw("Failed to send Discord alert", "error", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		n.logger.Warnw("Discord webhook returned error", "status", resp.StatusCode)
	}
}

// sendTelegram sends a message via Telegram Bot API.
func (n *Notifier) sendTelegram(message string) {
	url := fmt.Sprintf(
		"https://api.telegram.org/bot%s/sendMessage",
		n.telegramToken,
	)

	payload := map[string]interface{}{
		"chat_id":    n.telegramChatID,
		"text":       fmt.Sprintf("🛡️ *AegisShield Alert*\n\n%s", message),
		"parse_mode": "Markdown",
	}

	body, err := json.Marshal(payload)
	if err != nil {
		n.logger.Errorw("Failed to marshal Telegram payload", "error", err)
		return
	}

	resp, err := n.httpClient.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		n.logger.Errorw("Failed to send Telegram alert", "error", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		n.logger.Warnw("Telegram API returned error", "status", resp.StatusCode)
	}
}
