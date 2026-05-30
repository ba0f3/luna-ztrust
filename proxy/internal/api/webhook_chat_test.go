package api

import "testing"

func TestTelegramChatAllowed(t *testing.T) {
	t.Parallel()
	cases := []struct {
		cfg  string
		chat int64
		want bool
	}{
		{"4242", 4242, true},
		{"4242", 4243, false},
		{"", 4242, false},
		{" 99 ", 99, true},
		{"not-a-number", 1, false},
	}
	for _, tc := range cases {
		if got := telegramChatAllowed(tc.cfg, tc.chat); got != tc.want {
			t.Errorf("telegramChatAllowed(%q, %d) = %v, want %v", tc.cfg, tc.chat, got, tc.want)
		}
	}
}
