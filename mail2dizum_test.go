package main

import (
	"testing"
	"time"
)

func TestBuildEnvelopeRecipient(t *testing.T) {
	now := time.Date(2026, time.August, 19, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name      string
		server    string
		newsgroup string
		antispam  bool
		want      string
		wantErr   bool
	}{
		{
			name:      "restricted relay single group",
			server:    RESTRICTED_SMTP_RELAY,
			newsgroup: "it.test",
			want:      "mail2news-20260819-it.test@" + MAIL2NEWS_INGRESS_DOMAIN,
		},
		{
			name:      "restricted relay multiple normalized groups",
			server:    RESTRICTED_SMTP_RELAY,
			newsgroup: "IT.Test, it.politica",
			want:      "mail2news-20260819-it.test=it.politica@" + MAIL2NEWS_INGRESS_DOMAIN,
		},
		{
			name:      "custom relay legacy recipient",
			server:    "exampleonionaddress.onion:25",
			newsgroup: "it.test",
			want:      "mail2news@dizum.com",
		},
		{
			name:      "custom relay legacy antispam recipient",
			server:    "exampleonionaddress.onion:25",
			newsgroup: "it.test",
			antispam:  true,
			want:      "mail2news_nospam@dizum.com",
		},
		{
			name:      "restricted relay rejects unsupported antispam",
			server:    RESTRICTED_SMTP_RELAY,
			newsgroup: "it.test",
			antispam:  true,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := buildEnvelopeRecipient(tt.server, tt.newsgroup, tt.antispam, now)
			if (err != nil) != tt.wantErr {
				t.Fatalf("buildEnvelopeRecipient() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("buildEnvelopeRecipient() = %q, want %q", got, tt.want)
			}
		})
	}
}
