package github

import (
	"context"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func TestInstallationToken(t *testing.T) {
	if testing.Short() {
		t.Skip("creates a real token; -short skips it")
	}

	path := os.Getenv("GH_APP_KEY_FILE")
	if path == "" {
		t.Skip("set GH_APP_KEY_FILE to the App private key")
	}

	pemBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ParsePrivateKey(pemBytes)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	client := GitHubClient{
		AppID:      os.Getenv("GH_APP_ID"),
		PrivateKey: key,
		Client:     http.DefaultClient,
	}

	installation, err := InstallationIDFromString(os.Getenv("GH_APP_INSTALLATION_ID"))
	if err != nil {
		t.Fatal(err)
	}

	token, err := client.InstallationToken(ctx, installation,
		list(os.Getenv("GH_APP_REPOSITORIES")),
		list(os.Getenv("GH_APP_PERMISSIONS")))
	if err != nil {
		t.Fatalf("installation access token: %v", err)
	}

	if token.Token == "" {
		t.Error("GitHub returned no token")
	}
	t.Logf("installation %d, expires %s", installation, token.ExpiresAt.Format(time.RFC3339))
}

func list(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}
