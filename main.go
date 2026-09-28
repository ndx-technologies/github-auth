package main

import (
	"context"
	"flag"
	"log"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/ndx-technologies/github-auth/github"
)

func main() {
	var (
		keyFile        string
		appID          string
		installationID string
		repositories   stringList
		permissions    stringList
	)
	flag.StringVar(&keyFile, "key", "", "path to the App private key, PEM (required)")
	flag.StringVar(&appID, "app-id", "", "App ID (required)")
	flag.StringVar(&installationID, "installation-id", "", "installation ID (required)")
	flag.Var(&repositories, "repo", "repositories to narrow the token to; comma-separated or repeated")
	flag.Var(&permissions, "permissions", "permissions to narrow to, (e.g. contents=write); comma-separated or repeated")
	flag.Parse()

	pemBytes, err := os.ReadFile(keyFile)
	if err != nil {
		log.Fatal(keyFile, ": ", err)
	}
	key, err := github.ParsePrivateKey(pemBytes)
	if err != nil {
		log.Fatal(keyFile, ": ", err)
	}

	client := github.GitHubClient{
		AppID:      appID,
		PrivateKey: key,
		Client:     http.DefaultClient,
	}

	ctx := context.Background()

	id, err := github.InstallationIDFromString(installationID)
	if err != nil {
		log.Fatal(err)
	}

	token, err := client.InstallationToken(ctx, id, []string(repositories), []string(permissions))
	if err != nil {
		log.Fatal(err)
	}

	os.Stdout.WriteString(token.Token + "\n")
	slog.Info("installation access token", "installation", id, "expires", token.ExpiresAt, "permissions", token.Permissions)
}

type stringList []string

func (l stringList) String() string { return strings.Join(l, ",") }

func (l *stringList) Set(s string) error {
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			*l = append(*l, part)
		}
	}
	return nil
}
