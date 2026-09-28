package github

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type InstallationID int

func (id InstallationID) String() string {
	return strconv.Itoa(int(id))
}

func InstallationIDFromString(s string) (InstallationID, error) {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, err
	}
	return InstallationID(n), nil
}

type ErrHTTP struct {
	Status int
	Body   string
}

func (e *ErrHTTP) Error() string { return "http: " + strconv.Itoa(e.Status) + ": " + e.Body }

type ErrPermission struct {
	Permission string
}

func (e *ErrPermission) Error() string { return strconv.Quote(e.Permission) + " is not key=value" }

type ErrNoToken struct{}

func (e *ErrNoToken) Error() string { return "the response carried no token" }

// Token is a GitHub App installation access token.
type Token struct {
	Token       string            `json:"token"`
	ExpiresAt   time.Time         `json:"expires_at"`
	Permissions map[string]string `json:"permissions"`
}

const apiBase = "https://api.github.com"

type GitHubClient struct {
	AppID      string
	PrivateKey *rsa.PrivateKey
	Client     *http.Client
}

func (c *GitHubClient) InstallationToken(ctx context.Context, id InstallationID, repositories, permissions []string) (Token, error) {
	// Narrowing can only reduce what the App already holds.
	body := map[string]any{}
	if len(repositories) > 0 {
		body["repositories"] = repositories
	}

	if len(permissions) > 0 {
		granted := map[string]string{}
		for _, permission := range permissions {
			name, value, ok := strings.Cut(permission, "=")
			if !ok {
				return Token{}, &ErrPermission{Permission: permission}
			}
			granted[name] = value
		}
		body["permissions"] = granted
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return Token{}, err
	}

	// 9 minutes plus the backdated iat is GitHub's 10 minute ceiling.
	bearer, err := assertion(c.PrivateKey, c.AppID, 9*time.Minute)
	if err != nil {
		return Token{}, err
	}

	path := "/app/installations/" + id.String() + "/access_tokens"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiBase+path, bytes.NewReader(payload))
	if err != nil {
		return Token{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.Client.Do(req)
	if err != nil {
		return Token{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		detail, _ := io.ReadAll(resp.Body)
		return Token{}, &ErrHTTP{Status: resp.StatusCode, Body: string(detail)}
	}

	var token Token
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return Token{}, err
	}
	if token.Token == "" {
		return Token{}, &ErrNoToken{}
	}
	return token, nil
}
