package uac

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Client struct {
	Endpoint     string
	ClientID     string
	ClientSecret string
	HTTP         *http.Client
}

func New(endpoint, clientID, clientSecret string) *Client {
	return &Client{
		Endpoint:     endpoint,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		HTTP:         &http.Client{Timeout: 15 * time.Second},
	}
}

type APIError struct {
	Code    int
	Message string
}

func (e *APIError) Error() string { return fmt.Sprintf("uac code=%d msg=%s", e.Code, e.Message) }

func (c *Client) do(ctx context.Context, method, path string, body any, out any, withSecret bool) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.Endpoint+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Client-Id", c.ClientID)
	if withSecret && c.ClientSecret != "" {
		req.Header.Set("X-Client-Secret", c.ClientSecret)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var envelope struct {
		Code    int             `json:"code"`
		Message string          `json:"message"`
		Data    json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return err
	}
	if envelope.Code != 0 {
		return &APIError{Code: envelope.Code, Message: envelope.Message}
	}
	if out != nil && len(envelope.Data) > 0 {
		return json.Unmarshal(envelope.Data, out)
	}
	return nil
}

func (c *Client) Challenge(ctx context.Context, method, identity, scene string) (map[string]any, error) {
	var out map[string]any
	err := c.do(ctx, http.MethodPost, "/api/v1/auth/challenge", map[string]any{
		"method": method, "identity": identity, "scene": scene,
	}, &out, false)
	return out, err
}

func (c *Client) ChallengeWithCaptcha(ctx context.Context, method, identity, scene, captchaToken string) (map[string]any, error) {
	var out map[string]any
	err := c.do(ctx, http.MethodPost, "/api/v1/auth/challenge", map[string]any{
		"method": method, "identity": identity, "scene": scene, "captcha_token": captchaToken,
	}, &out, false)
	return out, err
}

func (c *Client) Login(ctx context.Context, payload map[string]any) (map[string]any, error) {
	var out map[string]any
	err := c.do(ctx, http.MethodPost, "/api/v1/auth/login", payload, &out, false)
	return out, err
}

func (c *Client) Introspect(ctx context.Context, token string) (map[string]any, error) {
	var out map[string]any
	err := c.do(ctx, http.MethodPost, "/api/v1/auth/introspect", map[string]string{"token": token}, &out, true)
	return out, err
}

func (c *Client) Refresh(ctx context.Context, refreshToken string) (map[string]any, error) {
	var out map[string]any
	err := c.do(ctx, http.MethodPost, "/api/v1/auth/token/refresh", map[string]string{"refresh_token": refreshToken}, &out, false)
	return out, err
}

func (c *Client) JWKS(ctx context.Context) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.Endpoint+"/.well-known/jwks.json", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) StepUp(ctx context.Context, accessToken string, payload map[string]any) (map[string]any, error) {
	var rdr io.Reader
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Endpoint+"/api/v1/auth/step-up", rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Client-Id", c.ClientID)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var envelope struct {
		Code    int             `json:"code"`
		Message string          `json:"message"`
		Data    json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, err
	}
	if envelope.Code != 0 {
		return nil, &APIError{Code: envelope.Code, Message: envelope.Message}
	}
	var out map[string]any
	if len(envelope.Data) > 0 {
		_ = json.Unmarshal(envelope.Data, &out)
	}
	return out, nil
}

func (c *Client) HostedLoginURL(redirectURI, state, codeChallenge, deviceID string) string {
	u := c.Endpoint + "/login?client_id=" + urlQueryEscape(c.ClientID) + "&redirect_uri=" + urlQueryEscape(redirectURI)
	if state != "" {
		u += "&state=" + urlQueryEscape(state)
	}
	if codeChallenge != "" {
		u += "&code_challenge=" + urlQueryEscape(codeChallenge)
	}
	if deviceID != "" {
		u += "&device_id=" + urlQueryEscape(deviceID)
	}
	return u
}

func (c *Client) ExchangeCode(ctx context.Context, code, redirectURI, codeVerifier string) (map[string]any, error) {
	var out map[string]any
	err := c.do(ctx, http.MethodPost, "/api/v1/auth/token", map[string]any{
		"grant_type": "authorization_code", "code": code, "redirect_uri": redirectURI, "code_verifier": codeVerifier,
	}, &out, true)
	return out, err
}

func urlQueryEscape(s string) string {
	return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
}
