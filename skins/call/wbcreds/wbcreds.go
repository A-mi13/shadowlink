package wbcreds

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

const cacheTTL = 4 * time.Minute

var (
	mu          sync.Mutex
	cachedCreds []TurnCred
	cachedAt    time.Time
)

// GetTURNCredentials returns cached credentials or fetches new ones if the cache expired.
func GetTURNCredentials() ([]TurnCred, error) {
	mu.Lock()
	if len(cachedCreds) > 0 && time.Since(cachedAt) < cacheTTL {
		c := make([]TurnCred, len(cachedCreds))
		copy(c, cachedCreds)
		mu.Unlock()
		return c, nil
	}
	mu.Unlock()

	creds, err := FetchTURNCredentials()
	if err != nil {
		return nil, err
	}

	mu.Lock()
	cachedCreds = creds
	cachedAt = time.Now()
	mu.Unlock()

	return creds, nil
}

// FetchTURNCredentials performs a full credential fetch from WB Stream API.
func FetchTURNCredentials() ([]TurnCred, error) {
	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{}, //nolint:gosec
		},
	}

	// 1. Guest register
	displayName := "wbturn_" + randChars(5)
	body := map[string]string{"displayName": displayName}
	var authResp struct {
		AccessToken string `json:"accessToken"`
	}
	if err := doJSON(client, "POST", "https://stream.wb.ru/auth/api/v1/auth/user/guest-register", "", body, &authResp); err != nil {
		return nil, fmt.Errorf("guest register: %w", err)
	}
	token := authResp.AccessToken
	if token == "" {
		return nil, fmt.Errorf("guest register: empty accessToken")
	}
	slog.Info("step 1/5: guest registered", "name", displayName)

	// 2. Create room
	roomBody := map[string]string{
		"roomType":    "ROOM_TYPE_ALL_ON_SCREEN",
		"roomPrivacy": "ROOM_PRIVACY_FREE",
	}
	var roomResp struct {
		RoomID string `json:"roomId"`
	}
	if err := doJSON(client, "POST", "https://stream.wb.ru/api-room/api/v2/room", token, roomBody, &roomResp); err != nil {
		return nil, fmt.Errorf("create room: %w", err)
	}
	roomID := roomResp.RoomID
	if roomID == "" {
		return nil, fmt.Errorf("create room: empty roomId")
	}
	slog.Info("step 2/5: room created", "roomId", roomID)

	// 3. Join room
	if err := doJSON(client, "POST", "https://stream.wb.ru/api-room/api/v1/room/"+roomID+"/join", token, nil, nil); err != nil {
		return nil, fmt.Errorf("join room: %w", err)
	}
	slog.Info("step 3/5: joined room")

	// 4. Get room token
	var tokenResp struct {
		RoomToken string `json:"roomToken"`
	}
	tokenURL := fmt.Sprintf("https://stream.wb.ru/api-room-manager/api/v1/room/%s/token?deviceType=PARTICIPANT_DEVICE_TYPE_WEB_DESKTOP&displayName=wbturn", roomID)
	if err := doJSON(client, "GET", tokenURL, token, nil, &tokenResp); err != nil {
		return nil, fmt.Errorf("get room token: %w", err)
	}
	roomToken := tokenResp.RoomToken
	if roomToken == "" {
		return nil, fmt.Errorf("get room token: empty roomToken")
	}
	slog.Info("step 4/5: got room token")

	// 5. WebSocket to LiveKit
	wsURL := fmt.Sprintf("wss://wbstream01-el.wb.ru:7880/rtc?access_token=%s&auto_subscribe=1&sdk=js&version=2.15.3", roomToken)
	dialer := websocket.Dialer{
		TLSClientConfig:  &tls.Config{}, //nolint:gosec
		HandshakeTimeout: 15 * time.Second,
	}
	conn, resp, err := dialer.Dial(wsURL, nil)
	if err != nil {
		if resp != nil {
			slog.Error("websocket dial failed", "status", resp.StatusCode)
		}
		return nil, fmt.Errorf("websocket dial: %w", err)
	}
	defer conn.Close()
	slog.Info("step 5/5: websocket connected to LiveKit")

	seen := make(map[string]bool)
	var creds []TurnCred

	for i := 0; i < 20; i++ {
		_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		msgType, msg, err := conn.ReadMessage()
		if err != nil {
			break
		}

		if msgType == websocket.TextMessage {
			parsed := parseJSONICE(msg)
			for _, c := range parsed {
				key := c.URL + "|" + c.Username
				if !seen[key] {
					seen[key] = true
					creds = append(creds, c)
				}
			}
		}
		if msgType == websocket.BinaryMessage || msgType == websocket.TextMessage {
			for _, c := range PbICE(msg) {
				key := c.URL + "|" + c.Username
				if seen[key] {
					continue
				}
				seen[key] = true
				creds = append(creds, c)
			}
		}
		if len(creds) > 0 {
			slog.Info("TURN credentials found", "count", len(creds))
			break
		}
	}

	if len(creds) == 0 {
		return nil, fmt.Errorf("no TURN credentials found in websocket messages")
	}

	return creds, nil
}

// doJSON performs an HTTP request with JSON body and decodes the JSON response.
func doJSON(client *http.Client, method, url, bearerToken string, reqBody interface{}, respBody interface{}) error {
	var bodyReader io.Reader
	if reqBody != nil {
		data, err := json.Marshal(reqBody)
		if err != nil {
			return err
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept-Encoding", "gzip")
	if bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+bearerToken)
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var reader io.Reader = resp.Body
	if resp.Header.Get("Content-Encoding") == "gzip" {
		gr, err := gzip.NewReader(resp.Body)
		if err != nil {
			return fmt.Errorf("gzip: %w", err)
		}
		defer gr.Close()
		reader = gr
	}

	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(reader)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(b))
	}

	if respBody != nil {
		if err := json.NewDecoder(reader).Decode(respBody); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}

	return nil
}

// parseJSONICE tries to extract ICE servers from a JSON-formatted LiveKit message.
// LiveKit sometimes sends JoinResponse as JSON with iceServers field.
func parseJSONICE(msg []byte) []TurnCred {
	// Try to find iceServers in nested JSON
	var raw map[string]json.RawMessage
	if json.Unmarshal(msg, &raw) != nil {
		return nil
	}

	// Look for iceServers at any nesting level
	return findICEInJSON(msg)
}

func findICEInJSON(data []byte) []TurnCred {
	s := string(data)
	// Quick check: does it contain "turn" or "urls"?
	if !strings.Contains(s, "turn") && !strings.Contains(s, "urls") {
		return nil
	}

	// Try to find iceServers array pattern
	var wrapper map[string]json.RawMessage
	if json.Unmarshal(data, &wrapper) != nil {
		return nil
	}

	var creds []TurnCred

	for key, val := range wrapper {
		// Direct iceServers field
		if key == "iceServers" || key == "ice_servers" {
			creds = append(creds, parseICEArray(val)...)
		}
		// Recurse into objects
		if len(val) > 0 && (val[0] == '{' || val[0] == '[') {
			if val[0] == '{' {
				creds = append(creds, findICEInJSON(val)...)
			}
			if val[0] == '[' {
				var arr []json.RawMessage
				if json.Unmarshal(val, &arr) == nil {
					for _, item := range arr {
						if len(item) > 0 && item[0] == '{' {
							creds = append(creds, findICEInJSON(item)...)
						}
					}
				}
			}
		}
	}
	return creds
}

func parseICEArray(data []byte) []TurnCred {
	var servers []struct {
		URLs       []string `json:"urls"`
		URL        string   `json:"url"`
		Username   string   `json:"username"`
		Credential string   `json:"credential"`
	}
	if json.Unmarshal(data, &servers) != nil {
		return nil
	}
	var creds []TurnCred
	for _, s := range servers {
		urls := s.URLs
		if s.URL != "" {
			urls = append(urls, s.URL)
		}
		for _, u := range urls {
			if strings.HasPrefix(u, "turn") || strings.HasPrefix(u, "stun") {
				creds = append(creds, TurnCred{
					URL:      u,
					Username: s.Username,
					Password: s.Credential,
				})
			}
		}
	}
	return creds
}

// randChars generates n random lowercase alphanumeric characters.
func randChars(n int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		b[i] = charset[idx.Int64()]
	}
	return string(b)
}
