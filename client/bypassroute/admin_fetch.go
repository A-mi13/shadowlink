package bypassroute

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
)

// maxFetchResponseSize ограничивает размер ответа сервера на bypass-list,
// защищая клиента от OOM при злонамеренном/некорректном ответе.
// 64 KiB вмещает несколько сотен CIDR'ов с запасом.
const maxFetchResponseSize = 64 * 1024

// fetchResponse — формат ответа сервера на GET /api/v1/client/shadowlink/bypass.
// Поля Adds/Excludes сериализуются сервером через json.Marshal({Adds, Excludes}),
// именно эту байтовую последовательность HMAC-подпись и покрывает.
type fetchResponse struct {
	Etag     string     `json:"etag"`
	Adds     []entryDTO `json:"adds"`
	Excludes []entryDTO `json:"excludes"`
}

// entryDTO — отдельная запись override-листа (adds[].action == "add",
// excludes[].action == "exclude").
type entryDTO struct {
	CIDR   string `json:"cidr"`
	Action string `json:"action"`
}

// sigBodyV1 — структура HMAC-scope v1 (LEGACY): {adds, excludes} БЕЗ etag.
// Уязвима к freshness/rollback oracle (см. P2-1 final-audit). Принимается
// для backward-compat от старых серверов, новые сервера всегда отдают v2.
type sigBodyV1 struct {
	Adds     []entryDTO `json:"adds"`
	Excludes []entryDTO `json:"excludes"`
}

// sigBodyV2 — структура HMAC-scope v2: {etag, adds, excludes}. Etag входит
// в подпись → MITM swap etag без полного refresh body инвалидирует подпись.
// Поля и порядок ЯВЛЯЮТСЯ ЧАСТЬЮ КОНТРАКТА с server side
// (internal/client/shadowlink_bypass_handlers.go::bypassSignedPayloadV2).
type sigBodyV2 struct {
	Etag     string     `json:"etag"`
	Adds     []entryDTO `json:"adds"`
	Excludes []entryDTO `json:"excludes"`
}

// buildV1SigBody — компактный JSON для v1 verify.
func buildV1SigBody(adds, excludes []entryDTO) ([]byte, error) {
	if adds == nil {
		adds = make([]entryDTO, 0)
	}
	if excludes == nil {
		excludes = make([]entryDTO, 0)
	}
	return json.Marshal(sigBodyV1{Adds: adds, Excludes: excludes})
}

// buildV2SigBody — компактный JSON для v2 verify, включая etag.
func buildV2SigBody(etag string, adds, excludes []entryDTO) ([]byte, error) {
	if adds == nil {
		adds = make([]entryDTO, 0)
	}
	if excludes == nil {
		excludes = make([]entryDTO, 0)
	}
	return json.Marshal(sigBodyV2{Etag: etag, Adds: adds, Excludes: excludes})
}

// bypassSigVersionHeader — server присылает версию подписи. Отсутствие
// заголовка в ответе ⇒ legacy server, scope = v1 (over body without etag).
const bypassSigVersionHeader = "X-Bypass-Signature-Version"

// bypassSigVersionQuery — opt-in клиента в v2 scope (HMAC включает etag).
// Server игнорирует параметр, если не понимает — даёт legacy v1 ответ,
// клиент это распознаёт по отсутствию X-Bypass-Signature-Version и
// fallback'нется на v1 verify. P2-1 final-audit: v2 scope над {etag, adds,
// excludes} закрывает rollback/freshness oracle attack (MITM swap etag).
const bypassSigVersionQuery = "cli_v"

// FetchAdminOverride запрашивает у сервера актуальный admin bypass override.
//
// Поведение:
//   - 304 Not Modified (etag совпал) → (nil, nil) — клиент должен использовать существующий кэш.
//   - 200 OK → парсит тело + проверяет HMAC из заголовка X-Bypass-Signature, возвращает *AdminOverride.
//   - Любой другой код → fmt.Errorf("status %d", code).
//   - Отсутствие/несовпадение подписи → ошибка.
//
// HMAC scope — версионируется через response header X-Bypass-Signature-Version:
//   - "2" → scope = json.Marshal({etag, adds, excludes}) — закрывает rollback oracle.
//   - "" (отсутствует) или "1" → legacy scope = json.Marshal({adds, excludes}).
//
// Клиент всегда запрашивает ?cli_v=2 (предпочтительный scope), но принимает
// и legacy v1 от старого сервера. Это backward-compat shim до retire'а v1.
//
// Sticky-v2 anti-downgrade (Opus review I-2, final-audit-2026-05-05): если
// caller передал previousSigVersion="2" (т.е. предыдущий успешный fetch уже
// был v2), то v1-ответ от сервера будет отклонён как downgrade. Это закрывает
// MITM-вектор где атакующий strip'ает `cli_v=2` query чтобы заставить сервер
// ответить legacy v1. previousSigVersion="" / "1" → нет sticky-ограничения
// (первый fetch / клиент после wipe cache).
func FetchAdminOverride(client *http.Client, baseURL, token, currentEtag string, hmacKey []byte, previousSigVersion string) (*AdminOverride, error) {
	// Срезаем хвостовой "/" чтобы не получить //api/... при baseURL="https://host/".
	url := strings.TrimRight(baseURL, "/") + "/api/v1/client/shadowlink/bypass?" + bypassSigVersionQuery + "=2"
	if currentEtag != "" {
		url += "&etag=" + currentEtag
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	sigHex := resp.Header.Get("X-Bypass-Signature")
	if sigHex == "" {
		return nil, errors.New("missing X-Bypass-Signature")
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxFetchResponseSize))
	if err != nil {
		return nil, err
	}
	var body fetchResponse
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, err
	}
	// Гарантируем не-nil слайсы — сервер инициализирует через make([]entryDTO, 0).
	if body.Adds == nil {
		body.Adds = make([]entryDTO, 0)
	}
	if body.Excludes == nil {
		body.Excludes = make([]entryDTO, 0)
	}
	// Версия подписи определяет scope. Отсутствие header'а или явное "1" → v1.
	// Любое другое значение, кроме "2", reject'им как unknown/unsafe — не
	// fallback'имся silently на legacy, чтобы не открывать downgrade-вектор
	// через подделанный header.
	version := resp.Header.Get(bypassSigVersionHeader)
	var checkBody []byte
	switch version {
	case "", "1":
		// Sticky-v2 anti-downgrade. Если когда-то ранее этот клиент
		// принял v2-ответ от данного сервера — больше не доверяем v1.
		if previousSigVersion == "2" {
			return nil, errors.New("downgrade detected: server replied v1 after v2")
		}
		checkBody, err = buildV1SigBody(body.Adds, body.Excludes)
	case "2":
		checkBody, err = buildV2SigBody(body.Etag, body.Adds, body.Excludes)
	default:
		return nil, fmt.Errorf("unknown signature version %q", version)
	}
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(checkBody)
	expectedMAC := mac.Sum(nil)
	serverMAC, decodeErr := hex.DecodeString(sigHex)
	if decodeErr != nil || !hmac.Equal(expectedMAC, serverMAC) {
		return nil, errors.New("signature mismatch")
	}
	ov := &AdminOverride{Etag: body.Etag}
	for _, e := range body.Adds {
		p, err := netip.ParsePrefix(e.CIDR)
		if err != nil {
			continue
		}
		ov.Adds = append(ov.Adds, p)
	}
	for _, e := range body.Excludes {
		p, err := netip.ParsePrefix(e.CIDR)
		if err != nil {
			continue
		}
		ov.Excludes = append(ov.Excludes, p)
	}
	return ov, nil
}
