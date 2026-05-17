package bypassroute

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
)

// cachedOverride — структура персистентного кэша admin override на диске.
//
// Версионирование (P2-1 final-audit): поле SigVersion определяет HMAC scope.
//   - "2" (default для новых записей) → HMAC over {etag, adds, excludes}.
//     Закрывает rollback/freshness oracle: stale signed cache на диске
//     нельзя безболезненно подменить новым etag — подпись инвалидируется.
//   - "" (отсутствует, legacy от старого клиента) → HMAC over {adds, excludes}.
//     Принимается на load для обратной совместимости. После 2-х релизов retire.
//
// Persist всегда пишет SigVersion="2" — клиент апгрейдит формат при первой
// успешной записи. Load принимает оба формата.
type cachedOverride struct {
	Etag       string   `json:"etag"`
	Adds       []string `json:"adds"`
	Excludes   []string `json:"excludes"`
	Signature  string   `json:"sig"`
	SigVersion string   `json:"sig_v,omitempty"`
}

// cacheFilePath возвращает путь к файлу кэша внутри cacheDir.
func cacheFilePath(dir string) string {
	return filepath.Join(dir, "bypass-overrides.bin")
}

// stringSigBodyV1 — JSON для legacy v1 cache scope: {adds, excludes}.
type stringSigBodyV1 struct {
	Adds     []string `json:"adds"`
	Excludes []string `json:"excludes"`
}

// stringSigBodyV2 — JSON для v2 cache scope: {etag, adds, excludes}. Etag
// входит в подпись → tampered cache file с подменённым etag не пройдёт verify.
type stringSigBodyV2 struct {
	Etag     string   `json:"etag"`
	Adds     []string `json:"adds"`
	Excludes []string `json:"excludes"`
}

// PersistOverride сохраняет AdminOverride на диск с HMAC-подписью.
// Директория создаётся с правами 0o700, файл пишется с 0o600.
//
// Формат — v2 (sig_v="2"): HMAC over {etag, adds, excludes}. Закрывает
// rollback oracle на диске клиента.
func PersistOverride(cacheDir string, ov *AdminOverride, hmacKey []byte) error {
	if ov == nil {
		return errors.New("nil override")
	}
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		return err
	}
	c := cachedOverride{
		Etag:       ov.Etag,
		Adds:       make([]string, 0, len(ov.Adds)),
		Excludes:   make([]string, 0, len(ov.Excludes)),
		SigVersion: "2",
	}
	for _, p := range ov.Adds {
		c.Adds = append(c.Adds, p.String())
	}
	for _, p := range ov.Excludes {
		c.Excludes = append(c.Excludes, p.String())
	}
	body, err := json.Marshal(stringSigBodyV2{Etag: c.Etag, Adds: c.Adds, Excludes: c.Excludes})
	if err != nil {
		return err
	}
	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(body)
	c.Signature = hex.EncodeToString(mac.Sum(nil))
	out, err := json.Marshal(c)
	if err != nil {
		return err
	}
	// Атомарная запись: tmp + rename. Защищает от corrupt cache при kill mid-write.
	finalPath := cacheFilePath(cacheDir)
	tmpPath := finalPath + ".tmp"
	if err := os.WriteFile(tmpPath, out, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, finalPath); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return nil
}

// LoadCachedOverride читает и валидирует кэш на диске.
// Возвращает ошибку если файла нет, JSON битый, либо HMAC-подпись не сходится.
// Префиксы, не парсящиеся как netip.Prefix, тихо пропускаются (forward-compat).
//
// Принимает оба формата:
//   - sig_v="2" → HMAC over {etag, adds, excludes} (preferred).
//   - sig_v="" / отсутствует / "1" → legacy HMAC over {adds, excludes}.
//
// Неизвестные значения sig_v reject'аются — не silently fallback'имся, чтобы
// не открыть downgrade-вектор через подделанный JSON.
func LoadCachedOverride(cacheDir string, hmacKey []byte) (*AdminOverride, error) {
	raw, err := os.ReadFile(cacheFilePath(cacheDir))
	if err != nil {
		return nil, err
	}
	var c cachedOverride
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, err
	}
	// Гарантируем непустые слайсы для воспроизводимой сериализации тела.
	adds := c.Adds
	if adds == nil {
		adds = []string{}
	}
	excludes := c.Excludes
	if excludes == nil {
		excludes = []string{}
	}
	var body []byte
	switch c.SigVersion {
	case "", "1":
		body, err = json.Marshal(stringSigBodyV1{Adds: adds, Excludes: excludes})
	case "2":
		body, err = json.Marshal(stringSigBodyV2{Etag: c.Etag, Adds: adds, Excludes: excludes})
	default:
		return nil, errors.New("cache: unknown signature version")
	}
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(body)
	expectedMAC := mac.Sum(nil)
	storedMAC, decodeErr := hex.DecodeString(c.Signature)
	if decodeErr != nil || !hmac.Equal(expectedMAC, storedMAC) {
		return nil, errors.New("cache signature invalid")
	}
	// Normalise SigVersion: empty string in cache means legacy v1 record,
	// surface as "1" so callers comparing to "2" don't accidentally tag a
	// real v1 cache as "uninitialized" (see AdminOverride.SigVersion doc).
	storedVersion := c.SigVersion
	if storedVersion == "" {
		storedVersion = "1"
	}
	ov := &AdminOverride{Etag: c.Etag, SigVersion: storedVersion}
	for _, s := range c.Adds {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			continue
		}
		ov.Adds = append(ov.Adds, p)
	}
	for _, s := range c.Excludes {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			continue
		}
		ov.Excludes = append(ov.Excludes, p)
	}
	return ov, nil
}
