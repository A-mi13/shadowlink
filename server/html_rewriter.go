package server

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"golang.org/x/net/html"
)

// RewriterConfig управляет поведением HTMLRewriter. Создаётся один раз при
// инициализации LiveBlogHandler; после создания не изменяется.
//
// BrandFromTokens — список подстрок (с учётом регистра), которые заменяются
// на BrandTo в видимом тексте. Используйте несколько значений, если сайт-
// источник использует разные варианты бренда ("Хабр", "Habr", "habrahabr").
type RewriterConfig struct {
	SourceHost          string
	SourceHostSuffixes  []string
	CDNProxyPrefix      string
	BrandFromTokens     []string
	BrandTo             string
	LogoImgClassMatch   string
	StripTagSignatures  []TagSignature
	InternalPathRewrite func(string) string
	TargetTitleSuffix   string
	TargetLogoPath      string
	TargetFaviconPath   string
	MaxOutputBytes      int
	MaxTagDepth         int
}

// TagSignature описывает открывающий тег для удаления — по имени элемента
// и (опционально) по подстроке класса или data-атрибуту.
type TagSignature struct {
	Tag           string
	ClassContains string
	DataAttrMatch [2]string // [name, valueContains]; нулевое значение = "не задано"
}

// HTMLRewriter применяет трансформации из RewriterConfig к потоковому HTML-
// документу. Безопасен для параллельных вызовов Rewrite (immutable после
// создания).
type HTMLRewriter struct {
	cfg RewriterConfig
}

// NewHTMLRewriter создаёт HTMLRewriter с заданной конфигурацией.
// MaxOutputBytes и MaxTagDepth получают разумные дефолты если <= 0.
func NewHTMLRewriter(cfg RewriterConfig) *HTMLRewriter {
	if cfg.MaxOutputBytes <= 0 {
		cfg.MaxOutputBytes = 2 * 1024 * 1024
	}
	if cfg.MaxTagDepth <= 0 {
		cfg.MaxTagDepth = 200
	}
	return &HTMLRewriter{cfg: cfg}
}

// matchesStripSignature возвращает true, если тег и атрибуты соответствуют
// одной из сигнатур в StripTagSignatures. Сравнение тега — без учёта регистра,
// сравнение class/data-attr — с учётом регистра (подстрока).
func (r *HTMLRewriter) matchesStripSignature(tag string, attrs []attr) bool {
	class := getAttr(attrs, "class")
	for _, sig := range r.cfg.StripTagSignatures {
		if !strings.EqualFold(sig.Tag, tag) {
			continue
		}
		if sig.ClassContains != "" {
			if !strings.Contains(class, sig.ClassContains) {
				continue
			}
		}
		if sig.DataAttrMatch[0] != "" {
			if v := getAttr(attrs, sig.DataAttrMatch[0]); !strings.Contains(v, sig.DataAttrMatch[1]) {
				continue
			}
		}
		return true
	}
	return false
}

// emitLogoReplacement записывает самозакрывающийся <img> с нашим путём логотипа,
// alt=BrandTo и оригинальным списком классов, чтобы CSS продолжал применяться.
func (r *HTMLRewriter) emitLogoReplacement(buf *bytes.Buffer, classList string) {
	logoAttrs := []attr{
		{Key: "src", Value: r.cfg.TargetLogoPath},
		{Key: "alt", Value: r.cfg.BrandTo},
	}
	if classList != "" {
		logoAttrs = append(logoAttrs, attr{Key: "class", Value: classList})
	}
	writeStartTag(buf, "img", logoAttrs, true)
}

// Rewrite читает body и возвращает новый HTML в виде []byte. Ошибки возможны
// только при структурных сбоях: превышение MaxOutputBytes, сбой токенизатора.
// Замены бренда и ссылок ошибок не дают.
//
// Тексты внутри code/pre/script/style/noscript/textarea не изменяются —
// preserveDepth > 0 означает, что мы находимся внутри «зоны сохранения».
//
// Skip-mode: когда skipDepth > 0, все токены вплоть до закрывающего тега
// skipTag (с учётом вложенности) проглатываются.
func (r *HTMLRewriter) Rewrite(body io.Reader) (out []byte, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			err = fmt.Errorf("rewriter panic: %v", rec)
			out = nil
		}
	}()

	var buf bytes.Buffer
	buf.Grow(64 * 1024)

	preserveTags := map[string]bool{
		"code": true, "pre": true, "script": true, "style": true, "noscript": true, "textarea": true,
	}
	var preserveDepth int
	var insideTitle bool

	// Skip-mode: когда non-zero, проглатываем токены до закрытия outermost-блока.
	var skipTag string
	var skipDepth int

	// openDepth отслеживает структурную глубину открытых тегов для MaxTagDepth.
	var openDepth int

	z := html.NewTokenizer(body)
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			if z.Err() == io.EOF {
				break
			}
			return nil, z.Err()
		}
		if buf.Len() > r.cfg.MaxOutputBytes {
			buf.WriteString("</body></html>")
			break
		}

		switch tt {
		case html.StartTagToken, html.SelfClosingTagToken:
			name, hasAttr := z.TagName()
			tag := string(name)
			attrs := collectAttrs(z, hasAttr)

			if skipDepth > 0 {
				if tag == skipTag && tt == html.StartTagToken {
					skipDepth++
				}
				// Даже внутри skip-блока выполняем замену логотипа: декой-сайт
				// должен показывать свой логотип независимо от того, стрипается
				// ли окружающая шапка.
				if tag == "img" && r.cfg.LogoImgClassMatch != "" {
					class := getAttr(attrs, "class")
					if strings.Contains(class, r.cfg.LogoImgClassMatch) {
						r.emitLogoReplacement(&buf, class)
					}
				}
				continue
			}
			if tt == html.StartTagToken && r.matchesStripSignature(tag, attrs) {
				skipTag = tag
				skipDepth = 1
				continue
			}

			// Замена логотипа: если img совпадает по LogoImgClassMatch — эмитируем
			// замену и пропускаем оригинал.
			if tag == "img" && r.cfg.LogoImgClassMatch != "" {
				class := getAttr(attrs, "class")
				if strings.Contains(class, r.cfg.LogoImgClassMatch) {
					r.emitLogoReplacement(&buf, class)
					continue
				}
			}

			r.transformStartTagAttrs(tag, attrs)
			writeStartTag(&buf, tag, attrs, tt == html.SelfClosingTagToken)
			if tag == "title" && tt == html.StartTagToken {
				insideTitle = true
			}
			if preserveTags[tag] && tt == html.StartTagToken {
				preserveDepth++
			}
			// Отслеживаем структурную глубину для MaxTagDepth.
			if tt == html.StartTagToken {
				openDepth++
				if openDepth > r.cfg.MaxTagDepth {
					return nil, fmt.Errorf("html rewriter: tag depth overflow (%d)", openDepth)
				}
			}
		case html.EndTagToken:
			name, _ := z.TagName()
			tag := string(name)
			if skipDepth > 0 {
				if tag == skipTag {
					skipDepth--
					if skipDepth == 0 {
						skipTag = ""
					}
				}
				continue
			}
			if openDepth > 0 {
				openDepth--
			}
			if tag == "title" && insideTitle {
				if r.cfg.TargetTitleSuffix != "" {
					buf.WriteString(r.cfg.TargetTitleSuffix)
				}
				insideTitle = false
			}
			if preserveTags[tag] && preserveDepth > 0 {
				preserveDepth--
			}
			buf.WriteString("</")
			buf.WriteString(tag)
			buf.WriteByte('>')
		case html.TextToken:
			if skipDepth > 0 {
				continue
			}
			if preserveDepth > 0 {
				buf.Write(z.Raw())
			} else {
				buf.Write(r.rewriteText(z.Text()))
			}
		default:
			if skipDepth > 0 {
				continue
			}
			buf.Write(z.Raw())
		}
	}
	return buf.Bytes(), nil
}

// attr представляет один HTML-атрибут ключ=значение.
type attr struct {
	Key   string
	Value string
}

// collectAttrs извлекает все атрибуты из текущего токена тегa.
func collectAttrs(z *html.Tokenizer, has bool) []attr {
	var out []attr
	if !has {
		return out
	}
	for {
		k, v, more := z.TagAttr()
		out = append(out, attr{Key: string(k), Value: string(v)})
		if !more {
			return out
		}
	}
}

// writeStartTag записывает открывающий тег с атрибутами в buf.
func writeStartTag(buf *bytes.Buffer, tag string, attrs []attr, selfClose bool) {
	buf.WriteByte('<')
	buf.WriteString(tag)
	for _, a := range attrs {
		buf.WriteByte(' ')
		buf.WriteString(a.Key)
		buf.WriteString(`="`)
		writeEscapedAttrValue(buf, a.Value)
		buf.WriteByte('"')
	}
	if selfClose {
		buf.WriteString("/>")
	} else {
		buf.WriteByte('>')
	}
}

// writeEscapedAttrValue экранирует минимальный набор символов для HTML attr-value:
// & → &amp;, " → &quot;, < → &lt;.
func writeEscapedAttrValue(buf *bytes.Buffer, v string) {
	for i := 0; i < len(v); i++ {
		switch v[i] {
		case '&':
			buf.WriteString("&amp;")
		case '"':
			buf.WriteString("&quot;")
		case '<':
			buf.WriteString("&lt;")
		default:
			buf.WriteByte(v[i])
		}
	}
}

// transformStartTagAttrs мутирует атрибуты тега на месте согласно конфигу.
// Task 5: расширено на a/area/img/source/video/audio/iframe/script/form + srcset + CDN proxy.
func (r *HTMLRewriter) transformStartTagAttrs(tag string, attrs []attr) {
	switch tag {
	case "meta":
		if r.cfg.BrandTo != "" && hasAttrEq(attrs, "property", "og:site_name") {
			setAttr(attrs, "content", r.cfg.BrandTo)
		}
	case "link":
		rel := getAttr(attrs, "rel")
		switch rel {
		case "canonical":
			if href := getAttr(attrs, "href"); href != "" {
				setAttr(attrs, "href", r.rewriteURLAttr(href))
			}
		case "icon", "shortcut icon", "apple-touch-icon":
			if r.cfg.TargetFaviconPath != "" {
				setAttr(attrs, "href", r.cfg.TargetFaviconPath)
			}
		default:
			if href := getAttr(attrs, "href"); href != "" {
				setAttr(attrs, "href", r.rewriteURLAttr(href))
			}
		}
	case "a", "area":
		if href := getAttr(attrs, "href"); href != "" {
			setAttr(attrs, "href", r.rewriteURLAttr(href))
		}
	case "img", "source", "video", "audio", "iframe", "script":
		if src := getAttr(attrs, "src"); src != "" {
			setAttr(attrs, "src", r.rewriteURLAttr(src))
		}
		if srcset := getAttr(attrs, "srcset"); srcset != "" {
			setAttr(attrs, "srcset", r.rewriteSrcset(srcset))
		}
	case "form":
		if action := getAttr(attrs, "action"); action != "" {
			setAttr(attrs, "action", r.rewriteURLAttr(action))
		}
	}
}

// rewriteURLAttr — переписывает URL-атрибут: убирает хост источника и применяет
// InternalPathRewrite. CDN-суффиксы (содержащие "cdn") направляются под CDNProxyPrefix.
// Суффикс "example.com" матчит точный хост "example.com" и поддомены "sub.example.com".
func (r *HTMLRewriter) rewriteURLAttr(raw string) string {
	if raw == "" {
		return raw
	}
	lower := strings.ToLower(raw)
	for _, suffix := range r.cfg.SourceHostSuffixes {
		suffixLower := strings.ToLower(suffix)
		for _, scheme := range []string{"https://", "http://", "//"} {
			if !strings.HasPrefix(lower, scheme) {
				continue
			}
			afterScheme := lower[len(scheme):]
			// Извлекаем хост-часть (до '/', ':', '?', '#' или конца строки).
			hostEnd := strings.IndexAny(afterScheme, "/:?#")
			var host string
			if hostEnd < 0 {
				host = afterScheme
			} else {
				host = afterScheme[:hostEnd]
			}
			// Матчим: точный хост или поддомен (host == suffix или host заканчивается на "."+suffix).
			if host != suffixLower && !strings.HasSuffix(host, "."+suffixLower) {
				continue
			}
			// rest — всё после scheme+host в оригинальном raw.
			rest := raw[len(scheme)+len(host):]
			if strings.HasPrefix(rest, ":") {
				slash := strings.IndexByte(rest, '/')
				if slash >= 0 {
					rest = rest[slash:]
				} else {
					rest = "/"
				}
			}
			if rest == "" || rest[0] != '/' {
				rest = "/" + rest
			}
			// CDN host suffix → rewrite под CDNProxyPrefix.
			if r.cfg.CDNProxyPrefix != "" && r.isCDNSuffix(suffix) {
				return r.cfg.CDNProxyPrefix + strings.TrimPrefix(rest, "/")
			}
			return r.applyInternalRewrite(rest)
		}
	}
	if strings.HasPrefix(raw, "/") {
		return r.applyInternalRewrite(raw)
	}
	return raw
}

// isCDNSuffix — любой суффикс, содержащий "cdn", считается CDN-хостом.
// Явное разделение CDNHostSuffixes vs ContentHostSuffixes — оптимизация V2.
func (r *HTMLRewriter) isCDNSuffix(suffix string) bool {
	return strings.Contains(strings.ToLower(suffix), "cdn")
}

// rewriteSrcset разбирает атрибут srcset (comma-separated "url descriptor" пары)
// и применяет rewriteURLAttr к каждой URL-компоненте.
func (r *HTMLRewriter) rewriteSrcset(raw string) string {
	parts := strings.Split(raw, ",")
	for i, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		fields := strings.Fields(p)
		if len(fields) == 0 {
			continue
		}
		fields[0] = r.rewriteURLAttr(fields[0])
		parts[i] = strings.Join(fields, " ")
	}
	return strings.Join(parts, ", ")
}

// applyInternalRewrite применяет InternalPathRewrite если задан.
func (r *HTMLRewriter) applyInternalRewrite(path string) string {
	if r.cfg.InternalPathRewrite == nil {
		return path
	}
	return r.cfg.InternalPathRewrite(path)
}

// hasAttrEq возвращает true если атрибут k имеет значение v.
func hasAttrEq(attrs []attr, k, v string) bool {
	for _, a := range attrs {
		if a.Key == k && a.Value == v {
			return true
		}
	}
	return false
}

// getAttr возвращает значение атрибута k или пустую строку.
func getAttr(attrs []attr, k string) string {
	for _, a := range attrs {
		if a.Key == k {
			return a.Value
		}
	}
	return ""
}

// setAttr устанавливает значение атрибута k в slice attrs на месте.
func setAttr(attrs []attr, k, v string) {
	for i := range attrs {
		if attrs[i].Key == k {
			attrs[i].Value = v
			return
		}
	}
}

// rewriteText применяет замену BrandFromTokens → BrandTo на текстовых байтах.
// Регистрозависимо; использует bytes.ReplaceAll для каждого токена.
//
// Контракт: возвращает срез, которым caller может владеть — независимый от
// backing-буфера токенизатора. Даже в no-op ветке делаем защитную копию,
// чтобы инварианта "возвращённый срез безопасно удерживать" не зависела от
// того, вызывает ли caller buf.Write немедленно.
func (r *HTMLRewriter) rewriteText(src []byte) []byte {
	if len(r.cfg.BrandFromTokens) == 0 || r.cfg.BrandTo == "" {
		out := make([]byte, len(src))
		copy(out, src)
		return out
	}
	// Защитная копия: z.Text() использует общую память между вызовами z.Next().
	out := make([]byte, len(src))
	copy(out, src)
	to := []byte(r.cfg.BrandTo)
	for _, from := range r.cfg.BrandFromTokens {
		if from == "" {
			continue
		}
		out = bytes.ReplaceAll(out, []byte(from), to)
	}
	return out
}
