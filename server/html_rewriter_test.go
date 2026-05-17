package server

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestHTMLRewriter_IdentityOnPlainHTML(t *testing.T) {
	r := NewHTMLRewriter(RewriterConfig{
		SourceHost:      "habr.com",
		BrandFromTokens: []string{"Хабр"},
		BrandTo:         "DataCanvases",
		MaxOutputBytes:  1 << 20,
		MaxTagDepth:     200,
	})
	in := `<!doctype html><html><body><p>Hello world</p></body></html>`
	out, err := r.Rewrite(bytes.NewBufferString(in))
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !strings.Contains(string(out), "Hello world") {
		t.Errorf("content lost: %q", out)
	}
}

func TestHTMLRewriter_ReplacesBrandInVisibleText(t *testing.T) {
	r := NewHTMLRewriter(RewriterConfig{
		SourceHost:      "habr.com",
		BrandFromTokens: []string{"Хабр", "Habr"},
		BrandTo:         "DataCanvases",
		MaxOutputBytes:  1 << 20,
		MaxTagDepth:     200,
	})
	in := `<p>Добро пожаловать на Хабр — лучший сайт Habr</p>`
	out, err := r.Rewrite(bytes.NewBufferString(in))
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	s := string(out)
	if strings.Contains(s, "Хабр") {
		t.Errorf("Хабр leak in: %q", s)
	}
	if strings.Contains(s, "Habr") {
		t.Errorf("Habr leak in: %q", s)
	}
	if strings.Count(s, "DataCanvases") != 2 {
		t.Errorf("expected 2 DataCanvases, got: %q", s)
	}
}

func TestHTMLRewriter_PreservesBrandInsideCodeBlocks(t *testing.T) {
	r := NewHTMLRewriter(RewriterConfig{
		BrandFromTokens: []string{"Хабр"},
		BrandTo:         "DataCanvases",
		MaxOutputBytes:  1 << 20,
		MaxTagDepth:     200,
	})
	in := `<p>Обычный текст про Хабр.</p>` +
		`<pre><code>// Источник: Хабр API v2</code></pre>` +
		`<p>Ещё про Хабр.</p>` +
		`<script>var site = "Хабр";</script>` +
		`<style>/* Хабр theme */</style>` +
		`<noscript>Для Хабр нужен JS</noscript>`
	out, err := r.Rewrite(bytes.NewBufferString(in))
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	s := string(out)
	// Visible paragraphs: replaced.
	if !strings.Contains(s, "Обычный текст про DataCanvases.") {
		t.Errorf("paragraph 1 not rewritten: %q", s)
	}
	if !strings.Contains(s, "Ещё про DataCanvases.") {
		t.Errorf("paragraph 2 not rewritten: %q", s)
	}
	// Code/pre/script/style/noscript: untouched.
	if !strings.Contains(s, "// Источник: Хабр API v2") {
		t.Errorf("code block lost Хабр: %q", s)
	}
	if !strings.Contains(s, `var site = "Хабр";`) {
		t.Errorf("script lost Хабр: %q", s)
	}
	if !strings.Contains(s, `/* Хабр theme */`) {
		t.Errorf("style lost Хабр: %q", s)
	}
	if !strings.Contains(s, "Для Хабр нужен JS") {
		t.Errorf("noscript lost Хабр: %q", s)
	}
}

func TestHTMLRewriter_AppendsTitleSuffix(t *testing.T) {
	r := NewHTMLRewriter(RewriterConfig{
		BrandFromTokens:   []string{"Хабр"},
		BrandTo:           "DataCanvases",
		TargetTitleSuffix: " — DataCanvases Research",
		MaxOutputBytes:    1 << 20,
		MaxTagDepth:       200,
	})
	in := `<html><head><title>Про Go / Хабр</title></head><body></body></html>`
	out, err := r.Rewrite(bytes.NewBufferString(in))
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(s, "<title>Про Go / DataCanvases — DataCanvases Research</title>") {
		t.Errorf("title rewrite wrong: %q", s)
	}
}

func TestHTMLRewriter_ReplacesOgSiteName(t *testing.T) {
	r := NewHTMLRewriter(RewriterConfig{
		BrandFromTokens: []string{"Хабр"},
		BrandTo:         "DataCanvases",
		MaxOutputBytes:  1 << 20,
		MaxTagDepth:     200,
	})
	in := `<meta property="og:site_name" content="Хабр">`
	out, err := r.Rewrite(bytes.NewBufferString(in))
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(s, `content="DataCanvases"`) {
		t.Errorf("og:site_name not rewritten: %q", s)
	}
	if strings.Contains(s, `content="Хабр"`) {
		t.Errorf("og:site_name leak: %q", s)
	}
}

func TestHTMLRewriter_RewritesCanonicalLink(t *testing.T) {
	r := NewHTMLRewriter(RewriterConfig{
		SourceHost:         "habr.com",
		SourceHostSuffixes: []string{"habr.com"},
		InternalPathRewrite: func(p string) string {
			if strings.HasPrefix(p, "/ru/articles/") {
				return "/blog/" + strings.TrimPrefix(p, "/ru/articles/")
			}
			return p
		},
		MaxOutputBytes: 1 << 20,
		MaxTagDepth:    200,
	})
	in := `<link rel="canonical" href="https://habr.com/ru/articles/723128/">`
	out, err := r.Rewrite(bytes.NewBufferString(in))
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if strings.Contains(s, "habr.com") {
		t.Errorf("canonical still points at habr: %q", s)
	}
	if !strings.Contains(s, `href="/blog/723128/"`) {
		t.Errorf("canonical path wrong: %q", s)
	}
}

func TestHTMLRewriter_ReplacesFavicon(t *testing.T) {
	r := NewHTMLRewriter(RewriterConfig{
		TargetFaviconPath: "/assets/favicon.ico",
		MaxOutputBytes:    1 << 20,
		MaxTagDepth:       200,
	})
	in := `<link rel="icon" href="https://habr.com/favicon.ico">`
	out, err := r.Rewrite(bytes.NewBufferString(in))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `href="/assets/favicon.ico"`) {
		t.Errorf("favicon not rewritten: %q", out)
	}
}

func TestHTMLRewriter_RewritesInternalArticleLinks(t *testing.T) {
	r := NewHTMLRewriter(RewriterConfig{
		SourceHost:         "habr.com",
		SourceHostSuffixes: []string{"habr.com"},
		InternalPathRewrite: func(p string) string {
			if strings.HasPrefix(p, "/ru/articles/") {
				return "/blog/" + strings.TrimPrefix(p, "/ru/articles/")
			}
			return p
		},
		MaxOutputBytes: 1 << 20,
		MaxTagDepth:    200,
	})
	in := `<a href="/ru/articles/939872">Read</a>` +
		`<a href="https://habr.com/ru/articles/111222/">Ext</a>` +
		`<a href="/sandbox">Keep</a>`
	out, err := r.Rewrite(bytes.NewBufferString(in))
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(s, `href="/blog/939872"`) {
		t.Errorf("relative rewrite fail: %q", s)
	}
	if !strings.Contains(s, `href="/blog/111222/"`) {
		t.Errorf("absolute rewrite fail: %q", s)
	}
	if !strings.Contains(s, `href="/sandbox"`) {
		t.Errorf("non-article path mangled: %q", s)
	}
	if strings.Contains(s, "habr.com") {
		t.Errorf("habr host leaked: %q", s)
	}
}

func TestHTMLRewriter_RewritesCDNSrcToProxy(t *testing.T) {
	r := NewHTMLRewriter(RewriterConfig{
		SourceHostSuffixes: []string{"habr.com", "habracdn.net"},
		CDNProxyPrefix:     "/_cdn/",
		MaxOutputBytes:     1 << 20,
		MaxTagDepth:        200,
	})
	in := `<img src="https://dr.habracdn.net/habr-web/img/logo.svg">` +
		`<link rel="stylesheet" href="https://dr.habracdn.net/habr-web/build/main.css">` +
		`<script src="https://dr.habracdn.net/habr-web/main.js"></script>`
	out, err := r.Rewrite(bytes.NewBufferString(in))
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if strings.Contains(s, "habracdn.net") {
		t.Errorf("habracdn leak: %q", s)
	}
	if !strings.Contains(s, `src="/_cdn/habr-web/img/logo.svg"`) {
		t.Errorf("img src rewrite fail: %q", s)
	}
	if !strings.Contains(s, `href="/_cdn/habr-web/build/main.css"`) {
		t.Errorf("link href rewrite fail: %q", s)
	}
	if !strings.Contains(s, `src="/_cdn/habr-web/main.js"`) {
		t.Errorf("script src rewrite fail: %q", s)
	}
}

func TestHTMLRewriter_RewritesSrcsetEntries(t *testing.T) {
	r := NewHTMLRewriter(RewriterConfig{
		SourceHostSuffixes: []string{"habracdn.net"},
		CDNProxyPrefix:     "/_cdn/",
		MaxOutputBytes:     1 << 20,
		MaxTagDepth:        200,
	})
	in := `<img srcset="https://dr.habracdn.net/img/a.jpg 1x, https://dr.habracdn.net/img/a@2x.jpg 2x">`
	out, err := r.Rewrite(bytes.NewBufferString(in))
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if strings.Contains(s, "habracdn.net") {
		t.Errorf("srcset habracdn leak: %q", s)
	}
	if !strings.Contains(s, "/_cdn/img/a.jpg 1x") {
		t.Errorf("srcset entry 1 fail: %q", s)
	}
	if !strings.Contains(s, "/_cdn/img/a@2x.jpg 2x") {
		t.Errorf("srcset entry 2 fail: %q", s)
	}
}

func TestHTMLRewriter_StripsTagBySignature(t *testing.T) {
	r := NewHTMLRewriter(RewriterConfig{
		StripTagSignatures: []TagSignature{
			{Tag: "header", ClassContains: "tm-header"},
			{Tag: "div", ClassContains: "comments-widget"},
		},
		MaxOutputBytes: 1 << 20,
		MaxTagDepth:    200,
	})
	in := `<body>` +
		`<header class="tm-header tm-header--sticky"><nav>login menu</nav></header>` +
		`<main><article>keep this</article></main>` +
		`<div class="comments-widget"><p>hate speech</p></div>` +
		`<footer>keep footer</footer>` +
		`</body>`
	out, err := r.Rewrite(bytes.NewBufferString(in))
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if strings.Contains(s, "login menu") {
		t.Errorf("header not stripped: %q", s)
	}
	if strings.Contains(s, "hate speech") {
		t.Errorf("comments not stripped: %q", s)
	}
	if !strings.Contains(s, "keep this") {
		t.Errorf("main content lost: %q", s)
	}
	if !strings.Contains(s, "keep footer") {
		t.Errorf("footer lost: %q", s)
	}
}

func TestHTMLRewriter_StripsNestedSignatureBlocks(t *testing.T) {
	r := NewHTMLRewriter(RewriterConfig{
		StripTagSignatures: []TagSignature{
			{Tag: "div", ClassContains: "ad-slot"},
		},
		MaxOutputBytes: 1 << 20,
		MaxTagDepth:    200,
	})
	in := `<div class="ad-slot"><div class="ad-inner"><p>ad</p></div></div><p>real</p>`
	out, err := r.Rewrite(bytes.NewBufferString(in))
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if strings.Contains(s, "ad-inner") || strings.Contains(s, ">ad<") {
		t.Errorf("nested strip fail: %q", s)
	}
	if !strings.Contains(s, "real") {
		t.Errorf("sibling lost: %q", s)
	}
}

func TestHTMLRewriter_ReplacesLogoImg(t *testing.T) {
	r := NewHTMLRewriter(RewriterConfig{
		LogoImgClassMatch: "tm-logo__image",
		TargetLogoPath:    "/assets/logo.svg",
		BrandTo:           "DataCanvases",
		MaxOutputBytes:    1 << 20,
		MaxTagDepth:       200,
	})
	in := `<img class="tm-logo__image tm-logo__image--big" src="/img/old-logo.png" alt="Хабр">` +
		`<img class="other-image" src="/img/article.png" alt="article">`
	out, err := r.Rewrite(bytes.NewBufferString(in))
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(s, `src="/assets/logo.svg"`) {
		t.Errorf("logo not swapped: %q", s)
	}
	if !strings.Contains(s, `alt="DataCanvases"`) {
		t.Errorf("logo alt not rebranded: %q", s)
	}
	if !strings.Contains(s, `src="/img/article.png"`) {
		t.Errorf("non-logo image mangled: %q", s)
	}
}

func TestHTMLRewriter_MaxOutputBytesTruncates(t *testing.T) {
	r := NewHTMLRewriter(RewriterConfig{
		MaxOutputBytes: 256,
		MaxTagDepth:    200,
	})
	// 10 KB of body text — deliberately larger than cap.
	big := strings.Repeat("<p>hello world hello world</p>", 500)
	out, err := r.Rewrite(bytes.NewBufferString("<html><body>" + big + "</body></html>"))
	if err != nil {
		t.Fatal(err)
	}
	if len(out) > 512 { // 256 cap + closing </body></html> allowance
		t.Errorf("output not truncated: len=%d", len(out))
	}
	if !bytes.HasSuffix(out, []byte("</body></html>")) {
		t.Errorf("truncation marker missing: %q", out[len(out)-32:])
	}
}

// TestHTMLRewriter_RewritesShortURLAttrs — regression for I8: rewriteURLAttr
// sliced lower[len(scheme):] before the HasPrefix check, panicking on any
// attr value shorter than 8 chars (href="/", href="#"). The recover()
// converted the panic into a fallback path, silently breaking every real
// page that had a clickable "/" logo link.
func TestHTMLRewriter_RewritesShortURLAttrs(t *testing.T) {
	r := NewHTMLRewriter(RewriterConfig{
		SourceHost:         "habr.com",
		SourceHostSuffixes: []string{"habr.com"},
		MaxOutputBytes:     1 << 20,
		MaxTagDepth:        200,
	})
	in := `<a href="/">root</a><a href="#">anchor</a><a href="?q=1">query</a>`
	out, err := r.Rewrite(bytes.NewBufferString(in))
	if err != nil {
		t.Fatalf("rewrite error on short attrs: %v", err)
	}
	s := string(out)
	for _, want := range []string{`href="/"`, `href="#"`, `href="?q=1"`} {
		if !strings.Contains(s, want) {
			t.Errorf("short attr lost: want %q in %q", want, s)
		}
	}
}

func TestHTMLRewriter_PanicRecoverOnPathologicalInput(t *testing.T) {
	r := NewHTMLRewriter(RewriterConfig{
		MaxOutputBytes: 1 << 20,
		MaxTagDepth:    200,
	})
	// Tokenizer handles most garbage; just ensure no panic leaks out.
	_, err := r.Rewrite(bytes.NewBufferString("\x00\x00<!-- \x00 --><html"))
	if err != nil && !strings.Contains(err.Error(), "panic") {
		// non-panic errors are allowed
		return
	}
}

func TestHTMLRewriter_FixtureEndToEnd(t *testing.T) {
	body, err := os.ReadFile("../testdata/habr/habr_article_synthetic.html")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	r := NewHTMLRewriter(RewriterConfig{
		SourceHost:         "habr.com",
		SourceHostSuffixes: []string{"habr.com", "habracdn.net"},
		CDNProxyPrefix:     "/_cdn/",
		BrandFromTokens:    []string{"Хабр"},
		BrandTo:            "DataCanvases",
		LogoImgClassMatch:  "tm-logo__image",
		StripTagSignatures: []TagSignature{
			{Tag: "header", ClassContains: "tm-header"},
			{Tag: "div", ClassContains: "comments-widget"},
			{Tag: "footer", ClassContains: "tm-footer"},
		},
		InternalPathRewrite: func(p string) string {
			if strings.HasPrefix(p, "/ru/articles/") {
				return "/blog/" + strings.TrimPrefix(p, "/ru/articles/")
			}
			return p
		},
		TargetTitleSuffix: " — DataCanvases Research",
		TargetLogoPath:    "/assets/logo.svg",
		TargetFaviconPath: "/assets/favicon.ico",
		MaxOutputBytes:    2 * 1024 * 1024,
		MaxTagDepth:       200,
	})
	out, err := r.Rewrite(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	s := string(out)

	// Invariants expected to hold on synthetic fixture.
	if strings.Contains(s, "Войти на Хабр") {
		t.Errorf("tm-header not stripped (content leaked)")
	}
	if strings.Contains(s, "Комментарии (42)") {
		t.Errorf("comments-widget not stripped")
	}
	if strings.Contains(s, "© Хабр 2026") {
		t.Errorf("tm-footer not stripped")
	}
	if !strings.Contains(s, "Как мы оптимизировали WebSocket") {
		t.Errorf("article h1 lost")
	}
	// Visible-text brand swap.
	if strings.Count(s, "DataCanvases") < 3 {
		t.Errorf("brand swap count too low: %q", s)
	}
	// Code block preservation.
	if !strings.Contains(s, "// Комментарий: источник — Хабр API v2") {
		t.Errorf("code block lost Хабр")
	}
	// Links and assets.
	if !strings.Contains(s, `href="/blog/939872"`) {
		t.Errorf("internal link rewrite fail")
	}
	if !strings.Contains(s, `href="/blog/111222/"`) {
		t.Errorf("absolute habr link rewrite fail")
	}
	if !strings.Contains(s, `href="/_cdn/habr-web/build/main.css"`) {
		t.Errorf("CDN css link fail")
	}
	if !strings.Contains(s, `/_cdn/img/diagram.jpg 1x`) {
		t.Errorf("srcset rewrite fail")
	}
	if !strings.Contains(s, `src="/assets/logo.svg"`) {
		t.Errorf("logo not swapped")
	}
	if !strings.Contains(s, `href="/assets/favicon.ico"`) {
		t.Errorf("favicon not swapped")
	}
	// No habr host references anywhere in hrefs/srcs.
	for _, needle := range []string{
		`href="https://habr.com`, `src="https://habr.com`,
		`href="https://dr.habracdn.net`, `src="https://dr.habracdn.net`,
	} {
		if strings.Contains(s, needle) {
			t.Errorf("habr host leak: %s in %q", needle, s)
		}
	}
	// Canonical rewrite — path side.
	if !strings.Contains(s, `href="/blog/723128/"`) {
		t.Errorf("canonical rewrite: %q", s)
	}
	// Title suffix.
	if !strings.Contains(s, "— DataCanvases Research</title>") {
		t.Errorf("title suffix missing: %q", s)
	}
	// og:site_name swap.
	if !strings.Contains(s, `property="og:site_name" content="DataCanvases"`) {
		t.Errorf("og:site_name swap: %q", s)
	}
}
