package main

import (
	"reflect"
	"strings"
	"testing"
)

func TestExtractCoverPaths(t *testing.T) {
	htmlSrc := `<html><head>
        <link rel="stylesheet" href="/assets/main.css">
        <script src="/assets/app.js"></script>
    </head><body>
        <img src="/hero.webp">
    </body></html>`
	paths, err := extractCoverPaths(strings.NewReader(htmlSrc))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/assets/main.css", "/assets/app.js", "/hero.webp"}
	if !reflect.DeepEqual(paths, want) {
		t.Errorf("got %v, want %v", paths, want)
	}
}

func TestExtractCoverPaths_SkipsExternal(t *testing.T) {
	htmlSrc := `<link href="https://fonts.googleapis.com/css" rel="stylesheet">
        <link href="/internal.css" rel="stylesheet">`
	paths, _ := extractCoverPaths(strings.NewReader(htmlSrc))
	want := []string{"/internal.css"}
	if !reflect.DeepEqual(paths, want) {
		t.Errorf("expected only same-origin paths, got %v", paths)
	}
}
