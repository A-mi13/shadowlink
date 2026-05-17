package server

import (
	"bytes"
	"strings"
	"testing"
)

func TestCanaryInvariants_PassClean(t *testing.T) {
	good := []byte(strings.Repeat(`<p>DataCanvases says hello</p>`, 1000))
	result := checkCanaryInvariants(good, "DataCanvases", []string{"Хабр"})
	if !result.ok() {
		t.Errorf("expected OK, got %+v", result)
	}
}

func TestCanaryInvariants_DetectsTooSmall(t *testing.T) {
	tiny := []byte("<html>DataCanvases</html>")
	result := checkCanaryInvariants(tiny, "DataCanvases", []string{"Хабр"})
	if result.ok() {
		t.Errorf("expected fail on small body")
	}
	if !result.I1SizeFailed {
		t.Errorf("I1 not triggered: %+v", result)
	}
}

func TestCanaryInvariants_DetectsBrandMissing(t *testing.T) {
	body := bytes.Repeat([]byte("<p>just html no brand</p>"), 2000)
	result := checkCanaryInvariants(body, "DataCanvases", []string{"Хабр"})
	if result.ok() {
		t.Errorf("expected fail on missing brand")
	}
	if !result.I2BrandMissing {
		t.Errorf("I2 not triggered: %+v", result)
	}
}

func TestCanaryInvariants_DetectsBrandLeakInVisible(t *testing.T) {
	body := []byte(strings.Repeat("<p>DataCanvases about Хабр news</p>", 1000))
	result := checkCanaryInvariants(body, "DataCanvases", []string{"Хабр"})
	if result.ok() {
		t.Errorf("expected fail on brand leak")
	}
	if !result.I3SourceBrandLeak {
		t.Errorf("I3 not triggered: %+v", result)
	}
}

func TestCanaryInvariants_DetectsHabrHrefLeak(t *testing.T) {
	body := []byte(strings.Repeat(`<p>DataCanvases</p><a href="/ru/articles/1">x</a>`, 500))
	result := checkCanaryInvariants(body, "DataCanvases", []string{"Хабр"})
	if result.ok() {
		t.Errorf("expected fail on /ru/articles href leak")
	}
	if !result.I4InternalLinkLeak {
		t.Errorf("I4 not triggered: %+v", result)
	}
}

func TestCanaryInvariants_DetectsCDNLeak(t *testing.T) {
	body := []byte(strings.Repeat(`<p>DataCanvases</p><img src="https://dr.habracdn.net/x.jpg">`, 500))
	result := checkCanaryInvariants(body, "DataCanvases", []string{"Хабр"})
	if result.ok() {
		t.Errorf("expected fail on habracdn leak")
	}
	if !result.I5CDNLeak {
		t.Errorf("I5 not triggered: %+v", result)
	}
}

func TestCanaryTracker_3ConsecutiveTriggersError(t *testing.T) {
	tr := &canaryTracker{}
	if tr.record(false) {
		t.Errorf("1st fail should NOT trigger error")
	}
	if tr.record(false) {
		t.Errorf("2nd fail should NOT trigger error")
	}
	if !tr.record(false) {
		t.Errorf("3rd consecutive fail SHOULD trigger error")
	}
	if !tr.record(false) {
		t.Errorf("4th consecutive fail SHOULD trigger error")
	}
	tr.record(true)
	if tr.record(false) {
		t.Errorf("1st fail after success should NOT trigger error")
	}
}
