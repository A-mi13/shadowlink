package server

import "testing"

func TestNegotiateMigration(t *testing.T) {
	if !negotiateMigration(true, true) {
		t.Error("both support → enabled")
	}
	if negotiateMigration(false, true) {
		t.Error("server off → disabled")
	}
	if negotiateMigration(true, false) {
		t.Error("client off → disabled")
	}
}
