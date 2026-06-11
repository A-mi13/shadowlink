//go:build !sl_firefox

package browser

// registerFirefoxIfEnabled — no-op в дефолтном (RU) билде. Firefox uTLS-FP
// в РФ банится первым (полевое знание MEMORY [[utls-chrome-fingerprint-maintenance]]).
// Чтобы вернуть Firefox для экспериментов вне РФ — собирать с тегом sl_firefox.
func registerFirefoxIfEnabled() {}
