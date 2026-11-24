//go:build !windows

package i18n

// systemLocale has nothing beyond the POSIX variables Resolve already reads.
func systemLocale() string { return "" }
