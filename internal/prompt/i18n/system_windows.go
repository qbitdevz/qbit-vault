//go:build windows

package i18n

import "golang.org/x/sys/windows"

// systemLocale is the user's first preferred display language, such as
// "es-ES": the language Windows itself is shown in, which is the language the
// user reads windows in. The regional format (dates, numbers) can differ from
// it and is not used.
func systemLocale() string {
	langs, err := windows.GetUserPreferredUILanguages(windows.MUI_LANGUAGE_NAME)
	if err != nil || len(langs) == 0 {
		return ""
	}
	return langs[0]
}
