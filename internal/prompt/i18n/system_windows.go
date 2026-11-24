//go:build windows

package i18n

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// systemLocale is the default locale name of the user, such as "es-AR".
func systemLocale() string {
	proc := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetUserDefaultLocaleName")
	var buf [85]uint16 // LOCALE_NAME_MAX_LENGTH
	n, _, _ := proc.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if n == 0 {
		return ""
	}
	return windows.UTF16ToString(buf[:])
}
