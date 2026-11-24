package i18n

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

// The OS locale of the machine running the tests must never matter.
func pinOS(t *testing.T, tag string) {
	t.Helper()
	old := OSLocale
	OSLocale = func() string { return tag }
	t.Cleanup(func() { OSLocale = old })
}

func TestMatchByPrimaryLanguage(t *testing.T) {
	tests := []struct {
		in   string
		want Locale
		ok   bool
	}{
		{"es", Es, true}, {"es-AR", Es, true}, {"es-ES", Es, true}, {"ES", Es, true}, {"ES_es.UTF-8", Es, true},
		{"es_MX@euro", Es, true}, {"es-419", Es, true},
		{"en", En, true}, {"en-GB", En, true}, {"EN_us.UTF-8", En, true},
		{"fr-FR", "", false}, {"de", "", false}, {"C", "", false}, {"POSIX", "", false}, {"", "", false},
		{"e", "", false}, {"esp", "", false}, {"123", "", false}, {"es es", "", false}, {"es\n", "", false},
		{"es\x00", "", false}, {"<es>", "", false}, {"-es", "", false}, {"_es", "", false},
		{"es-" + strings.Repeat("x", 40), "", false}, // over the 35 character cap
	}
	for _, tt := range tests {
		got, ok := Match(tt.in)
		if ok != tt.ok || got != tt.want {
			t.Errorf("Match(%q) = %q, %v; want %q, %v", tt.in, got, ok, tt.want, tt.ok)
		}
	}
	// The cap is exactly 35 characters.
	if _, ok := Match("es-" + strings.Repeat("x", 32)); !ok {
		t.Error("a 35 character tag was refused")
	}
	if _, ok := Match("es-" + strings.Repeat("x", 33)); ok {
		t.Error("a 36 character tag was accepted")
	}
}

func TestResolveOrder(t *testing.T) {
	tests := []struct {
		name string
		req  string
		env  map[string]string
		os   string
		want Locale
	}{
		{"nothing is English", "", nil, "", En},
		{"request wins over everything", "es-ES", map[string]string{EnvLocale: "en", "LANG": "en_US.UTF-8"}, "en-US", Es},
		{"request English wins over a Spanish env", "en", map[string]string{EnvLocale: "es"}, "es-ES", En},
		{"env wins over the system", "", map[string]string{EnvLocale: "es"}, "en-US", Es},
		{"LC_ALL first", "", map[string]string{"LC_ALL": "es_ES.UTF-8", "LC_MESSAGES": "en_US", "LANG": "en_US"}, "", Es},
		{"LC_MESSAGES before LANG", "", map[string]string{"LC_MESSAGES": "es_AR.UTF-8", "LANG": "en_US"}, "", Es},
		{"LANG", "", map[string]string{"LANG": "es_MX.UTF-8"}, "", Es},
		{"the OS locale last", "", nil, "es-ES", Es},
		{"unknown request falls to env", "fr", map[string]string{EnvLocale: "es"}, "", Es},
		{"malformed request falls to env", "es\n!!", map[string]string{EnvLocale: "es"}, "", Es},
		{"overlong request falls to system", strings.Repeat("a", 36), nil, "es-ES", Es},
		{"unknown env falls to POSIX", "", map[string]string{EnvLocale: "klingon", "LANG": "es_ES"}, "", Es},
		{"C falls to the next step", "", map[string]string{"LC_ALL": "C", "LANG": "es_ES"}, "es-ES", Es},
		{"all unknown is English", "zz", map[string]string{EnvLocale: "yy", "LANG": "xx"}, "ww", En},
		{"an English system stays English", "", map[string]string{"LANG": "en_US.UTF-8"}, "es-ES", En},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pinOS(t, tt.os)
			if got := Resolve(tt.req, env(tt.env)); got != tt.want {
				t.Errorf("Resolve = %q, want %q", got, tt.want)
			}
		})
	}
	pinOS(t, "")
	if got := Resolve("es", nil); got != Es {
		t.Errorf("a nil getenv: %q", got)
	}
}

func TestZeroLocaleIsEnglish(t *testing.T) {
	var zero Locale
	if zero.T("btn.save") != "Save" {
		t.Errorf("zero Locale: %q", zero.T("btn.save"))
	}
	if Es.T("btn.save") != "Guardar" {
		t.Errorf("Es: %q", Es.T("btn.save"))
	}
	if got := Locale("fr").T("btn.save"); got != "Save" {
		t.Errorf("an unsupported locale must read English, got %q", got)
	}
	if got := En.T("nope.missing"); got != "nope.missing" {
		t.Errorf("an unknown entry shows its id, got %q", got)
	}
}

var placeholder = regexp.MustCompile(`%(\[\d+\])?[a-zA-Z%]`)

func placeholders(s string) []string {
	m := placeholder.FindAllString(s, -1)
	sort.Strings(m)
	return m
}

func TestCatalogueIsComplete(t *testing.T) {
	base := catalogs[En]
	if len(base) < 50 {
		t.Fatalf("English catalogue has only %d entries", len(base))
	}
	for lang, c := range catalogs {
		for id, en := range base {
			txt, ok := c[id]
			if !ok {
				t.Errorf("%s lacks %q", lang, id)
				continue
			}
			if strings.TrimSpace(txt) == "" {
				t.Errorf("%s: %q is empty", lang, id)
			}
			if strings.Join(placeholders(txt), " ") != strings.Join(placeholders(en), " ") {
				t.Errorf("%s: %q has placeholders %v, English has %v", lang, id, placeholders(txt), placeholders(en))
			}
			// Arguments are always indexed: a translation may reorder them.
			if strings.Contains(en, "%s") || strings.Contains(en, "%d") {
				t.Errorf("%q uses an unindexed verb", id)
			}
			if strings.ContainsRune(txt, '\r') {
				t.Errorf("%s: %q holds a carriage return", lang, id)
			}
		}
		for id := range c {
			if _, ok := base[id]; !ok {
				t.Errorf("%s has %q, which English lacks", lang, id)
			}
		}
	}
	for _, lang := range []Locale{En, Es} {
		if catalogs[lang] == nil {
			t.Errorf("no catalogue for %s", lang)
		}
	}
}

// The product name and the scope tokens survive translation.
func TestTranslationsKeepTheTokens(t *testing.T) {
	for id, en := range catalogs[En] {
		if strings.Contains(en, "QBit Vault") && !strings.Contains(catalogs[Es][id], "QBit Vault") {
			t.Errorf("%q lost the product name in Spanish", id)
		}
	}
	// A scope option explains the scope in Spanish and still shows its token.
	for _, tok := range []string{"once", "session", "project"} {
		if id := "scope." + tok; en[id] != "" && !strings.Contains(es[id], tok) {
			t.Errorf("Spanish %q does not show the English token %q: %q", id, tok, es[id])
		}
	}
}

// Every id used in the code has an entry (a typo would show the id to the
// user), and every entry is used.
func TestEveryIDUsedInCodeExists(t *testing.T) {
	use := regexp.MustCompile(`\.T\("([a-z0-9_.]+)"`)
	root := filepath.Join("..", "..")
	used := map[string]string{}
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return err
		}
		raw, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		for _, m := range use.FindAllStringSubmatch(string(raw), -1) {
			used[m[1]] = p
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(used) < 30 {
		t.Fatalf("found only %d ids in use; the scan is broken", len(used))
	}
	for id, file := range used {
		if _, ok := catalogs[En][id]; !ok {
			t.Errorf("%s uses %q, which the catalogue lacks", file, id)
		}
	}
	for id := range catalogs[En] {
		if _, ok := used[id]; !ok {
			t.Errorf("%q is in the catalogue but no source uses it", id)
		}
	}
}

func TestTFormatsArguments(t *testing.T) {
	if got := En.T("val.field_of", 2, 3, "A"); got != "2 of 3 (A)" {
		t.Errorf("en: %q", got)
	}
	if got := Es.T("val.field_of", 2, 3, "A"); got != "2 de 3 (A)" {
		t.Errorf("es: %q", got)
	}
}
