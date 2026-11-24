package vault

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/qbitdevz/qbit-vault/internal/envelope"
	"github.com/qbitdevz/qbit-vault/internal/secret"
)

// Last use (issue #62 part 4, docs/STORAGE.md § Usage file). A small file next
// to the vault, sealed with the master key, local to this device: it is not in
// vault.enc (so a use never writes the vault, never takes a snapshot and never
// triggers a sync round), not in backups, exports or sync. Losing it loses only
// this history. Older binaries do not know the file and ignore it.
const (
	// UsageFile is the file name in the vault home.
	UsageFile = "usage.enc"
	// FormatUsage identifies it in the envelope header.
	FormatUsage = "qbit-vault-usage/1"
)

// ErrUsageUnreadable is a usage file that cannot be trusted: damaged, not an
// envelope, or sealed with another key. The history is then empty; the next
// recorded use replaces the file.
var ErrUsageUnreadable = errors.New("usage_unreadable")

// Usage is what is known about the use of one record: when a command last had
// it injected, how that command ended, and when one last ended with exit 0.
// Never the command, its arguments, its output, the directory or the session.
type Usage struct {
	LastUsedAt   string `json:"last_used_at"`
	LastExitCode *int   `json:"last_exit_code,omitempty"`
	LastOKAt     string `json:"last_ok_at,omitempty"`
}

type usageBody struct {
	Records map[string]Usage `json:"records"`
}

// loadUsage reads the file with key. A missing file is empty history; one that
// cannot be trusted is ErrUsageUnreadable with empty history. The returned AAD
// is the file's, for the next write counter.
func loadUsage(home string, key secret.Secret) (usageBody, AAD, error) {
	empty := usageBody{Records: map[string]Usage{}}
	data, err := os.ReadFile(filepath.Join(home, UsageFile))
	if errors.Is(err, os.ErrNotExist) {
		return empty, AAD{}, nil
	}
	if err != nil {
		return empty, AAD{}, fmt.Errorf("%w: read failed", ErrUsageUnreadable)
	}
	pt, aad, err := envelope.Open(FormatUsage, key, data)
	if err != nil {
		return empty, AAD{}, ErrUsageUnreadable
	}
	defer clear(pt)
	var b usageBody
	if json.Unmarshal(pt, &b) != nil || b.Records == nil {
		return empty, AAD{}, ErrUsageUnreadable
	}
	return b, aad, nil
}

func saveUsage(home string, key secret.Secret, prev AAD, b usageBody) error {
	pt, err := json.Marshal(b)
	if err != nil {
		return errors.New("vault: usage encoding failed")
	}
	defer clear(pt)
	created := prev.CreatedAt
	if created == "" {
		created = time.Now().UTC().Format(time.RFC3339)
	}
	sealed, err := envelope.Seal(FormatUsage, key, AAD{CreatedAt: created, Writes: prev.Writes + 1}, pt)
	if err != nil {
		return err
	}
	return replaceFile(home, UsageFile, sealed)
}

// Usage returns the recorded use of every record, keyed by record id. A file
// that cannot be read gives empty history and ErrUsageUnreadable.
func (v *Vault) Usage() (map[string]Usage, error) {
	var out map[string]Usage
	err := v.locked(false, func() error {
		b, _, err := loadUsage(v.st.home, v.st.key)
		out = b.Records
		return err
	})
	if out == nil {
		out = map[string]Usage{}
	}
	return out, err
}

// RecordUses notes that a command which had the records with these ids
// injected ended with exitCode at time at. Only usage.enc is written: never
// vault.enc, state.json, a snapshot or the grants. Entries of records that no
// longer exist are dropped on the same write, so the file stays as small as the
// vault. The caller treats an error as non-fatal.
func (v *Vault) RecordUses(ids []string, at time.Time, exitCode int) error {
	if len(ids) == 0 {
		return nil
	}
	return v.locked(true, func() error {
		body, err := v.load()
		if err != nil {
			return err
		}
		live := map[string]bool{}
		for _, secrets := range allSecretMaps(body) {
			for _, w := range secrets {
				live[w.ID] = true
			}
		}
		b, prev, lerr := loadUsage(v.st.home, v.st.key)
		if lerr != nil && !errors.Is(lerr, ErrUsageUnreadable) {
			return lerr
		}
		if lerr != nil {
			// A file that cannot be read is replaced; keep its counter going up.
			prev = AAD{}
		}
		for id := range b.Records {
			if !live[id] {
				delete(b.Records, id)
			}
		}
		ts := at.UTC().Format(time.RFC3339)
		for _, id := range ids {
			if !live[id] {
				continue
			}
			u := b.Records[id]
			code := exitCode
			u.LastUsedAt, u.LastExitCode = ts, &code
			if exitCode == 0 {
				u.LastOKAt = ts
			}
			b.Records[id] = u
		}
		return saveUsage(v.st.home, v.st.key, prev, b)
	})
}

// allSecretMaps lists every layer's record map of b, unlinked layers included.
func allSecretMaps(b *body) []map[string]wireRecord {
	out := []map[string]wireRecord{b.Global}
	for _, p := range b.allProjects() {
		out = append(out, p.Secrets)
	}
	return out
}

// rekeyUsage re-seals usage.enc under newKey. Best effort and never an error:
// a file neither key opens is only lost history, and the next use replaces it.
func rekeyUsage(home string, oldKey, newKey secret.Secret) {
	if _, _, err := loadUsage(home, newKey); err == nil {
		return
	}
	b, aad, err := loadUsage(home, oldKey)
	if err != nil {
		return
	}
	_ = saveUsage(home, newKey, aad, b)
}
