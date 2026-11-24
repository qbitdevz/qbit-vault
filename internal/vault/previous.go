package vault

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"time"

	"github.com/qbitdevz/qbit-vault/internal/secret"
)

// The previous value (issue #62, docs/STORAGE.md § Previous value). A record
// keeps the one value it last replaced, inside the same encrypted body and
// with the record, for PreviousRetention. It is not a schema change: the
// field is additive, an older binary ignores it and drops it on its next save.

// PreviousRetention is how long a replaced value stays recoverable.
const PreviousRetention = 7 * 24 * time.Hour

// previousSkew is how far in the future a replaced_at may be (another
// device's clock) before the value is not trusted to expire.
const previousSkew = 24 * time.Hour

// ErrNoPrevious is a revert of a record that has no recoverable previous value
// (never replaced, expired, or removed).
var ErrNoPrevious = errors.New("no_previous_value")

// previousLive reports whether p is still recoverable at time at.
func previousLive(p *wirePrevious, at time.Time) bool {
	if p == nil || p.Value == "" {
		return false
	}
	t, err := time.Parse(time.RFC3339, p.ReplacedAt)
	if err != nil || t.After(at.Add(previousSkew)) {
		return false
	}
	return at.Before(t.Add(PreviousRetention))
}

// pruneExpired drops every previous value that is no longer recoverable from
// the loaded body, so no reader sees it and the next save does not write it.
// It runs while decoding, before the body is indexed, so a drop never counts
// as a change of the record (no new clock, no sync conflict between devices).
func (b *body) pruneExpired(clock func() time.Time) {
	var at time.Time // read lazily: a vault with no previous value never asks the clock
	live := func(p *wirePrevious) bool {
		if at.IsZero() {
			at = clock()
		}
		return previousLive(p, at)
	}
	prune := func(secrets map[string]wireRecord) {
		for n, w := range secrets {
			if w.Previous != nil && !live(w.Previous) {
				w.Previous = nil
				secrets[n] = w
			}
		}
	}
	prune(b.Global)
	for _, p := range b.allProjects() {
		prune(p.Secrets)
	}
	for i, raw := range b.conflicts {
		b.conflicts[i] = scrubConflict(raw, live)
	}
}

// scrubConflict removes an expired previous value from the record a kept
// conflict holds. A conflict that cannot be read is returned as it is.
func scrubConflict(raw json.RawMessage, live func(*wirePrevious) bool) json.RawMessage {
	var c map[string]json.RawMessage
	if json.Unmarshal(raw, &c) != nil || len(c["record"]) == 0 {
		return raw
	}
	var rec map[string]json.RawMessage
	if json.Unmarshal(c["record"], &rec) != nil || len(rec["previous"]) == 0 {
		return raw
	}
	var p wirePrevious
	if json.Unmarshal(rec["previous"], &p) == nil && live(&p) {
		return raw
	}
	delete(rec, "previous")
	r, err := json.Marshal(rec)
	if err != nil {
		return raw
	}
	c["record"] = r
	out, err := json.Marshal(c)
	if err != nil {
		return raw
	}
	return out
}

// previousAfterReplace is the previous value of the record that replaces old
// with next: the old value, from now on; or, when next holds the same value
// (a replace the user confirmed after the same-value warning), the previous
// value old already had, so a copy of the current value never pushes it out.
func previousAfterReplace(old, next wireRecord, at string) *wirePrevious {
	if old.Value == "" || subtle.ConstantTimeCompare([]byte(old.Value), []byte(next.Value)) == 1 {
		return old.Previous
	}
	return &wirePrevious{Value: old.Value, ReplacedAt: at}
}

// PreviousEntry is a recoverable previous value and where it lives. The
// caller wipes Value.
type PreviousEntry struct {
	Name       string
	Layer      Layer
	Unlinked   bool
	Kind       string // the record's kind: "secret", "text" or empty
	Value      secret.Secret
	ReplacedAt string
}

// PreviousValues returns the recoverable previous value of every record of
// every layer. It exists for the redaction guards: nothing else reads one.
func (v *Vault) PreviousValues() ([]PreviousEntry, error) {
	var out []PreviousEntry
	err := v.read(func(b *body) error {
		add := func(l Layer, unlinked bool, secrets map[string]wireRecord) {
			for n, w := range secrets {
				if w.Previous != nil {
					out = append(out, PreviousEntry{Name: n, Layer: l, Unlinked: unlinked, Kind: w.Kind,
						Value: secret.New(n, []byte(w.Previous.Value)), ReplacedAt: w.Previous.ReplacedAt})
				}
			}
		}
		add(Global(), false, b.Global)
		for root, p := range b.Projects {
			add(Layer{Project: true, Root: root, Label: p.Label}, false, p.Secrets)
		}
		for _, p := range b.unlinked {
			add(Layer{Project: true, Label: p.Label}, true, p.Secrets)
		}
		return nil
	})
	return out, err
}

// RevertWithGrants swaps the current and the previous value of name in layer:
// the previous becomes current, the value it replaces becomes the previous
// (so the swap can be undone) and the window restarts. Like a replacement it
// gives the record a new id and drops the grants of (name, layer), so no
// permission carries over to a different value. It never returns a value.
func (v *Vault) RevertWithGrants(layer Layer, name string, ed GrantsEditor) (GrantsResult, error) {
	if err := checkName(name); err != nil {
		return GrantsResult{}, err
	}
	if err := checkLayer(layer); err != nil {
		return GrantsResult{}, err
	}
	var res GrantsResult
	id := ""
	err := v.locked(true, func() error {
		if err := v.mutateLocked(func(b *body) error {
			secrets := b.secrets(layer, false)
			w, ok := secrets[name]
			if !ok {
				return withName(ErrNotFound, name)
			}
			if w.Previous == nil {
				return withName(ErrNoPrevious, name)
			}
			ts := stamp()
			w.Value, w.Previous = w.Previous.Value, &wirePrevious{Value: w.Value, ReplacedAt: ts}
			w.ID, w.UpdatedAt = newRecordID(), ts
			secrets[name] = w
			id = w.ID
			return nil
		}); err != nil {
			return err
		}
		var err error
		res, err = v.editGrantsLocked(ed, func(ed GrantsEditor, body []byte) ([]byte, int, error) {
			return ed.DropRecord(body, name, layer.Key())
		})
		return err
	})
	res.RecordID = id
	return res, err
}
