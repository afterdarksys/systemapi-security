package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/afterdarksys/systemapi-security/internal/ids"
	"github.com/afterdarksys/systemapi-security/internal/modules"
	"github.com/afterdarksys/systemapi-security/internal/store"
)

// Report is a local snapshot contract for a future systemapi agent collector.
// It does not send data and contains no grants, password hashes or contacts.
type Report struct {
	Schema           string           `json:"schema"`
	Host             string           `json:"host"`
	GeneratedAt      string           `json:"generated_at"`
	LastScan         string           `json:"last_scan"`
	ConfigSHA256     string           `json:"config_sha256"`
	ScanConfigSHA256 string           `json:"scan_config_sha256"`
	ConfigChanged    bool             `json:"config_changed"`
	System           modules.Snapshot `json:"system"`
	Findings         []ReportFinding  `json:"findings"`
}

type ReportFinding struct {
	ID string `json:"id"`
	ids.Finding
	Observation string `json:"observation"`
	FirstSeen   string `json:"first_seen"`
	LastSeen    string `json:"last_seen"`
}

func configHash(c store.Config) string {
	b, _ := json.Marshal(c)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func systemView(c store.Config, st store.IDSState) modules.Snapshot {
	if st.LastScan == "" || st.ConfigSHA256 != configHash(c) {
		return modules.Pending(c.Modules)
	}
	return modules.CloneSnapshot(st.System)
}

// Report returns one coherent last-scan snapshot while holding the engine lock.
// No detector runs on GET. Coverage belongs to LastScan, not GeneratedAt.
func (e *Engine) Report() (Report, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	cfg, st := e.Store.Config(), e.Store.IDS()
	hash := configHash(cfg)
	r := Report{Schema: "secsvc-report/1", Host: e.Host, GeneratedAt: e.now().UTC().Format(time.RFC3339Nano), LastScan: st.LastScan,
		ConfigSHA256: hash, ScanConfigSHA256: st.ConfigSHA256, ConfigChanged: hash != st.ConfigSHA256, System: systemView(cfg, st), Findings: []ReportFinding{}}
	for _, f := range openFindings(st) {
		rec := st.Open[ident(f)]
		observation := "observed"
		if r.ConfigChanged {
			observation = "stale"
		} else if !rec.Observed {
			observation = "retained"
		}
		sum := sha256.Sum256([]byte(e.Host + "\x00" + ident(f)))
		r.Findings = append(r.Findings, ReportFinding{hex.EncodeToString(sum[:]), f, observation, rec.FirstSeen, rec.LastSeen})
	}
	return r, nil
}
