package httpgw

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ar "github.com/agent-reliability/agent-reliability"
	mguard "github.com/agent-reliability/mcp-guard/core"
	"github.com/agent-reliability/mcp-guard/hotel"
	"github.com/agent-reliability/mcp-guard/policy"
)

// TestServeAuditTrail verifies the full HTTP path with a JSONL audit sink and a
// secret in the arguments: the call is enforced/forwarded, the audit file is
// written with receipt_id / request_hash / target_server, and secrets are
// redacted.
func TestServeAuditTrail(t *testing.T) {
	up := &fakeUpstream{}
	srv := httptest.NewServer(up.handler())
	defer srv.Close()
	u, _ := url.Parse(srv.URL)

	kernel := &ar.Guard{}
	kernel.AddPolicy(hotel.IssueCardPolicy())
	kernel.AddPolicy(hotel.GetGuestProfilePolicy())
	def, _ := policy.DefaultPolicies()
	for _, p := range def {
		kernel.AddPolicy(p)
	}

	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")
	audit, err := mguard.NewFileAudit(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	defer audit.Close()

	guard := mguard.New(kernel,
		mguard.WithApprover(mguard.AllowAll{}),
		mguard.WithAudit(audit),
		mguard.WithTargetServer(srv.URL+"/mcp"),
	)
	gw := New(u, guard, "/mcp")

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"issue_card","arguments":{"role":"front_desk","room":"203","token":"super-secret"}}}`
	req, _ := http.NewRequest(http.MethodPost, "http://gw/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer tok-xyz")
	rec := httptest.NewRecorder()
	gw.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	// Call must have reached the upstream (ALLOW forwarded).
	if up.calls != 1 {
		t.Fatalf("expected 1 forwarded call, got %d", up.calls)
	}
	if up.lastAuth != "Bearer tok-xyz" {
		t.Fatalf("token not passed through: %q", up.lastAuth)
	}

	// Audit file must contain the record with redaction + enrichment. The
	// plaintext secret must NOT appear; only the masked form should.
	raw, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "super-secret") {
		t.Fatalf("plaintext secret leaked into audit: %s", string(raw))
	}
	if !strings.Contains(string(raw), `"token":"***"`) {
		t.Fatalf("secret not redacted in audit: %s", string(raw))
	}
	var recs []mguard.AuditRecord
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line == "" {
			continue
		}
		var r mguard.AuditRecord
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			continue
		}
		recs = append(recs, r)
	}
	if len(recs) != 1 {
		t.Fatalf("want 1 audit record, got %d", len(recs))
	}
	r := recs[0]
	if r.ReceiptID == "" || r.RequestHash == "" {
		t.Fatalf("receipt/hash missing: %+v", r)
	}
	if r.TargetServer == "" {
		t.Fatalf("target_server missing")
	}
	if !strings.Contains(string(r.Arguments), "***") {
		t.Fatalf("secret not redacted in audit args: %s", string(r.Arguments))
	}
}
