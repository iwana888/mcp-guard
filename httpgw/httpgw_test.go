package httpgw

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	ar "github.com/agent-reliability/agent-reliability"
	mguard "github.com/agent-reliability/mcp-guard/core"
	"github.com/agent-reliability/mcp-guard/hotel"
)

// fakeUpstream simulates the real MCP Server behind the guard. It records the
// last received Authorization header and tool args so we can assert that the
// gateway passed them through (or rewrote them for MODIFY).
type fakeUpstream struct {
	lastAuth  string
	lastTool  string
	lastArgs  json.RawMessage
	calls     int
}

func (f *fakeUpstream) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		f.lastAuth = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		var req jsonRPCRequest
		_ = json.Unmarshal(body, &req)
		if req.Method == "tools/call" {
			f.calls++
			var p toolsCallParams
			_ = json.Unmarshal(req.Params, &p)
			f.lastTool = p.Name
			f.lastArgs = p.Arguments
		}
		w.Header().Set("Content-Type", "application/json")
		// Echo a success result for any call.
		resp := rpcOKEcho(req.ID)
		b, _ := json.Marshal(resp)
		_, _ = w.Write(b)
	}
}

type rpcOK struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
}

func rpcOKEcho(id json.RawMessage) rpcOK {
	return rpcOK{JSONRPC: "2.0", ID: id, Result: map[string]any{"content": []map[string]any{{"type": "text", "text": "ok"}}}}
}

type upstreamResult struct {
	Content []map[string]any `json:"content"`
}

func newTestGateway(t *testing.T, approver mguard.Approver) (*Gateway, *fakeUpstream, string) {
	t.Helper()
	up := &fakeUpstream{}
	srv := httptest.NewServer(up.handler())
	t.Cleanup(srv.Close)

	u, _ := url.Parse(srv.URL)
	kernel := ar.NewGuard()
	kernel.AddPolicy(hotel.IssueCardPolicy())
	kernel.AddPolicy(hotel.GetGuestProfilePolicy())
	guard := mguard.New(kernel, mguard.WithApprover(approver))
	gw := New(u, guard, "/mcp")
	return gw, up, srv.URL
}

// postMCP sends a JSON-RPC request to the gateway and returns the parsed body.
func postMCP(t *testing.T, gw *Gateway, reqBody string, auth string) (int, map[string]any) {
	t.Helper()
	var buf bytes.Buffer
	buf.WriteString(reqBody)
	req, _ := http.NewRequest(http.MethodPost, "http://gw/mcp", &buf)
	req.Header.Set("Content-Type", "application/json")
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	rec := httptest.NewRecorder()
	gw.Handler().ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func toolsCall(name string, args map[string]any) string {
	b, _ := json.Marshal(args)
	return `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + name + `","arguments":` + string(b) + `}}`
}

func TestToolsListPassthrough(t *testing.T) {
	gw, up, _ := newTestGateway(t, mguard.DenyAll{})
	code, out := postMCP(t, gw, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, "Bearer tok-123")
	if code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	if _, ok := out["result"]; !ok {
		t.Fatalf("expected result, got %v", out)
	}
	if up.calls != 0 {
		t.Fatalf("tools/list must not hit a tool; calls=%d", up.calls)
	}
}

func TestAllowPassthrough(t *testing.T) {
	gw, up, _ := newTestGateway(t, mguard.DenyAll{})
	_, out := postMCP(t, gw, toolsCall(hotel.ToolIssueCard, map[string]any{
		"role": "front_desk", "room": "203",
	}), "Bearer tok-abc")
	if errObj, ok := out["error"]; ok {
		t.Fatalf("unexpected deny: %v", errObj)
	}
	if up.calls != 1 || up.lastTool != hotel.ToolIssueCard {
		t.Fatalf("call not forwarded: calls=%d tool=%q", up.calls, up.lastTool)
	}
	if up.lastAuth != "Bearer tok-abc" {
		t.Fatalf("authorization not passed through: %q", up.lastAuth)
	}
}

func TestDenyBlocks(t *testing.T) {
	gw, up, _ := newTestGateway(t, mguard.DenyAll{})
	_, out := postMCP(t, gw, toolsCall(hotel.ToolIssueCard, map[string]any{
		"role": "housekeeping", "room": "999", "assigned_room": "410",
	}), "Bearer tok")
	if errObj, ok := out["error"].(map[string]any); !ok {
		t.Fatalf("expected error, got %v", out)
	} else if _, hasDeny := errObj["message"].(string); !hasDeny {
		t.Fatalf("error missing message: %v", errObj)
	}
	if up.calls != 0 {
		t.Fatalf("denied call must not reach upstream: calls=%d", up.calls)
	}
}

func TestAskDeniedByDefault(t *testing.T) {
	// ASK with DenyAll approver => blocked, not forwarded.
	gw, up, _ := newTestGateway(t, mguard.DenyAll{})
	_, out := postMCP(t, gw, toolsCall(hotel.ToolIssueCard, map[string]any{
		"role": "guest", "room": "203",
	}), "Bearer tok")
	if _, ok := out["error"]; !ok {
		t.Fatalf("ASK with DenyAll must be blocked, got %v", out)
	}
	if up.calls != 0 {
		t.Fatalf("blocked ASK must not reach upstream")
	}
}

func TestAskApprovedForwards(t *testing.T) {
	// ASK with AllowAll approver => forwarded.
	gw, up, _ := newTestGateway(t, mguard.AllowAll{})
	_, out := postMCP(t, gw, toolsCall(hotel.ToolIssueCard, map[string]any{
		"role": "guest", "room": "203",
	}), "Bearer tok")
	if _, ok := out["error"]; ok {
		t.Fatalf("approved ASK must forward, got %v", out)
	}
	if up.calls != 1 {
		t.Fatalf("approved ASK must reach upstream, calls=%d", up.calls)
	}
}

func TestMasterCardIsAsk(t *testing.T) {
	gw, up, _ := newTestGateway(t, mguard.AllowAll{})
	_, out := postMCP(t, gw, toolsCall(hotel.ToolIssueCard, map[string]any{
		"role": "front_desk", "room": "203", "card_type": "master",
	}), "Bearer tok")
	if _, ok := out["error"]; ok {
		t.Fatalf("master card should be approved via AllowAll, got %v", out)
	}
	if up.calls != 1 {
		t.Fatalf("master card (approved) must forward, calls=%d", up.calls)
	}
}

func TestBulkIsAsk(t *testing.T) {
	gw, up, _ := newTestGateway(t, mguard.AllowAll{})
	_, out := postMCP(t, gw, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"issue_card","arguments":{"role":"front_desk","rooms":["201","202","203"]}}}`, "Bearer tok")
	if _, ok := out["error"]; ok {
		t.Fatalf("bulk (approved) should forward, got %v", out)
	}
	if up.calls != 1 {
		t.Fatalf("bulk must forward when approved, calls=%d", up.calls)
	}
}

func TestModifyStripsPrivileged(t *testing.T) {
	gw, up, _ := newTestGateway(t, mguard.DenyAll{})
	_, out := postMCP(t, gw, toolsCall(hotel.ToolIssueCard, map[string]any{
		"role": "front_desk", "room": "203", "privileged": true,
	}), "Bearer tok")
	if _, ok := out["error"]; ok {
		t.Fatalf("MODIFY must forward, got %v", out)
	}
	if up.calls != 1 {
		t.Fatalf("MODIFY must reach upstream, calls=%d", up.calls)
	}
	// The privileged flag must have been stripped before forwarding.
	var got map[string]any
	_ = json.Unmarshal(up.lastArgs, &got)
	if _, present := got["privileged"]; present {
		t.Fatalf("privileged flag was not stripped: %v", got)
	}
	if got["room"] != "203" {
		t.Fatalf("non-dangerous args must be preserved: %v", got)
	}
}
