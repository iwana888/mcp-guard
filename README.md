# MCP-Guard

An HTTP reverse proxy that sits **between an MCP Client and an MCP Server**,
evaluating every `tools/call` through the **agent-reliability** kernel before
forwarding it. It turns "should this agent be allowed to call this tool?" into
a single decision: `ALLOW` / `DENY` / `ASK` / `MODIFY`.

> Kernel: [`../agent-reliability`](https://github.com/agent-reliability/agent-reliability)
> (referenced locally via a Go `replace` directive — no publish required).

## What it delivers

1. **Action Policy** — tool-call rules expressed as kernel `Policy` functions.
2. **Decision** — every `tools/call` gets a kernel verdict.
3. **Approval** — `ASK` decisions are resolved by a pluggable `Approver`.
4. **Audit** — every decision is persisted to an `AuditSink` for forensics.

## Architecture: HTTP MCP Reverse Proxy

```
  MCP Client
      │  HTTP JSON-RPC  (Authorization: Bearer <token>)
      ▼
  ┌──────────────────────────────────────────────┐
  │                  MCP-Guard                    │
  │                                                │
  │   POST /mcp                                    │
  │     ├─ method != tools/call  ───────────────► │  transparent proxy
  │     │  (initialize, notifications/*,          │
  │     │   tools/list, resources/*, prompts/*)   │
  │     │                                          │
  │     └─ tools/call                             │
  │           ├─ extract Token / Context          │
  │           ├─ build agent-reliability Action   │
  │           ▼                                    │
  │        ALLOW ──────────────────┐              │
  │        DENY  ──► MCP Error     │              │
  │        ASK   ──► Approver ─────┤              │
  │        MODIFY ► rewritten args ┘              │
  │                              │                │
  └──────────────────────────────┼────────────────┘
                                  │  HTTP MCP  (Bearer passed through VERBATIM)
                                  ▼
                           MCP Server
                                  │
                                  ▼
                                Tool
                                  │
                                  ▼
                            TCService / door lock
```

**Responsibility boundary (important):** MCP-Guard does **not** re-authenticate
the caller. The `Authorization` header is forwarded to the upstream verbatim.
The upstream MCP Server still owns token validation and per-tool authz.
MCP-Guard only judges **action risk** from the request's identity context.

## Layout

```
mcp-guard/
├─ go.mod                      # module + replace → ../agent-reliability
├─ core/
│  ├─ core.go                  # ToolCall/Meta, Guard.Check gateway, decision routing
│  ├─ audit.go                 # AuditRecord + AuditSink (in-memory default)
│  ├─ approval.go              # Approver: DenyAll / AllowAll / ConsoleApprover
│  └─ core_test.go
├─ hotel/
│  └─ hotel.go                 # domain policies: issue_card, get_guest_profile
├─ httpgw/
│  ├─ httpgw.go                # HTTP MCP reverse proxy (only intercepts tools/call)
│  └─ httpgw_test.go           # end-to-end ALLOW/DENY/ASK/MODIFY + passthrough
├─ cmd/mcp-guard/              # HTTP gateway entrypoint
├─ server/hotel/               # minimal REAL upstream MCP Server (for P1 e2e)
└─ examples/hotel/             # library-level demo (no HTTP)
```

## Run the end-to-end demo (P1)

Terminal 1 — the real MCP Server (behind the guard):

```bash
go run ./server/hotel -listen :18080
```

Terminal 2 — MCP-Guard in front of it:

```bash
UPSTREAM=http://127.0.0.1:18080 go run ./cmd/mcp-guard -listen :8080 -approve auto
```

Terminal 3 — client now talks to MCP-Guard instead of the server:

```bash
curl -s -X POST http://127.0.0.1:8080/mcp \
  -H 'Authorization: Bearer <token>' -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"issue_card","arguments":{"role":"front_desk","room":"203"}}}'
```

### Verified scenarios (real HTTP, through the proxy)

| Scenario | Call | Decision | Result |
|----------|------|----------|--------|
| ordinary issue | `issue_card{front_desk,203}` | ALLOW | forwarded → `card_id` returned |
| unauthorized room | `issue_card{housekeeping,999}` | DENY | not forwarded, `-32000` |
| Master Card | `issue_card{...,card_type:"master"}` | ASK | approved → forwarded |
| bulk issue | `issue_card{...,rooms:[...]}` | ASK | approved → forwarded |
| dangerous arg | `issue_card{...,privileged:true}` | MODIFY | `privileged` stripped, forwarded |
| handshake | `tools/list`, `initialize` | — | transparently proxied |
| token | `Authorization: Bearer ...` | — | passed through verbatim |

## Hotel key-card policies (hotel/hotel.go)

- `housekeeping` may only issue a card to their `assigned_room` (else DENY).
- `guest` needs a `booking_id` (else ASK); `front_desk` always ALLOW.
- `Master Card` (`card_type:"master"`) and bulk (`rooms:[]`) are ASK.
- `privileged:true` is MODIFY (stripped before forwarding).
- `guest` reading `get_guest_profile` is DENY (PII).

## Extending

Add a rule by writing a kernel `Policy` and registering it:

```go
kernel.AddPolicy(agentreliability.Policy{
    ID: "my.rule", Name: "…", Severity: "high", Enabled: true,
    Eval: func(a agentreliability.Action) (agentreliability.Decision, bool) {
        if a.Tool != "some_tool" { return agentreliability.Decision{}, false }
        return agentreliability.Decision{Type: agentreliability.Deny, Reason: "…"}, true
    },
})
```

## Roadmap

- **P2** — `FileAuditSink` → `audit.jsonl` (append-only, no DB yet).
- **P3** — Streamable HTTP / SSE transport variants.
- Later — SQLite / PostgreSQL / Elasticsearch / OpenTelemetry sinks.
