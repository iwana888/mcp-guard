# AgentWorld Guard (formerly MCP Guard)

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
│  ├─ core.go                  # ToolCall/Meta, Guard.Check gateway, observe mode, redaction
│  ├─ audit.go                 # AuditRecord + AuditSink (in-memory default)
│  ├─ jsonl.go                 # FileAuditSink → audit.jsonl
│  ├─ approval.go              # Approver: DenyAll / AllowAll / ConsoleApprover
│  └─ *_test.go
├─ policy/
│  ├─ yaml.go                  # YAML → kernel Policy loader
│  └─ defaults.go              # built-in safety baseline (shell/SQL/deploy)
├─ hotel/
│  └─ hotel.go                 # domain policies: issue_card, get_guest_profile
├─ httpgw/
│  ├─ httpgw.go                # HTTP MCP reverse proxy (only intercepts tools/call)
│  └─ *_test.go                # end-to-end ALLOW/DENY/ASK/MODIFY + JSONL audit
├─ cmd/guard/                 # CLI: serve / check / demo
├─ server/hotel/               # minimal REAL upstream MCP Server (for e2e)
└─ examples/hotel/             # library-level demo (no HTTP)
```

## Policy as YAML

Rules are declarative — no Go needed to configure the guard. Drop a file and
point `-config` at it (or rely on the built-in safety baseline):

```yaml
rules:
  - id: block-dangerous-shell
    tool: shell
    command_contains: ["rm -rf", "mkfs", "shutdown"]
    action: deny

  - id: require-approval-production-deploy
    tool: deploy
    params:
      environment: "production"
    action: ask

  - id: strip-privileged
    tool: issue_card
    params:
      privileged: "true"
    action: modify
    modify_to:
      privileged: "false"
```

Match dimensions (all AND-ed): `tool` / `command_contains` (target + `command`/
`query`/`sql` args) / `arg_contains` (any arg value) / `params` (exact).
Actions: `allow` | `deny` | `ask` | `modify` (with `modify_to`). Unknown action
fails **closed** (deny). The built-in baseline already blocks destructive shell
commands and dangerous SQL, and asks before shell / production deploys.

## Modes: enforce vs observe

- `enforce` (default): decisions block or rewrite the call as usual.
- `observe`: every call runs **as if ALLOW** (shadow mode); the audit trail
  records `would_be` = what the policy *would* have decided. Use this to
  validate a policy against live traffic before turning it on.

## Audit (JSONL)

Every decision is appended to `audit.jsonl` (one JSON object per line) with:
`receipt_id`, `request_hash` (SHA-256 of tool+args+meta), `target_server`,
`policy_id`, `decision`, `would_be` (observe), `mode`, `actor`, and arguments
with **sensitive keys** (`token`, `password`, `secret`, …) masked as `***`.

## Run

Terminal 1 — the real MCP Server (behind the guard):

```bash
go run ./server/hotel -listen :18080
```

Terminal 2 — AgentWorld Guard in front of it:

```bash
go run ./cmd/guard serve \
  -upstream http://127.0.0.1:18080 \
  -listen :8080 -approve auto \
  -audit audit.jsonl -mode enforce
```

Terminal 3 — client now talks to the guard instead of the server:

```bash
curl -s -X POST http://127.0.0.1:8080/mcp \
  -H 'Authorization: Bearer <token>' -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"issue_card","arguments":{"role":"front_desk","room":"203"}}}'
```

CLI sub-commands (also `go install github.com/iwana888/mcp-guard/cmd/guard@latest`):

```bash
guard demo                                   # run the four-scenario demo
guard check -tool shell -args '{"command":"rm -rf /"}'   # local decision, no server
guard serve -upstream <url> -config guard.yaml -audit audit.jsonl
```

### Verified scenarios (real HTTP, through the proxy)

| Scenario | Call | Decision | Result |
|----------|------|----------|--------|
| ordinary issue | `issue_card{front_desk,203}` | ALLOW | forwarded → `card_id` returned |
| unauthorized room | `issue_card{housekeeping,999}` | DENY | not forwarded, `-32000` |
| Master Card | `issue_card{...,card_type:"master"}` | ASK | approved → forwarded |
| bulk issue | `issue_card{...,rooms:[...]}` | ASK | approved → forwarded |
| dangerous arg | `issue_card{...,privileged:true}` | MODIFY | `privileged` stripped, forwarded |
| destructive shell | `shell{command:"rm -rf /"}` | DENY | blocked by YAML baseline |
| handshake | `tools/list`, `initialize` | — | transparently proxied |
| token | `Authorization: Bearer ...` | — | passed through verbatim |
| observe | any call | ALLOW (would_be recorded) | runs, but audited as-if |

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
