# Development notes

## Using Codex and GPT-6 Astra as agents (not only reviewers)

"Astra" is **GPT-6 Astra**, OpenAI's model released 3 September 2026. It runs inside Codex CLI as model id `gpt-6-astra`
(reasoning effort `low|medium|high|xhigh|max`). So "Codex and Astra" are one tool with two models; the installed Codex CLI
0.153 on this box accepts `gpt-6-astra` (verified 2026-09-09 by running a design task with it).

Ways to drive Codex/Astra from Claude Code, in order of least setup:

1. **The installed codex plugin's `task` command** (already working). It runs Codex on an implementation, diagnosis or research
   task, foreground or background, read-only or with `--write`:

   ```bash
   node "$HOME/.claude/plugins/cache/openai-codex/codex/1.0.6/scripts/codex-companion.mjs" task --background --write --model gpt-6-astra --effort medium "Implement internal/idmap per docs/design/backend-packaging-plan.md section 2.14 with tests"
   ```

   Poll with `... status <job-id> --json` and collect with `... result <job-id>`. The `codex:codex-rescue` subagent is a thin
   wrapper around this command, so Claude can delegate to it from a conversation. Limitation: Codex works alone on the task and
   cannot call Claude subagents back.

2. **Codex as an MCP server inside Claude Code**, so any session or subagent can open a Codex conversation as a tool:

   ```bash
   claude mcp add --transport stdio --scope user codex -- codex mcp-server
   ```

   This exposes `codex(prompt, ...)` and `codex-reply(conversation_id, prompt, ...)` with `approval-policy` and `sandbox`
   parameters. Community wrappers add model and effort parameters:
   [codex-as-mcp](https://github.com/kky42/codex-as-mcp), [codex-mcp-server](https://github.com/tuannvm/codex-mcp-server),
   [claude-code-codex-mcp](https://github.com/ogmios2/claude-code-codex-mcp). Background:
   [Claude Code and Codex CLI bidirectional MCP](https://codex.danielvaughan.com/2026/03/26/claude-code-codex-bidirectional-mcp/).

3. **The project agent `codex-worker`** (`.claude/agents/codex-worker.md`, set up 2026-09-09). It runs
   `codex exec --skip-git-repo-check -m gpt-6-astra -c model_reasoning_effort=medium --sandbox workspace-write` with the task
   read from a temp file and returns Codex's final message. Invoke it with the Agent tool (`subagent_type: codex-worker`);
   say "read-only" in the task for review or research, and `--model`/`--effort` to override. Several can run in parallel
   alongside Opus subagents. Route 2 (Codex as an MCP server) is also registered on this machine: `claude mcp list` shows
   `codex: codex mcp-server - Connected`.

Recommended pattern for this repo: Claude orchestrates, plans and reviews; Codex or Astra take bounded implementation tasks
(one package, with tests) or give an independent second opinion. Keep Codex runs `sandbox = workspace-write` and review the
diff before committing. GPT-6 Astra notes: 1M-token context; its published system card reports lower chain-of-thought
monitorability, so rely on diffs and tests rather than transcripts
([source](https://codex.danielvaughan.com/2026/09/03/gpt-6-astra-codex-cli-configuration-context-notes-safety/)).

## Design reviews on file

- `docs/design/codex-independent-review.md`: Codex (default model) on the first plan.
- `docs/design/astra-per-user-review.md`: GPT-6 Astra, medium effort, on the per-user identity and QuTS hero requirements.
- `docs/design/identity-and-hero-plan.md`: Opus design for the same requirements.
