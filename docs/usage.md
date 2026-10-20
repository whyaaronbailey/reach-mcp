# Usage audit: Chat, Work, Codex and Reach MCP

Reach is a toolbox. Normal Reach tools run desktop, file and process operations
on the machine hosting Reach; the chat client supplies the model.

## What current OpenAI documentation establishes

As reviewed on 2026-10-19:

- Ordinary Chat has separate usage and credit rules from ChatGPT Work and Codex.
  See [GPT-6 and other models in ChatGPT](https://help.openai.com/en/articles/20001354-gpt-6-and-other-models-in-chatgpt).
- Work and Codex share an allowance.
  See [Work and Codex pricing](https://learn.chatgpt.com/docs/pricing) and
  [managing Astra usage](https://help.openai.com/en/articles/20001516-managing-usage-with-gpt-6-astra-in-work-and-codex).
- A plugin being available does not identify which surface a conversation uses.
  The [MCP plugin quickstart](https://developers.openai.com/plugins/quickstart)
  demonstrates Work specifically.

This supports using Reach from ordinary Chat without using the Work/Codex
allowance, subject to the product's current rules and the conversation actually
remaining in Chat. It is not a completed measurement of any individual account.
Chat still has its own applicable model and tool limits. Recheck official policy
when relying on this distinction; product availability and accounting can change.

Reach does not know or control the client's billing classification. MCP client
names, HTTP user agents, a successful tool call, or an assistant saying "this is
Chat" are not authoritative usage records. Reach audit logs establish which
tools executed. They do not establish which OpenAI allowance was charged.

Commands that launch another AI service have their own usage implications.
For example, asking Reach to run `codex exec ...` invokes Codex and consumes
its normal allocation or API billing. Installing Reach does not make those
commands free. Running Reach through Work or Codex also uses that surface's
normal allowance.

## Non-model quota collector

`scripts/audit-usage.py` uses only Python's standard library and an **already
installed, already signed-in** Codex CLI. It never installs a CLI, copies
credentials, opens a login flow, reads authentication files, or starts a model
turn. It does not change Reach settings.

Its entire RPC sequence is:

1. Start the existing `codex app-server` using private stdio pipes.
2. Send `initialize`, wait for its response, then send `initialized`.
3. Send `account/rateLimits/read`, sanitize the result, and exit.

It never sends thread creation/resume or model turn requests. This read-only
account method is documented in the
[Codex App Server reference](https://learn.chatgpt.com/docs/app-server).
The existing CLI manages its own sign-in. If it is not available or not signed
in, use the account's Usage dashboard instead; do not copy tokens from another
client or machine.

From the repository directory in PowerShell:

```powershell
python scripts/audit-usage.py snapshot --output .\usage-before.json
# If the existing CLI is not on PATH:
python scripts/audit-usage.py snapshot --codex 'C:\Tools\codex.exe' --output .\usage-before.json
python scripts/audit-usage.py snapshot --output .\usage-after.json
python scripts/audit-usage.py compare .\usage-before.json .\usage-after.json --quiet-window-confirmed
```

Use a private directory outside the checkout for actual account samples; they
are operational records and should not be committed. The paths above are usage
examples. Existing output files are never overwritten. Omit `--output` to
print the sanitized sample only. The optional `--timeout` is 1-120 seconds
(default 30).

Saved samples contain only a schema version, UTC capture time, status, bucket
identifiers and the reported quota windows: used percentage, duration and reset
time. Missing values stay null. Account identity, plan details, tokens, credit
purchase/reset information, server output and raw errors are excluded.
Failures return a fixed reason code and an actionable next step with exit code 2.

The CLI can use a different account/workspace from the Chat session. Confirm the
account in the applications' own settings before measuring; the collector
deliberately does not print account identity.

## Quiet-window test

Do this after active development or other Work/Codex tasks have finished.
Do not ask a Codex agent to keep checking the meter while testing: that agent
can consume the allowance being measured.

1. Confirm the same signed-in account/workspace in the ordinary Chat session
   and the quota dashboard or existing CLI. Record that the conversation's
   selected mode is **Chat**, along with the model, date and time zone.
2. Ensure other Work/Codex sessions, subagents, scheduled tasks and other
   devices are idle during the test. Record this as an operator observation;
   the collector cannot verify it.
3. Take before samples until the recent prior activity has settled. Avoid a
   quota reset boundary. No fixed reporting delay is guaranteed.
4. In that ordinary Chat session, make one small read-only Reach request:
   "Using Reach MCP, read the screen information and list open windows. Return
   the monitor resolution and window count. Do not launch another AI agent."
   Confirm the conversation remains in Chat afterward.
5. Inspect the corresponding UTC interval in `logs/audit.jsonl` locally.
   Correlate successful tool names, timestamps and results with the test.
   Keep tool arguments, file contents, private paths and screenshots private.
6. Once reporting has settled, take after samples and compare them. Only pass
   `--quiet-window-confirmed` if step 2 was actually satisfied. Without it,
   the comparison remains inconclusive.

Keep the ordinary Chat conversation reference, mode/model evidence, before/after
samples, reset windows and sanitized Reach call counts together privately.

## Reading the result

- **No observed increase:** consistent with the documented separation, but not
  proof of exactly zero consumption. Percentages can be coarse and usage can
  arrive late.
- **Observed increase:** the aggregate meter moved. This alone does not assign
  the increase to Reach; check the selected surface, background activity and
  any commands that invoked an AI service.
- **Inconclusive:** windows changed/reset, data was unavailable, usage decreased,
  or the quiet interval was not confirmed. Repeat with a clean interval rather
  than treating missing values as zero.

For eligible managed workspaces, more detailed billing records can help.
[OpenAI's usage guidance](https://help.openai.com/en/articles/20001478-reviewing-work-and-codex-usage-and-using-personal-analytics-in-chatgpt-desktop)
explains reporting delays and why a single chat's estimate may omit subagents
or background activity. It does not guarantee a per-request ledger for every
personal plan.

No isolated account experiment is claimed by this document or the collector.
