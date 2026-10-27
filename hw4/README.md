# Security Log Investigation Agent

Homework 4 for Security Engineering with Generative AI. The agent answers
natural-language questions about the fake events in `data/sample_events.json`.
Gemini reasons over evidence fetched through two real local STDIO MCP sessions:
the custom security server and the published Git MCP server.

## What it can do

The custom server has five tools: list events, search events, get an event by ID,
detect repeated failed logins, and save a report. The agent reads event data before
each answer and can ask for targeted event searches. It can inspect Git status and
recent commits through the published Git MCP server. When you ask for a report (or
use `--report`), it saves the answer through the custom MCP report tool under
`reports/`. Reports are local and ignored by Git.

The model sees only the four read-only event tools and two read-only Git tools.
The application chooses the report filename and calls the report tool itself.
Event details and tool responses are untrusted data, never code or instructions.
The agent rejects tool calls outside its allowlist and event IDs that were not
returned by MCP tools. Model answers are still interpretations; review reports
before relying on them. The sample events are fabricated and use documentation IPs.

## Install

Use Python 3.12 or newer, Git, and `uv`. From the repository root in PowerShell:

```powershell
cd hw4
uv sync --locked --group dev
```

This installs FastMCP, the MCP SDK, Google Gen AI, pytest, and the pinned published
`mcp-server-git` package. The Git server runs as a local subprocess and can inspect
this repository. No Git credentials are needed for the sample investigation.

Set a Gemini API key in the current PowerShell session before asking questions.
The key is read from `GEMINI_API_KEY`; never put it in a file in the repository.
This prompt masks the value and keeps it out of shell history:

```powershell
$secret = Read-Host "Gemini API key" -AsSecureString
$pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secret)
try { $env:GEMINI_API_KEY = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer) }
finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
```

The default model is `gemini-3.6-flash`. Set `GEMINI_MODEL` in the shell if your
account uses another Gemini model. `.env` files and reports are ignored by Git.

## Run

From `hw4`, check both MCP connections without a Gemini key:

```powershell
uv run --locked python agent.py --check
```

Ask one question or open an interactive prompt:

```powershell
uv run --locked python agent.py "Which IP has repeated failed logins?"
uv run --locked python agent.py --report "Investigate the suspicious logins"
uv run --locked python agent.py
```

In interactive mode, enter `exit` or press Ctrl+C to stop. Asking for a report in
ordinary language also saves one. The custom MCP server can be launched alone for
an MCP client with `uv run --locked python mcp-server.py`; it waits for MCP messages
on STDIO, so an idle terminal is expected.

## Test

No key is needed for local tests. From `hw4`:

```powershell
uv run --locked --group dev python -m pytest -ra --basetemp=.pytest_tmp
```

The tests launch the actual STDIO servers, check event results and Git's read-only
path, and exercise input and report-path validation. `.pytest_tmp/` is ignored by
Git and excluded from pytest collection. The live Gemini API needs a key and is not
called by the automated suite. One existing test for end-to-end agent prompt
injection and secret redaction remains skipped until that behavior can be tested
with a controlled model setup.

## Project files

- `agent.py`: Gemini CLI, MCP clients, tool allowlist, and report workflow.
- `mcp-server.py`: custom STDIO event and report tools.
- `data/sample_events.json`: fake event fixture.
- `tests/`: real MCP connection and security tests.
- `reports/`: ignored local reports.
- `screencast_url.txt`: existing submission file.
