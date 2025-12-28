# PatchPilot MCP

Security scanner for vibe coders. Checks npm packages for known vulnerabilities before you install them.

## What it does

PatchPilot is an MCP server that integrates with Claude Code, Cursor, and other AI coding tools. When you're about to install a package, you can ask Claude to check if it's safe first.

**Example:**
```
You: "Check if lodash@4.17.0 is safe to use"
Claude: 🚨 lodash@4.17.0 has 4 known vulnerabilities!
        ...
        💡 Recommendation: Update to lodash@4.17.21 or later
```

## Installation

### Prerequisites
- Node.js 18+
- Claude Code or another MCP-compatible client

### Setup

1. Clone this repository:
```bash
git clone https://github.com/YOUR_USERNAME/patchpilot-mcp.git
cd patchpilot-mcp
```

2. Install dependencies:
```bash
npm install
```

3. Build:
```bash
npm run build
```

### Add to Claude Code

Add to your Claude Code config (`~/.claude/settings.json`):

```json
{
  "mcpServers": {
    "patchpilot": {
      "command": "node",
      "args": ["/path/to/patchpilot-mcp/dist/index.js"]
    }
  }
}
```

Or for development (without building):

```json
{
  "mcpServers": {
    "patchpilot": {
      "command": "npx",
      "args": ["tsx", "/path/to/patchpilot-mcp/src/index.ts"]
    }
  }
}
```

Restart Claude Code after adding the config.

## Usage

Once installed, ask Claude to check packages:

- "Check if express@4.17.0 is safe"
- "Is next@14.1.0 secure?"
- "Check lodash 4.17.0 for vulnerabilities"

## How it works

PatchPilot uses the [OSV API](https://osv.dev/) (Google's Open Source Vulnerabilities database) to check packages. The API is:
- Free (no API key needed)
- Fast
- Comprehensive (aggregates data from npm, GitHub, NVD, and more)

## Available Tools

### `check_package`

Check a single npm package for known vulnerabilities.

**Input:**
- `name`: Package name (e.g., "lodash")
- `version`: Package version (e.g., "4.17.0")

**Output:**
- Vulnerability count and severity breakdown
- Details of each vulnerability
- Recommended fix version

## License

MIT
