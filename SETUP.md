# ntopng MCP Server — Setup Guide

## 1. Install Python dependencies

Open a terminal and run:

```
pip install mcp requests
```

## 2. Set your ntopng password

Set an environment variable so your password is never hardcoded:

**Windows (PowerShell):**
```powershell
$env:NTOPNG_PASS = "your_password_here"
```

To make it permanent, add it via System Properties → Environment Variables.

## 3. Test the server manually (optional)

```
python "D:\Cloude  IT\ntopng_mcp\ntopng_mcp.py"
```

It should start silently and wait — that means it's working.
Press Ctrl+C to stop.

## 4. Add to Claude

Open Claude settings → Developer → MCP Servers → Add new:

```json
{
  "ntopng": {
    "command": "python",
    "args": ["D:\\Cloude  IT\\ntopng_mcp\\ntopng_mcp.py"],
    "env": {
      "NTOPNG_URL": "http://192.168.1.7:3001",
      "NTOPNG_USER": "admin",
      "NTOPNG_PASS": "your_password_here",
      "NTOPNG_IFID": "3"
    }
  }
}
```

## Available Tools

| Tool | What it does |
|------|-------------|
| `get_interfaces` | List monitored interfaces |
| `get_interface_stats` | Real-time throughput & flow counts |
| `get_hosts` | All hosts sorted by traffic or risk |
| `get_host_details` | Deep dive into a specific IP |
| `get_active_flows` | Live connections on the network |
| `get_alerts` | Active security alerts |
| `get_top_hosts` | Highest bandwidth users right now |
| `get_top_applications` | Top protocols/apps by traffic |
| `search_host` | Look up any IP or MAC |

## Troubleshooting

- **"Cannot connect"** — make sure ntopng is running and port 3001 is accessible
- **401 Unauthorized** — check your password in the env variable
- **Empty results** — try `get_interfaces` first to confirm the correct `NTOPNG_IFID`
