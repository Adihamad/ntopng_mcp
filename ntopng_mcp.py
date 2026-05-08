#!/usr/bin/env python3
"""
ntopng MCP Server — HTTP/SSE transport
Runs as a Docker container on your NAS.
Claude connects to it over the network at http://nas-ip:3002/sse
"""

import os
import json
import asyncio
import requests

import uvicorn
from starlette.applications import Starlette
from starlette.routing import Mount, Route

from mcp.server import Server
from mcp.server.sse import SseServerTransport
from mcp import types

# ── Configuration (set via Docker environment variables) ──────────────────────
NTOPNG_URL    = os.getenv("NTOPNG_URL",   "http://192.168.1.7:3001")
NTOPNG_USER   = os.getenv("NTOPNG_USER",  "admin")
NTOPNG_PASS   = os.getenv("NTOPNG_PASS",  "")
NTOPNG_TOKEN  = os.getenv("NTOPNG_TOKEN", "")   # preferred: REST API token
DEFAULT_IFID  = int(os.getenv("NTOPNG_IFID", "3"))
PORT          = int(os.getenv("MCP_PORT", "3002"))
# ──────────────────────────────────────────────────────────────────────────────

session = requests.Session()
_authenticated = False


def authenticate() -> bool:
    """Log in to ntopng via CSRF-aware form login and store session cookie."""
    global _authenticated
    try:
        import re
        # Step 1: fetch login page and extract CSRF token
        r = session.get(f"{NTOPNG_URL}/lua/login.lua", timeout=15)
        csrf = ""
        match = re.search(r'name=["\']csrf["\'][^>]*value=["\']([^"\']+)["\']|value=["\']([^"\']+)["\'][^>]*name=["\']csrf["\']', r.text)
        if match:
            csrf = match.group(1) or match.group(2)

        # Step 2: POST credentials + CSRF
        r = session.post(
            f"{NTOPNG_URL}/lua/login.lua",
            data={"user": NTOPNG_USER, "password": NTOPNG_PASS, "csrf": csrf, "referer": "/"},
            timeout=15,
            allow_redirects=True,
        )
        _authenticated = "<title>Welcome to ntopng" not in r.text
        return _authenticated
    except Exception:
        return False


def api(endpoint: str, params: dict = None) -> dict:
    """Make an authenticated GET request to the ntopng REST API."""
    global _authenticated
    url = f"{NTOPNG_URL}{endpoint}"
    p = params or {}

    try:
        r = requests.get(url, params=p, timeout=15)
        r.raise_for_status()
        try:
            return r.json()
        except Exception:
            return {"error": f"Non-JSON response (status {r.status_code})", "raw": r.text[:500]}
    except requests.exceptions.ConnectionError:
        return {"error": f"Cannot connect to ntopng at {NTOPNG_URL}"}
    except requests.exceptions.HTTPError as e:
        return {"error": f"HTTP {r.status_code}: {str(e)}", "raw": r.text[:500]}
    except Exception as e:
        return {"error": str(e)}


def ok(data: dict) -> str:
    """Return clean JSON, extracting the rsp payload if present."""
    if isinstance(data, dict) and "rsp" in data:
        return json.dumps(data["rsp"], indent=2)
    return json.dumps(data, indent=2)


# ── MCP Server ────────────────────────────────────────────────────────────────
server = Server("ntopng")


@server.list_tools()
async def list_tools() -> list[types.Tool]:
    return [
        types.Tool(
            name="debug_config",
            description="Show current configuration and test raw connectivity to ntopng.",
            inputSchema={"type": "object", "properties": {}},
        ),
        types.Tool(
            name="get_interfaces",
            description="List all network interfaces being monitored by ntopng. Use this first to confirm the correct interface ID.",
            inputSchema={"type": "object", "properties": {}},
        ),
        types.Tool(
            name="get_interface_stats",
            description="Get real-time stats for a network interface: throughput, packet rates, active flows, top protocols.",
            inputSchema={
                "type": "object",
                "properties": {
                    "ifid": {"type": "integer", "description": f"Interface ID (default: {DEFAULT_IFID})"},
                },
            },
        ),
        types.Tool(
            name="get_hosts",
            description="List all hosts currently seen on the network with traffic stats, risk scores, and alert counts.",
            inputSchema={
                "type": "object",
                "properties": {
                    "ifid": {"type": "integer", "description": f"Interface ID (default: {DEFAULT_IFID})"},
                    "sortColumn": {
                        "type": "string",
                        "description": "Sort by: 'column_thpt' (throughput), 'column_score' (risk), 'column_bytes' (total traffic), 'column_alerts_count'",
                        "default": "column_thpt",
                    },
                    "currentPage": {"type": "integer", "default": 1},
                    "perPage": {"type": "integer", "description": "Max 100", "default": 25},
                },
            },
        ),
        types.Tool(
            name="get_host_details",
            description="Get detailed info about a specific host: protocols, flows, ports, DNS, HTTP, risk score breakdown.",
            inputSchema={
                "type": "object",
                "required": ["host"],
                "properties": {
                    "host": {"type": "string", "description": "IP address (e.g. '192.168.1.7')"},
                    "ifid": {"type": "integer", "description": f"Interface ID (default: {DEFAULT_IFID})"},
                },
            },
        ),
        types.Tool(
            name="get_active_flows",
            description="Get currently active network flows (connections). Shows source, destination, protocol, bytes, and application.",
            inputSchema={
                "type": "object",
                "properties": {
                    "ifid": {"type": "integer", "description": f"Interface ID (default: {DEFAULT_IFID})"},
                    "host": {"type": "string", "description": "Filter by host IP (optional)"},
                    "application": {"type": "string", "description": "Filter by app e.g. 'TLS', 'HTTP', 'DNS' (optional)"},
                    "currentPage": {"type": "integer", "default": 1},
                    "perPage": {"type": "integer", "default": 25},
                },
            },
        ),
        types.Tool(
            name="get_alerts",
            description="Get active security alerts on the network: type, severity, host, and description.",
            inputSchema={
                "type": "object",
                "properties": {
                    "ifid": {"type": "integer", "description": f"Interface ID (default: {DEFAULT_IFID})"},
                    "currentPage": {"type": "integer", "default": 1},
                    "perPage": {"type": "integer", "default": 25},
                },
            },
        ),
        types.Tool(
            name="get_top_hosts",
            description="Get the highest bandwidth-consuming hosts right now.",
            inputSchema={
                "type": "object",
                "properties": {
                    "ifid": {"type": "integer", "description": f"Interface ID (default: {DEFAULT_IFID})"},
                },
            },
        ),
        types.Tool(
            name="get_top_applications",
            description="Get top protocols/apps by traffic volume (e.g. TLS, HTTP, DNS, YouTube, Netflix).",
            inputSchema={
                "type": "object",
                "properties": {
                    "ifid": {"type": "integer", "description": f"Interface ID (default: {DEFAULT_IFID})"},
                },
            },
        ),
        types.Tool(
            name="search_host",
            description="Look up a specific host by IP address and get a full summary of its activity.",
            inputSchema={
                "type": "object",
                "required": ["query"],
                "properties": {
                    "query": {"type": "string", "description": "IP address to look up"},
                    "ifid": {"type": "integer", "description": f"Interface ID (default: {DEFAULT_IFID})"},
                },
            },
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[types.TextContent]:
    ifid = arguments.get("ifid", DEFAULT_IFID)
    result = ""

    if name == "debug_config":
        def probe(path):
            try:
                r = requests.get(f"{NTOPNG_URL}{path}", timeout=8)
                try:
                    return {"status": r.status_code, "json": True, "data": r.json()}
                except Exception:
                    return {"status": r.status_code, "json": False, "preview": r.text[:120]}
            except Exception as e:
                return {"error": str(e)}

        results = {
            "config": {"ntopng_url": NTOPNG_URL},
            "endpoints": {
                "v2_interface_list":    probe("/lua/rest/v2/get/interface/list.lua"),
                "v2_ntopng_interfaces": probe("/lua/rest/v2/get/ntopng/interfaces.lua"),
                "v2_interface_data":    probe("/lua/rest/v2/get/interface/data.lua?ifid=3"),
                "v1_interface_list":    probe("/lua/rest/v1/get/interface/list.lua"),
                "v2_host_list":         probe("/lua/rest/v2/get/host/list.lua?ifid=3"),
                "root":                 probe("/"),
                "lua_index":            probe("/lua/index.lua"),
            }
        }
        result = json.dumps(results, indent=2)

    elif name == "get_interfaces":
        data = api("/lua/rest/v2/get/ntopng/interfaces.lua")
        result = ok(data)

    elif name == "get_interface_stats":
        data = api("/lua/rest/v2/get/interface/data.lua", {"ifid": ifid})
        result = ok(data)

    elif name == "get_hosts":
        params = {
            "ifid": ifid,
            "sortColumn": arguments.get("sortColumn", "column_thpt"),
            "sortOrder": "desc",
            "currentPage": arguments.get("currentPage", 1),
            "perPage": min(arguments.get("perPage", 25), 100),
        }
        data = api("/lua/rest/v2/get/host/active.lua", params)
        result = ok(data)

    elif name == "get_host_details":
        params = {"ifid": ifid, "host": arguments["host"], "version": 4}
        data = api("/lua/rest/v2/get/host/data.lua", params)
        result = ok(data)

    elif name == "get_active_flows":
        params = {
            "ifid": ifid,
            "currentPage": arguments.get("currentPage", 1),
            "perPage": min(arguments.get("perPage", 25), 100),
            "sortColumn": "column_bytes",
            "sortOrder": "desc",
        }
        if arguments.get("host"):
            params["host"] = arguments["host"]
        if arguments.get("application"):
            params["application"] = arguments["application"]
        data = api("/lua/rest/v2/get/flow/active.lua", params)
        result = ok(data)

    elif name == "get_alerts":
        params = {
            "ifid": ifid,
            "currentPage": arguments.get("currentPage", 1),
            "perPage": min(arguments.get("perPage", 25), 100),
        }
        data = api("/lua/rest/v2/get/all/alert/list.lua", params)
        result = ok(data)

    elif name == "get_top_hosts":
        params = {"ifid": ifid, "max_hits": 10}
        data = api("/lua/rest/v2/get/host/active.lua", params)
        result = ok(data)

    elif name == "get_top_applications":
        data = api("/lua/rest/v2/get/interface/l7/stats.lua", {"ifid": ifid})
        result = ok(data)

    elif name == "search_host":
        params = {"ifid": ifid, "host": arguments["query"], "version": 4}
        data = api("/lua/rest/v2/get/host/data.lua", params)
        result = ok(data)

    else:
        result = json.dumps({"error": f"Unknown tool: {name}"})

    return [types.TextContent(type="text", text=result)]


# ── SSE / HTTP transport ───────────────────────────────────────────────────────
sse = SseServerTransport("/messages")


async def handle_sse(request):
    async with sse.connect_sse(
        request.scope, request.receive, request._send
    ) as streams:
        await server.run(
            streams[0], streams[1], server.create_initialization_options()
        )


app = Starlette(
    routes=[
        Route("/sse", endpoint=handle_sse),
        Mount("/messages", app=sse.handle_post_message),
    ]
)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=PORT)
