import json
import os
from mitmproxy import http

OUT_PATH = os.environ.get("CAPTURE_OUT", "mitmproxy_dump_raw.json")

flows = []

def request(flow: http.HTTPFlow) -> None:
    host = flow.request.pretty_host
    if "mixpanel.com" not in host and "mxpnl.com" not in host:
        return
    if flow.request.method != "POST":
        return
    flows.append({
        "method": flow.request.method,
        "url": flow.request.pretty_url,
        "host": host,
        "path": flow.request.path,
        "headers": dict(flow.request.headers),
        "content_type": flow.request.headers.get("content-type", ""),
        "body": flow.request.get_text(strict=False),
        "body_bytes_len": len(flow.request.raw_content) if flow.request.raw_content else 0,
    })

def done():
    with open(OUT_PATH, "w", encoding="utf-8") as f:
        json.dump(flows, f, indent=2, ensure_ascii=False)
    print(f"WROTE {len(flows)} flows -> {OUT_PATH}")
