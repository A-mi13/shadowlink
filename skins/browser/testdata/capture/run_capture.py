import asyncio
import os
import subprocess
import sys
import time
from pathlib import Path
from playwright.async_api import async_playwright

HERE = Path(__file__).parent
HTML = HERE / "mixpanel_capture.html"
DUMP_OUT = HERE / "mitmproxy_dump_raw.json"

TOKEN = os.environ.get("MIXPANEL_TOKEN")
if not TOKEN:
    print("ERROR: set MIXPANEL_TOKEN env var (signup at mixpanel.com -> project token)", file=sys.stderr)
    sys.exit(2)

async def main():
    if DUMP_OUT.exists():
        DUMP_OUT.unlink()
    env = os.environ.copy()
    env["CAPTURE_OUT"] = str(DUMP_OUT)
    mitm = subprocess.Popen([
        sys.executable, "-m", "mitmproxy.tools.dump",
        "-q",
        "-s", str(HERE / "mitmproxy_dump.py"),
        "--listen-host", "127.0.0.1",
        "--listen-port", "8080",
        "--set", "ssl_insecure=true",
    ], env=env)
    time.sleep(3)

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                proxy={"server": "http://127.0.0.1:8080"},
                args=["--ignore-certificate-errors"],
            )
            ctx = await browser.new_context(ignore_https_errors=True)
            page = await ctx.new_page()
            await page.add_init_script(f'window.__MIXPANEL_TOKEN__ = "{TOKEN}";')
            await page.goto(f"file://{HTML.resolve()}")
            await page.wait_for_function("document.title === 'CAPTURE_COMPLETE'", timeout=120_000)
            print("harness reported CAPTURE_COMPLETE")
            await browser.close()
    finally:
        mitm.terminate()
        try:
            mitm.wait(timeout=10)
        except subprocess.TimeoutExpired:
            mitm.kill()

    if not DUMP_OUT.exists():
        print("ERROR: dump file not written -- check mitmproxy logs", file=sys.stderr)
        sys.exit(3)
    print(f"OK: raw dump at {DUMP_OUT}")

asyncio.run(main())
