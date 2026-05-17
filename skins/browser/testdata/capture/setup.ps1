$ErrorActionPreference = "Stop"
# NOTE: pins use mitmproxy 12.x for Python 3.14 wheel compatibility
# (mitmproxy 11 cffi has no prebuilt wheels for py3.14, requires MSVC).
# playwright bumped to 1.58.0 (1.49.0 hard-pinned greenlet==3.1.1 which
# has no py3.14 wheels; 1.58.0 allows greenlet<4 -> resolves to 3.5.0).
# Addon API for our usage (flow.request.{method,headers,get_text,raw_content})
# is unchanged between v11 and v12.
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Push-Location $here
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m playwright install chromium
Write-Host "OK: capture environment ready in .venv"
Pop-Location
