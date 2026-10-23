#!/usr/bin/env python3
"""
SafeHeader Audit — beginner-friendly website security configuration checker.

Checks HTTP response headers and basic HTTPS usage. It does not exploit
vulnerabilities or perform intrusive testing. Scan only sites you own or
have explicit permission to assess.
"""
from __future__ import annotations

import argparse
import csv
import html
import json
import socket
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

USER_AGENT = "SafeHeaderAudit/1.0 (educational security-header checker)"
TIMEOUT_SECONDS = 10

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "High",
        "Helps restrict which sources a browser may load content from. "
        "Review the application before choosing a policy."
    ),
    "Strict-Transport-Security": (
        "Medium",
        "Tells compatible browsers to prefer HTTPS for future visits. "
        "Only enable after confirming HTTPS is correctly configured."
    ),
    "X-Content-Type-Options": (
        "Low",
        "Set to 'nosniff' to reduce MIME-type sniffing risks."
    ),
    "X-Frame-Options": (
        "Medium",
        "Consider DENY or SAMEORIGIN, or use CSP frame-ancestors."
    ),
    "Referrer-Policy": (
        "Low",
        "Set a policy such as strict-origin-when-cross-origin to limit "
        "referrer information exposure."
    ),
    "Permissions-Policy": (
        "Low",
        "Restrict browser features that the site does not need."
    ),
}

def normalize_url(raw: str) -> str:
    raw = raw.strip()
    if not raw:
        raise ValueError("Please enter a website URL.")
    if "://" not in raw:
        raw = "https://" + raw
    parsed = urllib.parse.urlparse(raw)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only http:// and https:// URLs are supported.")
    if not parsed.hostname:
        raise ValueError("The URL must include a valid hostname.")
    if parsed.username or parsed.password:
        raise ValueError("URLs containing embedded usernames/passwords are not accepted.")
    return urllib.parse.urlunparse(
        (parsed.scheme, parsed.netloc, parsed.path or "/", parsed.params, parsed.query, "")
    )

def fetch_response(url: str):
    request = urllib.request.Request(
        url,
        headers={"User-Agent": USER_AGENT, "Accept": "text/html,*/*;q=0.8"},
        method="GET",
    )
    try:
        return urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS)
    except urllib.error.HTTPError as exc:
        # HTTP errors still have a response and headers worth examining.
        return exc

def audit(url: str) -> dict:
    normalized = normalize_url(url)
    started = datetime.now(timezone.utc).isoformat(timespec="seconds")
    result = {
        "target": normalized,
        "scanned_at_utc": started,
        "status_code": None,
        "final_url": None,
        "https": normalized.lower().startswith("https://"),
        "server": "",
        "content_type": "",
        "headers": {},
        "cors": {},
        "findings": [],
        "error": None,
    }

    try:
        response = fetch_response(normalized)
        try:
            result["status_code"] = getattr(response, "status", None) or response.getcode()
            result["final_url"] = response.geturl()
            headers = {k.lower(): v.strip() for k, v in response.headers.items()}
            result["headers"] = headers
            result["server"] = headers.get("server", "")
            result["content_type"] = headers.get("content-type", "")
        finally:
            response.close()
    except (urllib.error.URLError, socket.timeout, TimeoutError, ssl.SSLError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        result["error"] = str(reason)
        result["findings"].append({
            "severity": "Info",
            "check": "Connection",
            "status": "Could not connect",
            "details": f"Connection failed: {reason}",
            "recommendation": "Check the URL, DNS, network access, and whether the site is reachable.",
        })
        return result

    headers = result["headers"]

    if not result["https"]:
        result["findings"].append({
            "severity": "High",
            "check": "HTTPS",
            "status": "HTTP URL",
            "details": "The supplied URL uses HTTP rather than HTTPS.",
            "recommendation": "Use HTTPS and redirect HTTP traffic to HTTPS where appropriate.",
        })
    else:
        result["findings"].append({
            "severity": "Info",
            "check": "HTTPS",
            "status": "HTTPS URL",
            "details": "The supplied URL uses HTTPS. This check does not constitute a full TLS configuration audit.",
            "recommendation": "Keep TLS certificates valid and use modern TLS configuration.",
        })

    for name, (severity, recommendation) in SECURITY_HEADERS.items():
        value = headers.get(name.lower())
        if value:
            result["findings"].append({
                "severity": "Info",
                "check": name,
                "status": "Present",
                "details": f"Header is present: {value[:300]}",
                "recommendation": f"Review the value to ensure it suits the application. {recommendation}",
            })
        else:
            result["findings"].append({
                "severity": severity,
                "check": name,
                "status": "Missing",
                "details": f"The {name} response header was not observed.",
                "recommendation": recommendation,
            })

    acao = headers.get("access-control-allow-origin")
    acac = headers.get("access-control-allow-credentials", "").lower()
    result["cors"] = {
        "access_control_allow_origin": acao or "",
        "access_control_allow_credentials": acac or "",
    }
    if acao == "*" and acac == "true":
        result["findings"].append({
            "severity": "High",
            "check": "CORS configuration",
            "status": "Review required",
            "details": "The response includes Access-Control-Allow-Origin: * and Access-Control-Allow-Credentials: true.",
            "recommendation": "Verify the actual server behavior and browser handling. Use an explicit trusted-origin allowlist when credentials are needed.",
        })
    elif acao == "*":
        result["findings"].append({
            "severity": "Medium",
            "check": "CORS configuration",
            "status": "Wildcard origin observed",
            "details": "The response includes Access-Control-Allow-Origin: *.",
            "recommendation": "Confirm that public cross-origin access is intentional. A wildcard alone is not automatically a vulnerability.",
        })
    elif acao:
        result["findings"].append({
            "severity": "Info",
            "check": "CORS configuration",
            "status": "Origin policy observed",
            "details": f"Access-Control-Allow-Origin: {acao}",
            "recommendation": "Verify that only intended origins are allowed and that credential handling is appropriate.",
        })
    else:
        result["findings"].append({
            "severity": "Info",
            "check": "CORS configuration",
            "status": "No CORS allow-origin header observed",
            "details": "The response did not include Access-Control-Allow-Origin.",
            "recommendation": "This may be appropriate. Configure CORS only if cross-origin browser access is required.",
        })

    return result

def make_html_report(result: dict, out_path: Path) -> None:
    rows = []
    for item in result["findings"]:
        rows.append(
            "<tr>"
            f"<td>{html.escape(item['severity'])}</td>"
            f"<td>{html.escape(item['check'])}</td>"
            f"<td>{html.escape(item['status'])}</td>"
            f"<td>{html.escape(item['details'])}</td>"
            f"<td>{html.escape(item['recommendation'])}</td>"
            "</tr>"
        )
    err = f"<p class='error'>Connection error: {html.escape(result['error'])}</p>" if result["error"] else ""
    status = result["status_code"] if result["status_code"] is not None else "Unavailable"
    doc = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SafeHeader Audit Report</title>
<style>
body{{font-family:Arial,sans-serif;background:#0d1117;color:#e6edf3;margin:0;padding:24px}}
main{{max-width:1200px;margin:auto}}h1{{color:#58a6ff}}.card{{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:16px;margin:12px 0}}
table{{width:100%;border-collapse:collapse;background:#161b22}}th,td{{border:1px solid #30363d;padding:10px;text-align:left;vertical-align:top;overflow-wrap:anywhere}}
th{{background:#21262d}}.note{{color:#c9d1d9}}.error{{color:#ff7b72}}a{{color:#58a6ff}}
@media(max-width:800px){{body{{padding:10px}}table{{font-size:12px}}th,td{{padding:6px}}}}
</style></head><body><main>
<h1>🛡️ SafeHeader Audit</h1>
<p class="note">Educational security-header and CORS configuration review. Findings require human validation.</p>
<div class="card"><b>Target:</b> {html.escape(result['target'])}<br>
<b>Scan time (UTC):</b> {html.escape(result['scanned_at_utc'])}<br>
<b>HTTP status:</b> {html.escape(str(status))}<br>
<b>Final URL:</b> {html.escape(result['final_url'] or 'Unavailable')}<br>
<b>HTTPS URL supplied:</b> {'Yes' if result['https'] else 'No'}</div>
{err}
<h2>Findings</h2><table><thead><tr><th>Severity</th><th>Check</th><th>Status</th><th>Observation</th><th>Recommendation</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table>
<div class="card"><b>Limitations</b><p>This tool checks the initial HTTP response only. It does not crawl pages, authenticate, test exploitability, validate all TLS properties, or perform an active vulnerability scan. A missing header is not proof of a vulnerability. Use only on systems you own or are authorized to assess.</p></div>
</main></body></html>"""
    out_path.write_text(doc, encoding="utf-8")

def save_json(result: dict, path: Path) -> None:
    path.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")

def save_csv(result: dict, path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["severity", "check", "status", "details", "recommendation"])
        writer.writeheader()
        writer.writerows(result["findings"])

def main():
    parser = argparse.ArgumentParser(description="SafeHeader Audit: basic HTTP security-header and CORS checker")
    parser.add_argument("url", nargs="?", help="Target URL, e.g. https://example.com")
    parser.add_argument("--out", default="reports", help="Output folder (default: reports)")
    args = parser.parse_args()
    raw_url = args.url or input("Enter a website URL you are authorized to check: ").strip()
    try:
        result = audit(raw_url)
    except ValueError as exc:
        print(f"Input error: {exc}", file=sys.stderr)
        return 2

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    stem = f"safeheader_report_{stamp}"
    html_path = out_dir / f"{stem}.html"
    json_path = out_dir / f"{stem}.json"
    csv_path = out_dir / f"{stem}.csv"
    make_html_report(result, html_path)
    save_json(result, json_path)
    save_csv(result, csv_path)

    print("\n=== SafeHeader Audit Summary ===")
    print(f"Target: {result['target']}")
    print(f"HTTP status: {result['status_code'] or 'Unavailable'}")
    print(f"Findings recorded: {len(result['findings'])}")
    if result["error"]:
        print(f"Connection error: {result['error']}")
    print(f"HTML report: {html_path}")
    print(f"JSON report: {json_path}")
    print(f"CSV report:  {csv_path}")
    print("\nReminder: findings are indicators for review, not proof of exploitability.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
