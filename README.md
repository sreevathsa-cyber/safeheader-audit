# SafeHeader Audit — Automated Web Scanner

## Project overview
SafeHeader Audit is a beginner-friendly Python tool that checks a website's initial HTTP response for HTTPS usage, selected security headers, and visible CORS response configuration. It creates HTML, JSON, and CSV reports.

## Objectives
- Inspect selected HTTP response security headers.
- Highlight missing headers for human review.
- Report visible CORS response configuration.
- Produce readable and machine-readable reports.
- Demonstrate practical Python, HTTP, and cybersecurity concepts.

## Features
- Python standard library only; no external packages required.
- HTTP status and final URL reporting.
- Checks for Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, and Permissions-Policy.
- Basic CORS response-header review.
- HTML, JSON, and CSV output.
- Handles common connection errors.

## Requirements
- Python 3.10 or later recommended.
- Internet access for public target websites.
- Test only websites you own or have explicit authorization to assess.

## Run on Windows
1. Extract the project ZIP.
2. Open the extracted folder in VS Code or Command Prompt.
3. Open a terminal in that folder.
4. Run:
   ```powershell
   python app.py https://example.com
   ```
   Replace the example with a site you are authorized to check.
5. Open the generated HTML report in the `reports` folder.

If `python` is not recognized, try `py app.py https://example.com`.

## Run on Linux/macOS
```bash
python3 app.py https://example.com
```

## Output
The `reports/` folder contains:
- `safeheader_report_<timestamp>.html` — formatted report for review/submission.
- `safeheader_report_<timestamp>.json` — structured result.
- `safeheader_report_<timestamp>.csv` — findings table.

## Methodology
1. Normalize and validate the supplied URL.
2. Send a single GET request with a timeout.
3. Capture the response status and headers.
4. Compare selected response headers against a small checklist.
5. Inspect the Access-Control-Allow-Origin and Access-Control-Allow-Credentials values when present.
6. Write findings and remediation suggestions to three report formats.

## Limitations
This is a basic configuration checker, not a comprehensive vulnerability scanner. It does not crawl the site, test authentication, exploit vulnerabilities, or conduct a full TLS audit. Missing headers do not automatically mean a vulnerability exists. CORS findings require context and validation.

## Ethical use
Only scan websites you own or have written permission to assess. Do not use the tool to disrupt services or access data without authorization.

## Suggested future improvements
- Add a graphical interface.
- Add unit tests and a test website.
- Add configurable header policies.
- Add a controlled OWASP ZAP baseline-scan integration for authorized targets.
