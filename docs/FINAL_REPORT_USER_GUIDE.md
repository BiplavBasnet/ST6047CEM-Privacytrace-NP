# Final Investigation Report — User Guide

## What it is

The **Final Investigation Report** is a privacy-safe export that combines one incident’s investigation into a single document suitable for thesis demonstration, analyst review, DevSecOps handoff, or audit summary.

PrivacyTrace-NP **does not** assign blame, close incidents automatically, or guarantee remediation.

## How to export

From the **Incident detail** page (Reports section), use:

- **Download PDF** — formal printable report  
- **Download HTML** — browser-readable report  
- **Download JSON** — structured machine-readable report  
- **Download Evidence CSV** — evidence inventory (metadata only)  
- **Download Report Bundle** — ZIP with all of the above plus README  

Requires the `report:generate` permission (Analyst, Admin, etc.).

## What is included

- Masked detections and evidence IDs  
- Likely root-cause ranking with confidence bands  
- Human review and fix verification status (if completed)  
- ScannerBridge-NP supporting evidence when linked  
- Guarded explanation when generated  
- Sanitised audit summary  
- Recommendations and limitations  

## What is never included

- Raw phone numbers, wallet IDs, tokens, API keys, passwords  
- Raw log files or raw scanner payloads  
- “Proven cause” or “confirmed blame” language  

## Safety notice

All exports are scanned before delivery. If unsafe content cannot be masked, it is omitted and a generic safety warning may appear — the unsafe value is never echoed back.
