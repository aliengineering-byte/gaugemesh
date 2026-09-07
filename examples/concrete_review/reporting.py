"""Offline HTML and Markdown reports from already-verified structured results."""
import hashlib
import html
import json
from pathlib import Path
import re


def exclusive_json(path, value):
    raw = (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False) + "\n").encode()
    with path.open("xb") as stream:
        stream.write(raw)


def documents(result):
    payload = json.dumps(result, indent=2, ensure_ascii=False, allow_nan=False)
    summary = result.get("calculation") or {}
    decimals = result.get("normalized", {}).get("displayDecimals", 3)
    response = summary.get("modelMoment_Nmm")
    response_text = "NOT_EVALUATED" if response is None else f"{response/1000000:.{decimals}f} kN·m"
    rows = [("Execution", result["executionState"]), ("Numerical verification", result["verificationState"]),
        ("Domain result", result["domainStatus"]), ("Prescribed-strain model response", response_text),
        ("Standards rules", "SOURCE_AUTHORIZATION_REQUIRED"), ("Professional decision", "HUMAN_REVIEW_REQUIRED")]
    missing = result.get("diagnostic")
    detail = "" if missing is None else f"<p class=warning>{html.escape(str(missing))}</p>"
    cards = "".join(f"<article><h2>{html.escape(title)}</h2><p>{html.escape(value)}</p></article>" for title, value in rows)
    conversions = result.get("normalized", {}).get("conversions", [])
    table = "".join(f"<tr><td>{html.escape(item['field'])}</td><td>{html.escape(item['original']['value']+' '+item['original']['unit'])}</td><td>{html.escape(item['normalizedDecimal']+' '+item['normalizedUnit'])}</td></tr>" for item in conversions)
    exclusions = "".join(f"<li>{html.escape(name)}: {html.escape(status)}</li>" for name, status in result["coverage"].items())
    document = f"""<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>GaugeMesh — optional mechanics review</title><style>
body{{font:16px/1.55 system-ui,sans-serif;max-width:1080px;margin:32px auto;padding:0 24px;color:#172c39;background:#f6f8f9}}
h1{{font-size:32px;line-height:1.2}}h2{{font-size:14px;font-weight:500;color:#49616e}}.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px}}article{{padding:16px;background:white;border:1px solid #c9d5db;border-radius:8px}}article p{{font-weight:650;overflow-wrap:anywhere}}.warning{{padding:16px;border-left:5px solid #b25e16;background:#fff3df}}table{{border-collapse:collapse;width:100%;background:white}}th,td{{padding:8px;text-align:left;border-bottom:1px solid #d5dfe4;overflow-wrap:anywhere}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:white;padding:16px;border:1px solid #c9d5db}}a{{color:#175f8a}}
</style><header><p>GaugeMesh / optional external consumer / educational scope</p><h1>Inspect the section response, not a construction approval</h1>
<p>Define the task. Execute it under controls. Inspect the result.</p></header>
<p class="warning">Original declared constitutive assumptions only. No code capacity, reduction factor, adopted-code check, or approval is provided. Real-project decisions require qualified professional and applicable-authority review.</p>
{detail}<section class="cards">{cards}</section>
<h2>Confirmed scope and assumptions</h2><pre>{html.escape(json.dumps(result.get('scopeAndAssumptions'), indent=2))}</pre>
<h2>Unrounded comparison</h2><pre>{html.escape(json.dumps(result.get('comparison'), indent=2))}</pre>
<p>Display rounding affects presentation only. The comparison uses unrounded values and an explicit numerical tolerance band. A service/factored label applies no load or resistance factor.</p>
<h2>Supplied and normalized quantities</h2><table><thead><tr><th>Field</th><th>Supplied</th><th>Normalized</th></tr></thead><tbody>{table}</tbody></table>
<h2>Coverage boundary</h2><ul>{exclusions}</ul>
<h2>Offline verification</h2><pre>{html.escape(result.get('verificationCommand', 'No accepted Run evidence exists for this input-review result.'))}</pre>
<p>Keep the original artifact root and trusted export. Verification hashes are not signatures. This file has no scripts, remote assets, or automatic network calls.</p>
<details><summary>Exact structured result, original input, computational trace and producer identity</summary><pre>{html.escape(payload)}</pre></details>
<footer><p>Optional <a href="https://github.com/aliengineering-byte/gaugemesh/issues/new">sanitized feedback</a>: remove private inputs and sensitive paths before sharing. Nothing is sent automatically.</p></footer></html>"""
    fence = "`" * max(3, 1 + max((len(match) for match in re.findall(r"`+", payload)), default=0))
    markdown = "# Optional section mechanics review\n\n" + "\n".join(f"- {title}: {value}" for title, value in rows)
    markdown += "\n\nOriginal declared model only; no code capacity or construction approval. Qualified professional review required.\n\n"
    markdown += result.get("verificationCommand", "No accepted Run evidence to verify.") + "\n\n" + fence + "json\n" + payload + "\n" + fence + "\n"
    return document, markdown


def render(root, result, name="report"):
    document, markdown = documents(result)
    for suffix, text in ((".html", document), (".md", markdown)):
        with (root / (name + suffix)).open("x", encoding="utf-8") as stream:
            stream.write(text)
    exclusive_json(root / (name + ".json"), result)
    return {name + suffix: hashlib.sha256((root / (name + suffix)).read_bytes()).hexdigest() for suffix in (".html", ".md", ".json")}
