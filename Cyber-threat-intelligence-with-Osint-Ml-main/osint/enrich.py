import re
import requests
import tldextract
import socket


def ip_geolocate(ip: str, ipinfo_token: str | None = None):
    """Geolocate an IP address using ip-api.com"""
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=8)
        if resp.ok:
            d = resp.json()
            return {
                "asn": d.get("as"),
                "city": d.get("city"),
                "region": d.get("regionName"),
                "country": d.get("country"),
                "loc": f"{d.get('lat')},{d.get('lon')}",
                "source": "ip-api"
            }
    except Exception:
        pass
    return {}


def http_head(url: str):
    """Perform HTTP HEAD request to check URL status."""
    try:
        r = requests.head(url, allow_redirects=True, timeout=8)
        return {
            "status": r.status_code,
            "final_url": r.url,
            "headers": dict(r.headers)
        }
    except Exception:
        return {}


def dns_lookup(domain: str):
    """Simple DNS A-record lookup."""
    try:
        return socket.gethostbyname_ex(domain)
    except Exception:
        return {}


def detect_type(value: str) -> str:
    """Detect indicator type (very basic)."""
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", value):
        return "ip"
    elif value.startswith("http://") or value.startswith("https://"):
        return "url"
    elif re.match(r"^[a-fA-F0-9]{32}$", value):
        return "md5"
    elif re.match(r"^[a-fA-F0-9]{64}$", value):
        return "sha256"
    elif "." in value:
        return "domain"
    return "unknown"


def enrich_indicator(value: str, ipinfo_token: str | None = None):
    """Enrich a single indicator (IP, domain, URL, hash)."""
    kind = detect_type(value)
    row = {"indicator": value, "type": kind, "summary": {}}
    try:
        if kind == 'ip':
            geo = ip_geolocate(value, ipinfo_token=ipinfo_token)
            row["summary"].update({"geolocation": geo})
        elif kind == 'domain':
            ext = tldextract.extract(value)
            fqdn = f"{ext.domain}.{ext.suffix}" if ext.suffix else value
            dnsr = dns_lookup(fqdn)
            row["summary"].update({"domain": fqdn, "dns": dnsr})
        elif kind == 'url':
            h = http_head(value)
            row["summary"].update(h)
        elif kind in ('md5', 'sha256'):
            # Placeholder – typically you would query VirusTotal, etc.
            row["summary"].update({
                "note": "Hash enrichment requires VT/OTX API – add in code if you have keys."
            })
        else:
            row["summary"].update({"note": "Unknown indicator type."})
    except Exception as e:
        row["summary"].update({"error": str(e)})
    return row


def enrich_indicator_batch(values: list[str], ipinfo_token: str | None = None):
    """Enrich a batch of indicators."""
    results = []
    for v in values:
        results.append(enrich_indicator(v, ipinfo_token=ipinfo_token))
    return {"count": len(results), "items": results}