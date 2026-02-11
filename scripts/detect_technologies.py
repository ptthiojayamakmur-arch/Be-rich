from typing import Dict, Any
import re
import socket
import ssl

def detect_technologies(domain: str, timeout: int = 10, verbose: bool = False) -> Dict[str, Any]:
    """Detect web technologies, frameworks, CMS, and server information for a domain.

    Returns a dictionary with keys: web_server, frameworks, cms, analytics, cdn,
    hosting_provider, technologies, security_headers, ssl_info, checked, error.
    """
    try:
        import requests
    except Exception as e:
        return {"checked": False, "error": f"requests unavailable: {e}"}

    # optional rich progress
    use_rich = False
    try:
        from rich.progress import Progress, SpinnerColumn, TextColumn
        from rich.console import Console
        console = Console()
        use_rich = True
    except Exception:
        use_rich = False

    def _log(msg: str):
        if verbose and not use_rich:
            print(msg)

    url = domain if domain.startswith(("http://", "https://")) else f"https://{domain}"
    result: Dict[str, Any] = {
        "web_server": None,
        "frameworks": [],
        "cms": None,
        "analytics": [],
        "cdn": None,
        "hosting_provider": None,
        "technologies": [],
        "security_headers": {},
        "ssl_info": {},
        "checked": False,
        "error": None,
    }

    def probe():
        try:
            _log(f"Requesting {url}")
            resp = requests.get(url, timeout=timeout, allow_redirects=True)
        except requests.exceptions.SSLError:
            # try http as fallback
            try:
                url_http = url.replace("https://", "http://")
                _log(f"SSL error, trying HTTP: {url_http}")
                resp = requests.get(url_http, timeout=timeout, allow_redirects=True)
            except Exception as e:
                result["error"] = f"request failed: {e}"
                return
        except Exception as e:
            result["error"] = f"request failed: {e}"
            return

        headers = {k.lower(): v for k, v in resp.headers.items()}
        html = resp.text or ""

        # web server
        server = headers.get("server")
        if server:
            result["web_server"] = server

        # hosting / CDN heuristics
        if (server and "cloudflare" in server.lower()) or "cf-ray" in headers:
            result["cdn"] = "Cloudflare"
            result["hosting_provider"] = "Cloudflare"
        elif server and "akamai" in server.lower() or headers.get("x-akamai-request-id"):
            result["cdn"] = "Akamai"
        elif headers.get("x-cache") and "fastly" in headers.get("x-cache", "").lower():
            result["cdn"] = "Fastly"

        # security headers
        for h in ("content-security-policy", "strict-transport-security", "x-frame-options",
                  "x-content-type-options", "referrer-policy", "x-xss-protection"):
            if h in headers:
                result["security_headers"][h] = headers[h]

        # CMS / framework heuristics (HTML + headers)
        if re.search(r"wp-?(content|includes)|<meta name=[\"']generator[\"'] content=[\"']WordPress", html, re.I):
            result["cms"] = "WordPress"
        if re.search(r"Joomla!|com_content", html, re.I):
            result["cms"] = result.get("cms") or "Joomla"
        if re.search(r"drupalSettings|Drupal", html, re.I):
            result["cms"] = result.get("cms") or "Drupal"

        # frameworks: simple heuristics
        if re.search(r"\bReact\.|react-dom|data-reactroot", html, re.I):
            result["frameworks"].append("React")
        if re.search(r"ng-app|angular\.js|@angular", html, re.I):
            result["frameworks"].append("Angular")
        if re.search(r"vue\.js|new Vue\(", html, re.I):
            result["frameworks"].append("Vue")
        if "x-powered-by" in headers:
            xp = headers["x-powered-by"]
            result["frameworks"].append(xp)

        # analytics detection
        if re.search(r"googletagmanager|gtag\.js|analytics\.js|UA-\d{4,}", html, re.I):
            result["analytics"].append("Google Analytics/GTAG")
        if re.search(r"collect\.hotjar\.com|hotjar", html, re.I):
            result["analytics"].append("Hotjar")
        if re.search(r"mixpanel", html, re.I):
            result["analytics"].append("Mixpanel")

        # script src / asset heuristics for CDN detection
        if re.search(r"cdnjs\.cloudflare\.com|akamai|cdn\.jsdelivr\.net|cdn\.bootstrapcdn\.com", html, re.I):
            result["cdn"] = result.get("cdn") or "Public CDN"

        # aggregate technologies
        techs = set()
        if result.get("web_server"):
            techs.add(result["web_server"])
        techs.update(result.get("frameworks", []))
        if result.get("cms"):
            techs.add(result["cms"])
        techs.update(result.get("analytics", []))
        if result.get("cdn"):
            techs.add(result["cdn"])
        result["technologies"] = [t for t in techs if t]

        # SSL / certificate basic info
        try:
            host = domain.replace("https://", "").replace("http://", "").split("/")[0]
            port = 443
            _log(f"Retrieving cert for {host}:{port}")
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as sslsock:
                    cert = sslsock.getpeercert()
                    result["ssl_info"] = {
                        "subject": dict(x[0] for x in cert.get("subject", [])) if cert.get("subject") else cert.get("subject"),
                        "issuer": dict(x[0] for x in cert.get("issuer", [])) if cert.get("issuer") else cert.get("issuer"),
                        "notBefore": cert.get("notBefore"),
                        "notAfter": cert.get("notAfter"),
                    }
        except Exception as e:
            # non-fatal; note reason
            result["ssl_info"] = {"error": str(e)}

        result["checked"] = True

    # run with progress if available
    if use_rich:
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console, transient=True) as progress:
            task = progress.add_task("[cyan]Detecting web technologies and server info...", total=None)
            probe()
            progress.stop_task(task)
    else:
        probe()

    return result
