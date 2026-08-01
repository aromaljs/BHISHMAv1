import socket
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse


MAX_CRAWL_PAGES = 20

WEB_PORTS = {
    80,
    443,
    8000,
    8008,
    8080,
    8081,
    8088,
    8443,
    8888,
    10000,
    20000,
}

COMMON_RESOURCES = [
    "/robots.txt",
    "/sitemap.xml",
    "/security.txt",
    "/.well-known/security.txt",
    "/admin",
    "/admin/",
    "/login",
    "/login.php",
    "/manage",
    "/manage.php",
    "/dashboard",
    "/upload",
    "/upload.php",
    "/search",
    "/search.php",
    "/backup",
    "/backup.zip",
    "/server-status",
    "/phpinfo.php",
]

INTERESTING_KEYWORDS = [
    "admin",
    "login",
    "manage",
    "dashboard",
    "upload",
    "search",
    "backup",
    "config",
    "private",
    "secret",
    "test",
    "dev",
    "old",
    "database",
    "db",
    "user",
    "staff",
]


class WebReconParser(HTMLParser):
    def __init__(self):
        super().__init__()

        self.title = ""
        self._in_title = False

        self.links = []
        self.forms = []
        self.inputs = []
        self.comments = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)

        if tag == "title":
            self._in_title = True

        if tag == "a":
            href = attrs.get("href")

            if href:
                self.links.append(href)

        if tag == "form":
            self.forms.append(
                {
                    "method": attrs.get("method", "GET").upper(),
                    "action": attrs.get("action", ""),
                }
            )

        if tag in ("input", "textarea", "select", "button"):
            self.inputs.append(
                {
                    "tag": tag,
                    "name": attrs.get("name", ""),
                    "type": attrs.get("type", ""),
                    "value": attrs.get("value", ""),
                }
            )

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._in_title:
            clean = data.strip()

            if clean:
                self.title += clean

    def handle_comment(self, data):
        clean = data.strip()

        if clean:
            self.comments.append(clean)


def _http_request(host, port, path="/", timeout=5):
    try:
        with socket.create_connection(
            (host, port),
            timeout=timeout,
        ) as sock:
            request = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                "User-Agent: BHISHMA-WebRecon/1.0\r\n"
                "Accept: text/html,application/xhtml+xml,*/*\r\n"
                "Connection: close\r\n"
                "\r\n"
            )

            sock.sendall(request.encode())

            data = b""

            while True:
                chunk = sock.recv(4096)

                if not chunk:
                    break

                data += chunk

                if len(data) > 2_000_000:
                    break

        response = data.decode(
            "utf-8",
            errors="ignore",
        )

        header_text, separator, body = response.partition(
            "\r\n\r\n"
        )

        status_line = (
            header_text.splitlines()[0]
            if header_text
            else ""
        )

        return {
            "status_line": status_line,
            "headers_raw": header_text,
            "body": body if separator else "",
            "error": "",
        }

    except Exception as exc:
        return {
            "status_line": "",
            "headers_raw": "",
            "body": "",
            "error": str(exc),
        }


def _status_code(status_line):
    try:
        return int(status_line.split()[1])
    except Exception:
        return 0


def _extract_headers(header_text):
    headers = {}

    for line in header_text.splitlines()[1:]:
        if ":" not in line:
            continue

        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip()

        if key.lower() == "set-cookie":
            headers.setdefault("Set-Cookie", [])
            headers["Set-Cookie"].append(value)
        else:
            headers[key] = value

    return headers


def _normalize_path(base_path, link, target):
    if not link:
        return None

    link = link.strip()

    if (
        link.startswith("#")
        or link.startswith("mailto:")
        or link.startswith("javascript:")
        or link.startswith("tel:")
    ):
        return None

    base_url = f"http://{target}{base_path}"
    absolute = urljoin(base_url, link)
    parsed = urlparse(absolute)

    if parsed.hostname not in (target, None):
        return None

    path = parsed.path or "/"

    if parsed.query:
        path = f"{path}?{parsed.query}"

    return path


def _interesting_link(path):
    lower = path.lower()

    return any(
        keyword in lower
        for keyword in INTERESTING_KEYWORDS
    )


def _classify_resource(path):
    lower = path.lower()

    if "admin" in lower or "manage" in lower:
        return "Management"

    if "login" in lower or "signin" in lower:
        return "Authentication"

    if "upload" in lower:
        return "File Upload"

    if "search" in lower:
        return "Search"

    if "backup" in lower or lower.endswith(
        (".zip", ".tar", ".gz", ".bak")
    ):
        return "Backup"

    if "config" in lower:
        return "Configuration"

    if "dashboard" in lower:
        return "Dashboard"

    return "Interesting Resource"


def _format_inputs(inputs):
    formatted = []

    for item in inputs:
        name = item.get("name", "")
        field_type = item.get("type", "")
        tag = item.get("tag", "")

        if not name and not field_type:
            continue

        formatted.append(
            (
                f"{tag} | "
                f"name={name or 'N/A'} | "
                f"type={field_type or 'N/A'}"
            )
        )

    return formatted


def _analyze_page(target, port, path):
    response = _http_request(
        target,
        port,
        path,
    )

    status_code = _status_code(
        response["status_line"]
    )

    headers = _extract_headers(
        response["headers_raw"]
    )

    parser = WebReconParser()

    content_type = str(
        headers.get("Content-Type", "")
    ).lower()

    if (
        response["body"]
        and (
            "html" in content_type
            or "<html" in response["body"].lower()
            or "<form" in response["body"].lower()
        )
    ):
        try:
            parser.feed(response["body"])
        except Exception:
            pass

    normalized_links = []

    for link in parser.links:
        normalized = _normalize_path(
            path,
            link,
            target,
        )

        if normalized:
            normalized_links.append(normalized)

    cookies = headers.get("Set-Cookie", [])

    if not isinstance(cookies, list):
        cookies = [cookies]

    return {
        "path": path,
        "status_code": status_code,
        "status_line": response["status_line"],
        "title": parser.title or "Unknown",
        "server": headers.get("Server", "Unknown"),
        "powered_by": headers.get(
            "X-Powered-By",
            "Unknown",
        ),
        "content_type": headers.get(
            "Content-Type",
            "Unknown",
        ),
        "cookies": cookies,
        "forms": parser.forms,
        "inputs": _format_inputs(parser.inputs),
        "comments": parser.comments[:20],
        "links": list(
            dict.fromkeys(normalized_links)
        ),
        "error": response["error"],
        "body_preview": response["body"][:500],
    }


def _crawl_site(target, port):
    pages = {}
    queue = ["/"]
    visited = set()

    while queue and len(visited) < MAX_CRAWL_PAGES:
        path = queue.pop(0)

        if path in visited:
            continue

        visited.add(path)

        page = _analyze_page(
            target,
            port,
            path,
        )

        pages[path] = page

        if page["status_code"] != 200:
            continue

        for link in page["links"]:
            if link not in visited and link not in queue:
                queue.append(link)

    return pages


def _check_common_resources(target, port):
    resources = []

    for path in COMMON_RESOURCES:
        response = _http_request(
            target,
            port,
            path,
        )

        status_code = _status_code(
            response["status_line"]
        )

        if status_code in (200, 301, 302, 401, 403):
            resources.append(
                {
                    "path": path,
                    "status_code": status_code,
                    "classification": _classify_resource(
                        path
                    ),
                    "preview": response["body"][:500],
                }
            )

    return resources


def _deduplicate_resources(resources):
    unique = {}

    for item in resources:
        path = item.get("path", "")

        if not path:
            continue

        if path not in unique:
            unique[path] = item
            continue

        existing_status = unique[path].get(
            "status_code",
            0,
        )

        new_status = item.get(
            "status_code",
            0,
        )

        if not existing_status and new_status:
            unique[path] = item

    return list(unique.values())

def _classify_forms(forms, inputs):
    classifications = []

    for form in forms:
        page = form.get("page", "/")

        page_inputs = [
            item.get("field", "").lower()
            for item in inputs
            if item.get("page", "/") == page
        ]

        combined = " ".join(page_inputs)

        form_type = "General Form"

        if (
            "type=password" in combined
            or (
                "name=username" in combined
                and "name=password" in combined
            )
        ):
            form_type = "Authentication Form"

        elif "name=search" in combined:
            form_type = "Search Form"

        elif "type=file" in combined:
            form_type = "File Upload Form"

        classifications.append(
            {
                "page": page,
                "type": form_type,
                "method": form.get(
                    "method",
                    "GET",
                ),
                "action": form.get(
                    "action",
                    "",
                ),
            }
        )

    return classifications

def _merge_web_results(target, port, pages, resources):
    titles = []
    forms = []
    inputs = []
    comments = []
    cookies = []
    interesting_links = []

    server = "Unknown"
    powered_by = "Unknown"

    for path, page in pages.items():
        title = page.get("title", "Unknown")

        if title != "Unknown":
            titles.append(
                {
                    "path": path,
                    "title": title,
                }
            )

        if server == "Unknown":
            server = page.get(
                "server",
                "Unknown",
            )

        if powered_by == "Unknown":
            powered_by = page.get(
                "powered_by",
                "Unknown",
            )

        for form in page.get("forms", []):
            forms.append(
                {
                    "page": path,
                    "method": form.get(
                        "method",
                        "GET",
                    ),
                    "action": form.get(
                        "action",
                        "",
                    ),
                }
            )

        for field in page.get("inputs", []):
            inputs.append(
                {
                    "page": path,
                    "field": field,
                }
            )

        for comment in page.get("comments", []):
            comments.append(
                {
                    "page": path,
                    "comment": comment,
                }
            )

        for cookie in page.get("cookies", []):
            cookies.append(
                {
                    "page": path,
                    "cookie": cookie,
                }
            )

        for link in page.get("links", []):
            if _interesting_link(link):
                interesting_links.append(
                    {
                        "path": link,
                        "classification": _classify_resource(
                            link
                        ),
                    }
                )

    for resource in resources:
        interesting_links.append(
            {
                "path": resource["path"],
                "classification": resource[
                    "classification"
                ],
                "status_code": resource[
                    "status_code"
                ],
            }
        )

    return {
        "port": port,
        "target": target,
        "server": server,
        "powered_by": powered_by,
        "pages_crawled": list(pages.keys()),
        "page_count": len(pages),
        "titles": titles,
        "forms": forms,
        "form_classifications": _classify_forms(
            forms,
            inputs,
        ),
        "inputs": inputs,
        "comments": comments[:30],
        "cookies": cookies[:30],
        "interesting_links": _deduplicate_resources(
            interesting_links
        )[:30],
        "common_resources": resources,
        "robots_found": any(
            item["path"] == "/robots.txt"
            and item["status_code"] == 200
            for item in resources
        ),
        "sitemap_found": any(
            item["path"] == "/sitemap.xml"
            and item["status_code"] == 200
            for item in resources
        ),
    }


def run_web_recon(target, ports):
    results = {}

    web_ports = []

    for port in ports:
        try:
            port_int = int(port)

            if port_int in WEB_PORTS:
                web_ports.append(port_int)

        except Exception:
            continue

    for port in sorted(set(web_ports)):
        pages = _crawl_site(
            target,
            port,
        )

        resources = _check_common_resources(
            target,
            port,
        )

        results[port] = _merge_web_results(
            target,
            port,
            pages,
            resources,
        )

    return results
