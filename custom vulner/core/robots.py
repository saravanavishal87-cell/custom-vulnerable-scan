import urllib.parse
import requests

class RobotsAuditor:
    """
    Downloads and audits the robots.txt file to identify potentially sensitive
    endpoints or folders exposed to web search crawlers.
    """

    # Keywords that suggest sensitive/private resources
    SENSITIVE_KEYWORDS = [
        "admin", "administrator", "login", "auth", "signin",
        "api", "v1", "v2", "graphql", "rest",
        "config", "settings", "backup", "db", "database", "sql", "dump",
        "private", "secret", "hidden", "internal", "draft",
        "temp", "tmp", "cache", "log", "logs",
        "src", "source", "git", "svn", "env", "credentials"
    ]

    def __init__(self, target_url: str):
        self.target_url = target_url
        # Build standard URL to /robots.txt
        parsed = urllib.parse.urlparse(target_url)
        self.robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"

    def audit(self) -> dict:
        """
        Attempts to fetch robots.txt and parse its rules.
        """
        result = {
            "exists": False,
            "status_code": 0,
            "disallowed_paths": [],
            "sensitive_paths": [],
            "sitemaps": []
        }

        try:
            # Safe HTTP request with short timeout
            response = requests.get(self.robots_url, timeout=5, headers={
                "User-Agent": "VulcanPassiveAuditor/1.0"
            })
            result["status_code"] = response.status_code

            if response.status_code == 200:
                result["exists"] = True
                self._parse(response.text, result)
        except Exception:
            # Fail silently or log error programmatically
            pass

        return result

    def _parse(self, content: str, result: dict):
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Check for Disallow rules
            if line.lower().startswith("disallow:"):
                parts = line.split(":", 1)
                if len(parts) == 2:
                    path = parts[1].strip()
                    if path:
                        result["disallowed_paths"].append(path)
                        # Check for sensitive patterns
                        matched_keys = [key for key in self.SENSITIVE_KEYWORDS if key in path.lower()]
                        if matched_keys:
                            result["sensitive_paths"].append({
                                "path": path,
                                "matched_keywords": matched_keys,
                                "description": f"Exposes route pattern containing administrative/sensitive keywords ('{', '.join(matched_keys)}').",
                                "recommendation": "Avoid exposing internal, sensitive, or developmental URLs in robots.txt. Use proper authorization mechanisms to secure endpoints instead of relying on crawler exclusions (security through obscurity)."
                            })

            # Check for Sitemap declarations
            elif line.lower().startswith("sitemap:"):
                parts = line.split(":", 1)
                if len(parts) == 2:
                    sitemap_url = parts[1].strip()
                    if sitemap_url:
                        result["sitemaps"].append(sitemap_url)
