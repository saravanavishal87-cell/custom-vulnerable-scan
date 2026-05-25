import requests

class HeaderAuditor:
    """
    Analyzes HTTP response headers passively to find security configuration weaknesses
    and information disclosure.
    """
    
    # Recommended security headers and their ideal/common protective configurations
    SECURITY_HEADERS = {
        "Content-Security-Policy": {
            "description": "Restricts resources (such as JavaScript, CSS, Images) that the browser is allowed to load.",
            "recommendation": "Define a strict Content Security Policy to prevent XSS and data injection attacks."
        },
        "X-Frame-Options": {
            "description": "Protects users against clickjacking attacks by controlling whether the site can be framed.",
            "recommendation": "Set to 'DENY' or 'SAMEORIGIN'."
        },
        "Strict-Transport-Security": {
            "description": "Enforces secure (HTTPS) connections to the server.",
            "recommendation": "Configure with a max-age (e.g., 'max-age=63072000; includeSubDomains; preload')."
        },
        "X-Content-Type-Options": {
            "description": "Prevents the browser from MIME-sniffing a response away from the declared content-type.",
            "recommendation": "Set to 'nosniff'."
        },
        "Referrer-Policy": {
            "description": "Controls how much referrer information the browser includes with requests.",
            "recommendation": "Set to a restrictive value such as 'strict-origin-when-cross-origin' or 'no-referrer'."
        },
        "Permissions-Policy": {
            "description": "Allows web developers to selectively enable, disable, and modify the behavior of browser features and APIs.",
            "recommendation": "Configure permissions-policy to restrict access to sensitive browser features (e.g., camera, microphone, geolocation)."
        }
    }

    # Headers often leaking framework, operating system, or server details
    VERBOSE_HEADERS = [
        "Server",
        "X-Powered-By",
        "X-AspNet-Version",
        "X-Runtime",
        "X-Version",
        "Server-Backend"
    ]

    def __init__(self, headers: dict):
        self.headers = {k.lower(): v for k, v in headers.items()}
        self.raw_headers = headers

    def audit(self) -> dict:
        """
        Runs passive checks on headers.
        Returns a dictionary with 'missing_headers', 'present_headers', and 'verbose_headers'.
        """
        missing = []
        present = []
        info_leak = []

        # 1. Audit Security Headers
        for header, info in self.SECURITY_HEADERS.items():
            h_lower = header.lower()
            if h_lower in self.headers:
                present.append({
                    "header": header,
                    "value": self.headers[h_lower],
                    "description": info["description"]
                })
            else:
                missing.append({
                    "header": header,
                    "description": info["description"],
                    "recommendation": info["recommendation"]
                })

        # 2. Audit Verbose/Information Disclosure Headers
        for h_verbose in self.VERBOSE_HEADERS:
            h_lower = h_verbose.lower()
            if h_lower in self.headers:
                val = self.headers[h_lower]
                # Filter out generic or non-disclosing values if any, but generally flag exposure
                info_leak.append({
                    "header": h_verbose,
                    "value": val,
                    "severity": "Low",
                    "description": f"Exposes server configuration details which could assist reconnaissance.",
                    "recommendation": f"Remove the '{h_verbose}' header or sanitize its value in the server configuration."
                })

        # 3. CORS Misconfiguration check
        cors_origin = self.headers.get("access-control-allow-origin")
        cors_creds = self.headers.get("access-control-allow-credentials")
        if cors_origin == "*" and cors_creds == "true":
            info_leak.append({
                "header": "Access-Control-Allow-Origin",
                "value": "* with credentials",
                "severity": "Medium",
                "description": "Overly permissive CORS policy allows any origin to read response data via credentialed requests.",
                "recommendation": "Configure specific, trusted origins instead of a wildcard when credentials are enabled."
            })

        return {
            "missing_headers": missing,
            "present_headers": present,
            "verbose_headers": info_leak
        }
