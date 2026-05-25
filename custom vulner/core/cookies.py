from http.cookiejar import Cookie
import requests

class CookieAuditor:
    """
    Passively inspects set cookies to ensure proper security flags are enabled.
    """

    def __init__(self, cookiejar):
        self.cookiejar = cookiejar

    def audit(self) -> list:
        """
        Iterates over cookies in the cookie jar and checks security attributes.
        """
        findings = []
        for cookie in self.cookiejar:
            cookie_issues = []
            
            # Check HttpOnly flag (prevents access via client-side scripts like Javascript)
            # Cookie objects have a 'has_nonstandard_attr' or direct attributes depending on parser.
            # In standard requests.cookies: cookie.has_nonstandard_attr('HttpOnly') or cookie.rest.get('HttpOnly')
            # Let's inspect the keys and check case-insensitively
            is_httponly = cookie.has_nonstandard_attr('HttpOnly') or 'httponly' in [k.lower() for k in cookie._rest.keys()]
            
            if not is_httponly:
                cookie_issues.append({
                    "attribute": "HttpOnly",
                    "severity": "Medium",
                    "description": "Cookie lacks the 'HttpOnly' flag, leaving it vulnerable to theft via Cross-Site Scripting (XSS).",
                    "recommendation": "Configure the application or server to append '; HttpOnly' to the Set-Cookie directive."
                })

            # Check Secure flag (forces transmission over secure HTTPS only)
            if not cookie.secure:
                cookie_issues.append({
                    "attribute": "Secure",
                    "severity": "Medium",
                    "description": "Cookie lacks the 'Secure' flag, allowing it to be transmitted in cleartext over unencrypted HTTP.",
                    "recommendation": "Configure the application or server to append '; Secure' to the Set-Cookie directive."
                })

            # Check SameSite attribute (mitigates CSRF)
            samesite_val = None
            for key, val in cookie._rest.items():
                if key.lower() == 'samesite':
                    samesite_val = val
                    break
            
            if not samesite_val:
                cookie_issues.append({
                    "attribute": "SameSite",
                    "severity": "Low",
                    "description": "Cookie does not explicitly define a 'SameSite' attribute, relying on default browser behavior.",
                    "recommendation": "Set the 'SameSite' attribute to 'Lax' or 'Strict' to prevent Cross-Site Request Forgery (CSRF)."
                })
            elif samesite_val.lower() == 'none' and not cookie.secure:
                cookie_issues.append({
                    "attribute": "SameSite",
                    "severity": "High",
                    "description": "SameSite is set to 'None' but the cookie is not 'Secure'. Modern browsers will reject this cookie.",
                    "recommendation": "Always pair 'SameSite=None' with the 'Secure' flag."
                })

            if cookie_issues:
                findings.append({
                    "name": cookie.name,
                    "domain": cookie.domain,
                    "path": cookie.path,
                    "issues": cookie_issues
                })

        return findings
