import json
import os
import datetime

class ReportGenerator:
    """
    Generates JSON and premium HTML reports summarizing the security configuration posture.
    """

    def __init__(self, target: str, results: dict):
        self.target = target
        self.results = results
        self.timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def to_json(self, output_path: str):
        data = {
            "target": self.target,
            "timestamp": self.timestamp,
            "results": self.results
        }
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4)

    def to_html(self, output_path: str):
        # Count total issues and split by severity
        high_count = 0
        med_count = 0
        low_count = 0
        info_count = 0

        # Calculate severity stats from headers
        missing_count = len(self.results.get("headers", {}).get("missing_headers", []))
        # Missing critical security headers are marked as Low/Medium
        med_count += sum(1 for h in self.results.get("headers", {}).get("missing_headers", []) if h["header"] in ["Content-Security-Policy", "Strict-Transport-Security"])
        low_count += sum(1 for h in self.results.get("headers", {}).get("missing_headers", []) if h["header"] not in ["Content-Security-Policy", "Strict-Transport-Security"])
        
        for v in self.results.get("headers", {}).get("verbose_headers", []):
            sev = v.get("severity", "Low")
            if sev == "High": high_count += 1
            elif sev == "Medium": med_count += 1
            else: low_count += 1

        # Calculate from cookies
        for cookie_finding in self.results.get("cookies", []):
            for issue in cookie_finding.get("issues", []):
                sev = issue.get("severity", "Medium")
                if sev == "High": high_count += 1
                elif sev == "Medium": med_count += 1
                else: low_count += 1

        # Calculate from robots.txt
        sensitive_robots_count = len(self.results.get("robots", {}).get("sensitive_paths", []))
        low_count += sensitive_robots_count

        total_findings = high_count + med_count + low_count + info_count

        # HTML Premium Template with HSL tailored dark-mode colors, glassmorphism, responsive grid, and cards.
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulcan Security Configuration Audit Report</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&family=Plus+Jakarta+Sans:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg-color: #0b0f19;
            --surface-color: rgba(20, 27, 45, 0.7);
            --border-color: rgba(255, 255, 255, 0.08);
            --primary: #6366f1;
            --primary-hover: #4f46e5;
            --text-main: #f3f4f6;
            --text-muted: #9ca3af;
            
            --severity-high: #ef4444;
            --severity-medium: #f59e0b;
            --severity-low: #3b82f6;
            --severity-info: #10b981;
        }}

        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Plus Jakarta Sans', sans-serif;
        }}

        body {{
            background-color: var(--bg-color);
            color: var(--text-main);
            padding: 2rem 1rem;
            line-height: 1.6;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}

        /* Header Card */
        .header-card {{
            background: linear-gradient(135deg, rgba(99, 102, 241, 0.15) 0%, rgba(20, 27, 45, 0.7) 100%);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 2.5rem;
            margin-bottom: 2rem;
            backdrop-filter: blur(12px);
            box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
        }}

        h1 {{
            font-family: 'Outfit', sans-serif;
            font-size: 2.5rem;
            font-weight: 700;
            background: linear-gradient(to right, #6366f1, #a855f7, #ec4899);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 0.5rem;
        }}

        .meta-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 1.5rem;
            margin-top: 1.5rem;
            border-top: 1px solid var(--border-color);
            padding-top: 1.5rem;
        }}

        .meta-item {{
            display: flex;
            flex-direction: column;
        }}

        .meta-label {{
            font-size: 0.85rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}

        .meta-val {{
            font-size: 1.1rem;
            font-weight: 500;
            word-break: break-all;
        }}

        /* Dashboard Overview */
        .dash-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}

        .stat-card {{
            background: var(--surface-color);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 1.5rem;
            text-align: center;
            backdrop-filter: blur(8px);
        }}

        .stat-num {{
            font-family: 'Outfit', sans-serif;
            font-size: 2.2rem;
            font-weight: 700;
            margin-bottom: 0.2rem;
        }}

        .stat-name {{
            font-size: 0.9rem;
            color: var(--text-muted);
        }}

        /* Vulnerability Badges */
        .badge {{
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}

        .badge-high {{ background-color: rgba(239, 68, 68, 0.15); color: var(--severity-high); border: 1px solid rgba(239, 68, 68, 0.3); }}
        .badge-medium {{ background-color: rgba(245, 158, 11, 0.15); color: var(--severity-medium); border: 1px solid rgba(245, 158, 11, 0.3); }}
        .badge-low {{ background-color: rgba(59, 130, 246, 0.15); color: var(--severity-low); border: 1px solid rgba(59, 130, 246, 0.3); }}
        .badge-info {{ background-color: rgba(16, 185, 129, 0.15); color: var(--severity-info); border: 1px solid rgba(16, 185, 129, 0.3); }}

        /* Main Sections */
        .section-title {{
            font-family: 'Outfit', sans-serif;
            font-size: 1.6rem;
            font-weight: 600;
            margin: 2.5rem 0 1.2rem 0;
            display: flex;
            align-items: center;
            gap: 0.75rem;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 0.5rem;
        }}

        .vuln-card {{
            background: var(--surface-color);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 1.5rem;
            margin-bottom: 1rem;
            transition: transform 0.2s, border-color 0.2s;
        }}

        .vuln-card:hover {{
            transform: translateY(-2px);
            border-color: rgba(99, 102, 241, 0.3);
        }}

        .vuln-header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            flex-wrap: wrap;
            gap: 1rem;
            margin-bottom: 1rem;
        }}

        .vuln-title {{
            font-size: 1.2rem;
            font-weight: 600;
            color: var(--text-main);
        }}

        .vuln-desc {{
            color: var(--text-muted);
            margin-bottom: 1rem;
            font-size: 0.95rem;
        }}

        .vuln-remediation {{
            background: rgba(99, 102, 241, 0.05);
            border-left: 3px solid var(--primary);
            padding: 1rem;
            border-radius: 0 8px 8px 0;
            font-size: 0.9rem;
        }}

        .remediation-title {{
            font-weight: 600;
            color: var(--text-main);
            margin-bottom: 0.25rem;
        }}

        /* Tables */
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 1.5rem;
            background: var(--surface-color);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            overflow: hidden;
        }}

        th, td {{
            padding: 1rem;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }}

        th {{
            background: rgba(255, 255, 255, 0.02);
            font-weight: 600;
            color: var(--text-muted);
            font-size: 0.85rem;
            text-transform: uppercase;
        }}

        tr:last-child td {{
            border-bottom: none;
        }}

        .text-green {{ color: var(--severity-info); font-weight: 500; }}
        .text-red {{ color: var(--severity-high); font-weight: 500; }}
    </style>
</head>
<body>
    <div class="container">
        
        <!-- Header Card -->
        <div class="header-card">
            <h1>Vulcan Configuration Auditor</h1>
            <p style="color: var(--text-muted);">Passive web application security and header compliance verification.</p>
            
            <div class="meta-grid">
                <div class="meta-item">
                    <span class="meta-label">Target URL</span>
                    <span class="meta-val">{self.target}</span>
                </div>
                <div class="meta-item">
                    <span class="meta-label">Audit Time</span>
                    <span class="meta-val">{self.timestamp}</span>
                </div>
                <div class="meta-item">
                    <span class="meta-label">Status</span>
                    <span class="meta-val" style="color: var(--severity-info);">Audit Completed</span>
                </div>
            </div>
        </div>

        <!-- Dashboard Stat Grid -->
        <div class="dash-grid">
            <div class="stat-card">
                <div class="stat-num" style="color: var(--primary);">{total_findings}</div>
                <div class="stat-name">Total Observations</div>
            </div>
            <div class="stat-card">
                <div class="stat-num" style="color: var(--severity-high);">{high_count}</div>
                <div class="stat-name">High Risk</div>
            </div>
            <div class="stat-card">
                <div class="stat-num" style="color: var(--severity-medium);">{med_count}</div>
                <div class="stat-name">Medium Risk</div>
            </div>
            <div class="stat-card">
                <div class="stat-num" style="color: var(--severity-low);">{low_count}</div>
                <div class="stat-name">Low Risk</div>
            </div>
        </div>

        <!-- Section 1: Security Headers -->
        <div class="section-title">🛡️ Security Response Headers</div>
        
        <h3 style="margin-bottom: 0.8rem; font-weight: 500;">Missing Security Protections</h3>
        """

        if missing_count == 0:
            html_content += """
            <div class="vuln-card" style="border-color: rgba(16, 185, 129, 0.2);">
                <div class="vuln-title text-green">✓ Excellent! No security headers are missing.</div>
            </div>
            """
        else:
            for mh in self.results.get("headers", {}).get("missing_headers", []):
                h_name = mh["header"]
                sev = "Medium" if h_name in ["Content-Security-Policy", "Strict-Transport-Security"] else "Low"
                badge_class = "badge-medium" if sev == "Medium" else "badge-low"
                html_content += f"""
                <div class="vuln-card">
                    <div class="vuln-header">
                        <span class="vuln-title">Missing "{h_name}" Header</span>
                        <span class="badge {badge_class}">{sev}</span>
                    </div>
                    <p class="vuln-desc">{mh["description"]}</p>
                    <div class="vuln-remediation">
                        <div class="remediation-title">Mitigation / Recommendation</div>
                        <p>{mh["recommendation"]}</p>
                    </div>
                </div>
                """

        # Present Headers
        html_content += """
        <h3 style="margin: 2rem 0 0.8rem 0; font-weight: 500;">Configured Security Headers</h3>
        <table>
            <thead>
                <tr>
                    <th>Header</th>
                    <th>Configured Value</th>
                </tr>
            </thead>
            <tbody>
        """
        for ph in self.results.get("headers", {}).get("present_headers", []):
            html_content += f"""
                <tr>
                    <td class="text-green" style="font-family: monospace;">{ph["header"]}</td>
                    <td style="font-family: monospace; font-size: 0.9rem; word-break: break-all;">{ph["value"]}</td>
                </tr>
            """
        if not self.results.get("headers", {}).get("present_headers", []):
            html_content += """<tr><td colspan="2" style="text-align: center; color: var(--text-muted);">No protective security headers detected.</td></tr>"""
        
        html_content += """
            </tbody>
        </table>
        """

        # Verbose Headers / Info disclosure
        html_content += """
        <h3 style="margin: 2rem 0 0.8rem 0; font-weight: 500;">Information Leakage & Server Footprints</h3>
        """
        verbose_list = self.results.get("headers", {}).get("verbose_headers", [])
        if not verbose_list:
            html_content += """
            <div class="vuln-card" style="border-color: rgba(16, 185, 129, 0.2);">
                <div class="vuln-title text-green">✓ Clean Audit! No disclosure or signature headers detected.</div>
            </div>
            """
        else:
            for vh in verbose_list:
                sev = vh.get("severity", "Low")
                badge_class = "badge-medium" if sev == "Medium" else "badge-low"
                html_content += f"""
                <div class="vuln-card">
                    <div class="vuln-header">
                        <span class="vuln-title">Server Header Leakage: "{vh["header"]}"</span>
                        <span class="badge {badge_class}">{sev}</span>
                    </div>
                    <p class="vuln-desc">The header contains values: <code style="font-family: monospace; color: var(--primary);">{vh["value"]}</code>. {vh["description"]}</p>
                    <div class="vuln-remediation">
                        <div class="remediation-title">Mitigation</div>
                        <p>{vh["recommendation"]}</p>
                    </div>
                </div>
                """

        # Section 2: Cookies
        html_content += """
        <!-- Section 2: Cookie Security flags -->
        <div class="section-title">🍪 Cookie Security Flags</div>
        """
        cookie_list = self.results.get("cookies", [])
        if not cookie_list:
            html_content += """
            <div class="vuln-card" style="border-color: rgba(16, 185, 129, 0.2);">
                <div class="vuln-title text-green">✓ All session and client cookies configured safely or no cookies set by application.</div>
            </div>
            """
        else:
            for cf in cookie_list:
                html_content += f"""
                <div style="margin-bottom: 2rem;">
                    <h4 style="margin-bottom: 0.5rem; font-family: monospace; font-size: 1.1rem; color: var(--primary);">Cookie: {cf["name"]}</h4>
                    <p style="font-size: 0.85rem; color: var(--text-muted); margin-bottom: 0.8rem;">Domain: {cf["domain"]} | Path: {cf["path"]}</p>
                """
                for issue in cf["issues"]:
                    sev = issue["severity"]
                    badge_class = "badge-high" if sev == "High" else ("badge-medium" if sev == "Medium" else "badge-low")
                    html_content += f"""
                    <div class="vuln-card" style="margin-left: 1rem; margin-bottom: 0.75rem;">
                        <div class="vuln-header">
                            <span class="vuln-title" style="font-size: 1.05rem;">Missing {issue["attribute"]} Protection Flag</span>
                            <span class="badge {badge_class}">{sev}</span>
                        </div>
                        <p class="vuln-desc" style="font-size: 0.9rem;">{issue["description"]}</p>
                        <div class="vuln-remediation" style="padding: 0.75rem; font-size: 0.85rem;">
                            <p>{issue["recommendation"]}</p>
                        </div>
                    </div>
                    """
                html_content += "</div>"

        # Section 3: robots.txt
        html_content += """
        <!-- Section 3: robots.txt -->
        <div class="section-title">🤖 robots.txt Mapping</div>
        """
        robots_res = self.results.get("robots", {})
        if not robots_res.get("exists", False):
            html_content += f"""
            <div class="vuln-card" style="border-color: rgba(59, 130, 246, 0.2);">
                <div class="vuln-title">No robots.txt detected at target root.</div>
                <p class="vuln-desc" style="margin-top: 0.5rem;">Target returned HTTP Status: {robots_res.get("status_code", 404)}. This is not a security issue, but search engine crawlers will index all routes defaultly unless meta tags are configured.</p>
            </div>
            """
        else:
            sensitive_routes = robots_res.get("sensitive_paths", [])
            html_content += f"""
            <p style="color: var(--text-muted); margin-bottom: 1rem;">Discovered {len(robots_res.get("disallowed_paths", []))} crawlers exclusion definitions.</p>
            """
            if not sensitive_routes:
                html_content += """
                <div class="vuln-card" style="border-color: rgba(16, 185, 129, 0.2);">
                    <div class="vuln-title text-green">✓ Audited robots.txt rules safely. No sensitive patterns (e.g. admin, private) were disclosed inside exclusions.</div>
                </div>
                """
            else:
                for sr in sensitive_routes:
                    html_content += f"""
                    <div class="vuln-card">
                        <div class="vuln-header">
                            <span class="vuln-title">Crawler Directive Information Disclosure: "{sr["path"]}"</span>
                            <span class="badge badge-low">Low</span>
                        </div>
                        <p class="vuln-desc">{sr["description"]}</p>
                        <div class="vuln-remediation">
                            <div class="remediation-title">Mitigation</div>
                            <p>{sr["recommendation"]}</p>
                        </div>
                    </div>
                    """

        html_content += """
    </div>
</body>
</html>
"""
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return os.path.abspath(output_path)
