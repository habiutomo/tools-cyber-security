"""
Technology Detection Module
Detects technologies, frameworks, and CMS used on a website.
"""

import argparse
import re
import sys
import requests
from urllib3.exceptions import InsecureRequestWarning
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table

console = Console()
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

TECH_SIGNATURES = {
    "CMS": {
        "WordPress": {"headers": ["x-powered-by: wordpress"], "body": ["wp-content", "wp-includes", "wordpress"],
                      "cookies": ["wordpress_", "wp-settings-"]},
        "Drupal": {"headers": ["x-generator: drupal", "x-drupal-cache"], "body": ["drupal.js", "sites/default/files", "drupal"],
                   "cookies": ["SESS", "SSESS"]},
        "Joomla": {"headers": [], "body": ["/media/jui/", "joomla", "Joomla!"],
                   "cookies": ["joomla_"]},
        "Ghost": {"headers": ["x-ghost-"], "body": ["ghost-", "content/themes/"],
                  "cookies": ["ghost-"]},
    },
    "Framework": {
        "Laravel": {"headers": ["x-powered-by: laravel"], "body": ["laravel"],
                    "cookies": ["laravel_session"]},
        "Django": {"headers": ["x-frame-options: deny"], "body": ["csrfmiddlewaretoken", "django"],
                   "cookies": ["csrftoken", "sessionid"]},
        "Flask": {"headers": [], "body": [],
                  "cookies": ["session=ey"]},
        "Express.js": {"headers": ["x-powered-by: express"], "body": [],
                       "cookies": ["connect.sid"]},
        "Spring": {"headers": [], "body": ["spring", "Whitelabel Error Page"],
                   "cookies": ["JSESSIONID"]},
        "Ruby on Rails": {"headers": ["x-powered-by: passenger"], "body": ["csrf-token", "authenticity_token"],
                          "cookies": ["_session_id"]},
        "ASP.NET": {"headers": ["x-powered-by: asp.net", "x-aspnet-version"], "body": ["__VIEWSTATE", "__EVENTVALIDATION"],
                    "cookies": [".aspxauth", "ASP.NET_SessionId"]},
        "Next.js": {"headers": ["x-powered-by: next.js"], "body": ["__next", "_next/static"],
                    "cookies": []},
        "Nuxt.js": {"headers": [], "body": ["__nuxt", "_nuxt/"],
                    "cookies": ["_nuxt"]},
    },
    "Web Server": {
        "Apache": {"headers": ["server: apache"], "body": [], "cookies": []},
        "Nginx": {"headers": ["server: nginx"], "body": [], "cookies": []},
        "IIS": {"headers": ["server: microsoft-iis"], "body": [], "cookies": []},
        "LiteSpeed": {"headers": ["server: litespeed"], "body": [], "cookies": []},
        "Caddy": {"headers": ["server: caddy"], "body": [], "cookies": []},
    },
    "Analytics": {
        "Google Analytics": {"headers": [], "body": ["google-analytics.com", "googletagmanager.com", "gtag("],
                            "cookies": ["_ga", "_gid"]},
        "Google Tag Manager": {"headers": [], "body": ["googletagmanager.com/gtm.js"],
                               "cookies": []},
        "Facebook Pixel": {"headers": [], "body": ["connect.facebook.net", "fbq("],
                           "cookies": ["_fbp"]},
        "Hotjar": {"headers": [], "body": ["hotjar.com", "hotjar.js"],
                   "cookies": ["_hj"]},
        "Matomo": {"headers": [], "body": ["matomo", "piwik"],
                   "cookies": ["_pk_"]},
    },
    "JavaScript Libraries": {
        "jQuery": {"headers": [], "body": ["jquery", "jquery.min.js"], "cookies": []},
        "React": {"headers": [], "body": ["react", "reactdom", "_reactroot"],
                  "cookies": []},
        "Vue.js": {"headers": [], "body": ["vue", "vue.min.js", "__vue__"],
                   "cookies": []},
        "Angular": {"headers": [], "body": ["ng-version", "angular", "ng-app"],
                    "cookies": []},
        "Bootstrap": {"headers": [], "body": ["bootstrap.min.css", "bootstrap.min.js"],
                      "cookies": []},
        "Tailwind CSS": {"headers": [], "body": ["tailwindcss", "tailwind"],
                         "cookies": []},
    },
    "Security": {
        "Cloudflare": {"headers": ["cf-ray", "cf-cache-status"], "body": [],
                       "cookies": ["__cfduid"]},
        "reCAPTCHA": {"headers": [], "body": ["google.com/recaptcha", "recaptcha"],
                      "cookies": []},
        "hCaptcha": {"headers": [], "body": ["hcaptcha.com"],
                     "cookies": []},
    },
    "E-Commerce": {
        "Shopify": {"headers": ["x-shopify-stage"], "body": ["shopify", "cdn.shopify.com"],
                    "cookies": ["_shopify_"]},
        "WooCommerce": {"headers": [], "body": ["woocommerce", "wc-"],
                        "cookies": ["woocommerce_"]},
        "Magento": {"headers": [], "body": ["magento", "Mage.Cookies"],
                    "cookies": ["frontend", "PHPSESSID"]},
        "PrestaShop": {"headers": [], "body": ["prestashop"],
                       "cookies": ["PrestaShop"]},
    },
}

def detect_tech(url):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        resp = requests.get(url, timeout=10, verify=False, allow_redirects=True,
                           headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"})
    except requests.exceptions.RequestException as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        sys.exit(1)

    headers = {k.lower(): v for k, v in resp.headers.items()}
    cookies_str = str(resp.cookies)
    body = resp.text[:100000]

    soup = BeautifulSoup(body, "html.parser")
    page_text = soup.get_text().lower()
    body_lower = body.lower()

    detected = {}

    for category, techs in TECH_SIGNATURES.items():
        detected[category] = []
        for tech_name, sigs in techs.items():
            score = 0
            matched = []

            # Check headers
            for h in sigs["headers"]:
                h_lower = h.lower()
                for k, v in headers.items():
                    if h_lower in f"{k}: {v}".lower():
                        score += 3
                        matched.append("Header")

            # Check body
            for b in sigs["body"]:
                if b.lower() in body_lower:
                    score += 2
                    matched.append("Body")

            # Check cookies
            for c in sigs["cookies"]:
                if c.lower() in cookies_str.lower():
                    score += 2
                    matched.append("Cookie")

            if score > 0:
                detected[category].append({"name": tech_name, "score": score, "evidence": matched})

        detected[category].sort(key=lambda x: x["score"], reverse=True)

    # Meta generator
    gen = soup.find("meta", attrs={"name": "generator"})
    if gen and gen.get("content"):
        detected.setdefault("Generator", []).append({
            "name": gen["content"], "score": 10, "evidence": ["Meta tag"]
        })

    return {
        "url": resp.url,
        "status": resp.status_code,
        "server": headers.get("server", "Unknown"),
        "detected": detected
    }

def run(raw_args=None):
    parser = argparse.ArgumentParser(description="Technology Detection")
    parser.add_argument("-u", "--url", required=True, help="Target URL")

    args = parser.parse_args(raw_args)

    result = detect_tech(args.url)

    console.print(f"[bold cyan]URL:[/bold cyan] {result['url']}")
    console.print(f"[bold cyan]Status:[/bold cyan] {result['status']}")
    console.print(f"[bold cyan]Server:[/bold cyan] {result['server']}\n")

    total = 0
    for category, techs in result["detected"].items():
        if techs:
            table = Table(title=category, border_style="cyan", show_lines=True)
            table.add_column("Technology", style="bold green")
            table.add_column("Confidence", style="yellow")
            table.add_column("Evidence", style="dim")

            for t in techs:
                conf = "HIGH" if t["score"] >= 4 else "MEDIUM" if t["score"] >= 2 else "LOW"
                color = "green" if conf == "HIGH" else "yellow" if conf == "MEDIUM" else "dim"
                table.add_row(t["name"], f"[{color}]{conf}[/{color}]", ", ".join(t["evidence"]))
                total += 1

            console.print(table)
            console.print()

    console.print(f"[bold]{total}[/bold] technology(ies) detected")
