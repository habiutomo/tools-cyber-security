"""
OSINT Username Lookup Module
Searches for a username across multiple platforms.
"""

import argparse
import sys
import requests
from rich.console import Console
from rich.table import Table

console = Console()

PLATFORMS = {
    "GitHub": {"url": "https://github.com/{}", "status": 200, "err_msg": "404"},
    "GitLab": {"url": "https://gitlab.com/{}", "status": 200, "err_msg": "404"},
    "Twitter/X": {"url": "https://x.com/{}", "status": 200, "err_msg": "This account doesn"},
    "Instagram": {"url": "https://www.instagram.com/{}/", "status": 200, "err_msg": "Sorry, this page isn't available"},
    "Reddit": {"url": "https://www.reddit.com/user/{}/", "status": 200, "err_msg": "Sorry, nobody on Reddit goes by that name"},
    "LinkedIn": {"url": "https://www.linkedin.com/in/{}/", "status": 200, "err_msg": "This page doesn't exist"},
    "YouTube": {"url": "https://www.youtube.com/@{}", "status": 200, "err_msg": "404"},
    "TikTok": {"url": "https://www.tiktok.com/@{}", "status": 200, "err_msg": "Couldn't find this account"},
    "Pinterest": {"url": "https://www.pinterest.com/{}/", "status": 200, "err_msg": "Not Found"},
    "Medium": {"url": "https://medium.com/@{}", "status": 200, "err_msg": "PAGE NOT FOUND"},
    "DeviantArt": {"url": "https://www.deviantart.com/{}", "status": 200, "err_msg": "404"},
    "Twitch": {"url": "https://www.twitch.tv/{}", "status": 200, "err_msg": "page not found"},
    "Steam": {"url": "https://steamcommunity.com/id/{}", "status": 200, "err_msg": "The specified profile could not be found"},
    "Keybase": {"url": "https://keybase.io/{}", "status": 200, "err_msg": "404"},
    "HackerRank": {"url": "https://www.hackerrank.com/{}", "status": 200, "err_msg": "Profile Not Found"},
    "LeetCode": {"url": "https://leetcode.com/{}", "status": 200, "err_msg": "404"},
    "StackOverflow": {"url": "https://stackoverflow.com/users/?Tab=Accounts&Filter=NOPE&search={}", "status": 200, "err_msg": ""},
    "npm": {"url": "https://www.npmjs.com/~{}", "status": 200, "err_msg": "404"},
    "PyPI": {"url": "https://pypi.org/user/{}/", "status": 200, "err_msg": "404 Not Found"},
    "DockerHub": {"url": "https://hub.docker.com/u/{}", "status": 200, "err_msg": "User not found"},
    "Gravatar": {"url": "https://en.gravatar.com/{}", "status": 200, "err_msg": "Profile not found"},
    "About.me": {"url": "https://about.me/{}", "status": 200, "err_msg": ""},
    "Patreon": {"url": "https://www.patreon.com/{}", "status": 200, "err_msg": "404"},
    "Flickr": {"url": "https://www.flickr.com/people/{}", "status": 200, "err_msg": "Member not found"},
    "Spotify": {"url": "https://open.spotify.com/user/{}", "status": 200, "err_msg": "Page not found"},
    "SoundCloud": {"url": "https://soundcloud.com/{}", "status": 200, "err_msg": "404: Not Found"},
    "Dev.to": {"url": "https://dev.to/{}", "status": 200, "err_msg": "404"},
    "Replit": {"url": "https://replit.com/@{}", "status": 200, "err_msg": ""},
    "CodePen": {"url": "https://codepen.io/{}", "status": 200, "err_msg": "404"},
    "Behance": {"url": "https://www.behance.net/{}", "status": 200, "err_msg": "404"},
    "Dribbble": {"url": "https://dribbble.com/{}", "status": 200, "err_msg": "not found"},
}

def check_username(platform, info, username, timeout=5):
    url = info["url"].format(username)
    try:
        r = requests.get(url, timeout=timeout, verify=False,
                        allow_redirects=True,
                        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"})

        exists = r.status_code == info["status"]
        if exists and info["err_msg"] and info["err_msg"].lower() in r.text.lower():
            exists = False

        return {
            "platform": platform,
            "url": url,
            "status": r.status_code,
            "exists": exists
        }
    except requests.exceptions.RequestException:
        return {"platform": platform, "url": url, "status": "ERR", "exists": False}

def run(raw_args=None):
    parser = argparse.ArgumentParser(description="OSINT Username Lookup")
    parser.add_argument("-u", "--username", required=True, help="Username to search")
    parser.add_argument("-p", "--platforms", nargs="+", help="Specific platforms to check")
    parser.add_argument("--timeout", type=float, default=5, help="Request timeout per platform")

    args = parser.parse_args(raw_args)

    username = args.username
    platforms = args.platforms if args.platforms else list(PLATFORMS.keys())

    console.print(f"[bold cyan]Searching username:[/bold cyan] {username}")
    console.print(f"[bold cyan]Platforms:[/bold cyan] {len(platforms)}\n")

    found = []
    not_found = []
    errors = []

    for platform in platforms:
        if platform not in PLATFORMS:
            console.print(f"  [yellow]Unknown platform: {platform}[/yellow]")
            continue

        info = PLATFORMS[platform]
        result = check_username(platform, info, username, args.timeout)

        if result["exists"]:
            found.append(result)
            console.print(f"  [green]FOUND[/green] {platform}: {result['url']}")
        elif result["status"] == "ERR":
            errors.append(result)
            console.print(f"  [dim]ERROR[/dim] {platform}")
        else:
            not_found.append(result)

    # Summary table
    if found:
        table = Table(title=f"Username '{username}' Found On", border_style="green", show_lines=True)
        table.add_column("Platform", style="bold cyan")
        table.add_column("URL", style="green")
        table.add_column("Status")

        for r in found:
            table.add_row(r["platform"], r["url"], str(r["status"]))

        console.print(table)

    console.print(f"\n[bold green]Found:[/bold green] {len(found)}")
    console.print(f"[bold red]Not found:[/bold red] {len(not_found)}")
    if errors:
        console.print(f"[bold yellow]Errors:[/bold yellow] {len(errors)}")
