# engine/crawler.py

"""
Website Path Crawler.

This module provides functionality to crawl a target website and discover internal
links. This is used in the HTTP/S flood attack to distribute requests across
various pages, making the attack pattern less uniform and potentially more
stressful for the target server (e.g., by hitting database-intensive pages).

Usage:
    import asyncio
    from engine.crawler import crawl_target_paths

    async def main():
        base_url = "http://example.com"
        paths = await crawl_target_paths(base_url)
        print(f"Found paths: {paths}")

    if __name__ == "__main__":
        asyncio.run(main())

Dependencies:
    - asyncio, urllib.parse (standard libraries)
    - httpx (for making HTTP requests)
    - beautifulsoup4 (for parsing HTML)
    - termcolor (for colored console output)

Testing:
    This module can be tested by running it against a known website and verifying
    that it returns a list of expected internal paths. Edge cases to test include:
    - A website that is down or returns an error status code.
    - A website with no internal links.
    - Handling of relative vs. absolute URLs.
"""

import asyncio
from urllib.parse import urlparse, urljoin
from typing import List, Set

import httpx
from bs4 import BeautifulSoup
from termcolor import colored

async def crawl_target_paths(base_url: str) -> List[str]:
    """
    Crawls a given base URL to find all unique internal URL paths.

    It sends a GET request to the base URL, parses the HTML response, and
    extracts all `<a>` hrefs that point to the same domain.

    Args:
        base_url (str): The base URL of the target to crawl (e.g., "http://example.com").

    Returns:
        List[str]: A list of unique internal paths found on the site, including '/'.
                   Returns just ['/'] if crawling fails or no paths are found.
    """
    print(colored(f"\n[+] Starting crawl on {base_url} to find attack paths...", "cyan"))
    # The root path is always a valid target.
    paths: Set[str] = {'/'}
    try:
        # Use an async client with SSL verification disabled and a reasonable timeout.
        async with httpx.AsyncClient(verify=False, timeout=15.0, follow_redirects=True) as client:
            response = await client.get(base_url)

            # Only proceed if the initial request was successful.
            if response.status_code != 200:
                print(colored(f"[!] Crawl failed, target returned status code: {response.status_code}", "yellow"))
                return list(paths)
            
            # Parse the HTML content of the page.
            soup = BeautifulSoup(response.text, 'html.parser')
            base_netloc = urlparse(base_url).netloc

            # Find all anchor tags with an 'href' attribute.
            for link in soup.find_all('a', href=True):
                href = link['href']
                # Resolve the relative URL to an absolute one.
                full_url = urljoin(base_url, href)
                parsed_url = urlparse(full_url)

                # Ensure the link belongs to the same domain and uses a web protocol.
                if parsed_url.netloc == base_netloc and parsed_url.scheme in ['http', 'https']:
                    path = parsed_url.path
                    if parsed_url.query:
                        path += "?" + parsed_url.query
                    if path:
                        paths.add(path)                           

    except httpx.RequestError as e:
        print(colored(f"[!] Error during crawling request: {e}", "red"))
    except Exception as e:
        print(colored(f"[!] An unexpected error occurred while parsing HTML: {e}", "red"))

    crawled_paths = sorted(list(paths))
    print(colored(f"[+] Crawl complete. Found {len(crawled_paths)} unique paths.", "green"))

    # Print a sample of the found paths for user feedback.
    if crawled_paths:
        display_limit = 10
        paths_to_display = crawled_paths[:display_limit]
        ellipsis = '...' if len(crawled_paths) > display_limit else ''
        print(colored("    -> " + "\n    -> ".join(paths_to_display) + ellipsis, "white"))

    return crawled_paths
