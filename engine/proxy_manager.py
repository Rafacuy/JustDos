# engine/proxy_manager.py

"""
Adaptive Proxy Management System.

This module provides the tools to manage a list of proxies for HTTP/S flood attacks.
It includes an `AdaptiveProxyPool` that intelligently handles proxy rotation,
cooldowns, and exponential backoff for failing proxies. This resilience is vital
for maintaining attack effectiveness when target systems start blocking IP addresses.

It also includes a placeholder for a function to load and test proxies from a file.

Usage:
    # 1. Load proxies from a file
    proxies = await load_and_test_proxies(file_path="proxies.txt", test_url="https://example.com")

    # 2. Initialize the pool
    logger = setup_logging()
    proxy_pool = AdaptiveProxyPool(proxies, logger)

    # 3. In an async worker, get a proxy
    proxy = await proxy_pool.get_proxy()
    # ... use the proxy ...

    # 4. Release the proxy, reporting its success or failure
    await proxy_pool.release_proxy(proxy, status_code=200) # Success
    await proxy_pool.release_proxy(proxy, status_code=403) # Failure

Dependencies:
    - asyncio, time, collections, typing (standard libraries)
    - httpx (for testing proxies)
    - utils.logger

Testing:
    The AdaptiveProxyPool can be tested by simulating worker interactions:
    - Verify that get_proxy() waits when the pool is empty.
    - Verify that a failed proxy (e.g., released with status 429) is put on cooldown.
    - Verify that the cooldown_manager task eventually returns the proxy to the pool.
    - Check that concurrent access from multiple async tasks is handled correctly by the locks.
"""

import asyncio
import logging
import time
import httpx
from collections import defaultdict
from typing import List, Optional, Dict

from utils.logger import setup_logging

logger = setup_logging()

# --- Placeholder for Proxy Loading ---
# In the original script, this was handled by an external 'proxy_manager' module.
# We recreate its essential functionality here.

async def load_and_test_proxies(file_path: str, test_url: str, protocol_prefix: str = "http") -> List[str]:
    """
    Loads proxies from a file and performs a basic connectivity test.

    Args:
        file_path (str): The path to the text file containing proxies (one per line).
        test_url (str): The URL to test the proxies against.
        protocol_prefix (str): The protocol to use for the proxy URL (e.g., 'http', 'socks5').

    Returns:
        List[str]: A list of valid, working proxy URLs.
    """
    valid_proxies: List[str] = []
    try:
        with open(file_path, 'r') as f:
            proxies_from_file = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        logger.error(f"Proxy file not found at '{file_path}'.")
        return []

    logger.info(f"Found {len(proxies_from_file)} proxies in file. Testing connectivity...")

    async def test_proxy(proxy_address: str, client: httpx.AsyncClient):
        proxy_url = f"{protocol_prefix}://{proxy_address}"
        try:
            response = await client.get(test_url, proxies=proxy_url, timeout=10.0)
            if response.status_code < 400:
                valid_proxies.append(proxy_url)
                logger.info(f"Proxy {proxy_address} is valid.")
            else:
                 logger.warning(f"Proxy {proxy_address} failed test (Status: {response.status_code}).")
        except (httpx.ProxyError, httpx.ConnectTimeout, httpx.ReadTimeout):
            logger.warning(f"Proxy {proxy_address} failed test (Connection Error/Timeout).")
        except Exception as e:
            logger.error(f"An unexpected error occurred while testing proxy {proxy_address}: {e}")

    async with httpx.AsyncClient(verify=False) as client:
        tasks = [test_proxy(p, client) for p in proxies_from_file]
        await asyncio.gather(*tasks)

    logger.info(f"Found {len(valid_proxies)} working proxies.")
    return valid_proxies


class AdaptiveProxyPool:
    """
    Manages a pool of proxies with thread-safe (asyncio-safe) operations,
    implementing cooldowns and adaptive backoff for proxies that fail.
    """
    def __init__(self, proxies: List[str], logger: logging.Logger):
        """
        Initializes the adaptive proxy pool.

        Args:
            proxies (List[str]): A list of initial proxy URLs.
            logger (logging.Logger): A configured logger instance.
        """
        self.logger = logger
        self.lock = asyncio.Lock()
        # Condition variable to signal when a proxy becomes available.
        self.condition = asyncio.Condition(lock=self.lock)

        self.available_proxies: List[str] = list(proxies)
        self.cooldown_proxies: Dict[str, float] = {}  # {proxy: cooldown_end_time}
        self.backoff_counters: Dict[str, int] = defaultdict(int)

        # Configuration for cooldown behavior
        self.base_cooldown_duration: int = 30  # seconds
        self.backoff_factor: float = 1.5

        self.logger.info(f"AdaptiveProxyPool initialized with {len(proxies)} proxies.")

    async def get_proxy(self) -> Optional[str]:
        """
        Asynchronously gets an available proxy from the pool.

        If no proxies are available, it waits until one is released from use
        or its cooldown period ends.

        Returns:
            Optional[str]: An available proxy URL, or None if the pool is
                           permanently exhausted (should not happen in normal operation).
        """
        async with self.condition:
            # Wait until the list of available_proxies is not empty.
            # The wait_for predicate is checked whenever the condition is notified.
            await self.condition.wait_for(lambda: len(self.available_proxies) > 0)
            proxy = self.available_proxies.pop(0)
            return proxy

    async def release_proxy(self, proxy: str, status_code: Optional[int]):
        """
        Releases a proxy back to the pool after use.

        If the request failed with a critical status code (e.g., 403 Forbidden,
        429 Too Many Requests, 5xx Server Error) or a connection error (status_code=None),
        the proxy is put on a cooldown with an exponentially increasing duration.
        If the request was successful, the proxy is returned to the available pool
        and its failure counter is reset.

        Args:
            proxy (str): The proxy URL that was used.
            status_code (Optional[int]): The HTTP status code of the response.
                                         None indicates a connection-level error.
        """
        # Determine if the proxy is "bad" based on the status code.
        is_bad = status_code in [403, 429] or status_code is None or 500 <= (status_code or 0) < 600

        async with self.condition:
            if is_bad:
                self.backoff_counters[proxy] += 1
                failure_count = self.backoff_counters[proxy]
                # Calculate cooldown duration with exponential backoff.
                cooldown_time = self.base_cooldown_duration * (self.backoff_factor ** (failure_count - 1))
                cooldown_end = time.monotonic() + cooldown_time
                self.cooldown_proxies[proxy] = cooldown_end
                self.logger.warning(
                    f"Proxy {proxy} failed (Status: {status_code}). Cooldown for {cooldown_time:.1f}s (Failures: {failure_count})."
                )
            else:
                # If the proxy was successful, reset its failure counter and return it to the pool.
                if self.backoff_counters[proxy] > 0:
                    self.logger.info(f"Proxy {proxy} is healthy again (Status: {status_code}). Resetting backoff counter.")
                    self.backoff_counters[proxy] = 0
                self.available_proxies.append(proxy)

            # Notify any waiting workers that the state of the pool has changed.
            self.condition.notify_all()

    async def cooldown_manager(self, stop_event: asyncio.Event):
        """
        A background task that periodically checks for proxies whose cooldown
        period has expired and returns them to the available pool.

        This should be run as a concurrent task for the duration of the attack.

        Args:
            stop_event (asyncio.Event): An event to signal when this task should terminate.
        """
        while not stop_event.is_set():
            await asyncio.sleep(5)  # Check every 5 seconds.
            now = time.monotonic()

            async with self.condition:
                ready_from_cooldown = [
                    p for p, end_time in self.cooldown_proxies.items() if now >= end_time
                ]

                if ready_from_cooldown:
                    for p in ready_from_cooldown:
                        del self.cooldown_proxies[p]
                        self.available_proxies.append(p)
                        self.logger.info(f"Proxy {p} cooldown finished. Returning to active pool.")
                    # Signal that new proxies are available for any waiting workers.
                    self.condition.notify_all()
