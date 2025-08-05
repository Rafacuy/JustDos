# engine/benchmark.py

"""
Attack Performance and Benchmark Manager.

This module provides a class, `BenchmarkManager`, for tracking and reporting
real-time statistics during a Layer 7 (HTTP/S) flood attack. It is designed
to be thread-safe (using asyncio.Lock) for use in concurrent environments.

The manager collects data on:
- Total requests sent.
- Counts of each HTTP status code received.
- Request latencies (time taken for a request to complete).
- Overall requests per second (RPS).

Usage:
    import asyncio

    benchmark = BenchmarkManager()

    async def make_request():
        # Simulate a request
        start_time = time.monotonic()
        await asyncio.sleep(0.1)
        latency = time.monotonic() - start_time
        status_code = 200
        await benchmark.record_request(status_code, latency)

    # In the main attack loop:
    await make_request()

    # At the end of the attack:
    benchmark.generate_report()

Dependencies:
    - asyncio, time, collections, typing (standard libraries)
    - termcolor (for colored console output)

Testing:
    The BenchmarkManager can be tested by:
    - Creating an instance and calling record_request() multiple times with different inputs.
    - Verifying that get_total_requests() returns the correct count.
    - Checking that the response_counts dictionary is updated accurately.
    - Ensuring the generate_report() method calculates and prints statistics correctly.
    - Testing concurrent calls to record_request() to ensure the lock prevents race conditions.
"""

import asyncio
import time
from collections import defaultdict
from typing import List, Optional, Any

from termcolor import colored

class BenchmarkManager:
    """
    Manages and reports HTTP attack statistics in an asynchronous context.
    """
    def __init__(self):
        """
        Initializes the BenchmarkManager, setting the start time and data structures.
        """
        self.start_time: float = time.monotonic()
        self.response_counts: defaultdict[str, int] = defaultdict(int)
        self.latencies: List[float] = []
        # An asyncio lock is crucial to prevent race conditions when multiple
        # workers update the stats concurrently.
        self.lock: asyncio.Lock = asyncio.Lock()

    async def record_request(self, status_code: Optional[Any], latency: float):
        """
        Atomically records the result of a single HTTP request.

        Args:
            status_code (Optional[Any]): The HTTP status code received. Can be any type
                                         that can be converted to a string. If None, it's
                                         treated as a timeout or connection error.
            latency (float): The time taken for the request to complete, in seconds.
        """
        async with self.lock:
            self.latencies.append(latency)
            # Group results by status code. Treat None status as a distinct error category.
            key = str(status_code) if status_code is not None else "Timeout/Error"
            self.response_counts[key] += 1

    def get_total_requests(self) -> int:
        """
        Calculates the total number of requests recorded so far.

        Returns:
            int: The total count of requests.
        """
        # Note: This method is not async and does not need a lock because it's
        # typically called from a single monitoring thread. If called from multiple
        # threads, it should also be under a lock.
        return sum(self.response_counts.values())

    def generate_report(self):
        """
        Calculates final statistics and prints a formatted benchmark report.
        """
        total_duration = time.monotonic() - self.start_time
        total_requests = self.get_total_requests()

        print(colored("\n\n" + "="*25, "cyan"))
        print(colored(" [ BENCHMARK REPORT ]", "white", attrs=["bold"]))
        print(colored("="*25, "cyan"))

        print(colored(f"\n- Total Attack Duration: {total_duration:.2f} seconds", "white"))
        print(colored(f"- Total Requests Sent: {total_requests}", "white"))

        # Display breakdown of response codes.
        if self.response_counts:
            print(colored("\n- Response Status Codes:", "white"))
            # Sort codes for consistent report layout.
            sorted_codes = sorted(self.response_counts.keys(), key=lambda x: str(x))
            for code in sorted_codes:
                count = self.response_counts[code]
                percentage = (count / total_requests) * 100 if total_requests > 0 else 0
                print(f"  - Status {code}: {count} requests ({percentage:.1f}%)")

        # Display latency statistics.
        if self.latencies:
            avg_latency = sum(self.latencies) / len(self.latencies)
            max_latency = max(self.latencies)
            min_latency = min(self.latencies)
            print(colored("\n- Request Latency:", "yellow"))
            print(colored(f"  - Average: {avg_latency:.4f} s", "yellow"))
            print(colored(f"  - Max:     {max_latency:.4f} s", "yellow"))
            print(colored(f"  - Min:     {min_latency:.4f} s", "yellow"))

        # Display overall requests per second.
        avg_rps = total_requests / total_duration if total_duration > 0 else 0
        print(colored(f"\n- Average Throughput: {avg_rps:.2f} RPS (Requests/Second)", "green", attrs=["bold"]))
        print(colored("="*25, "cyan"))
