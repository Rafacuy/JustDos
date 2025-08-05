# engine/planner.py

"""
Adaptive Strategy Planner for JustDos.

This module provides the StrategyPlanner class, upgraded to an "Adaptive Ninja" with dynamic health scores,
smart cooldowns, and adaptive attack modes to make the attack strategy more intelligent and resilient.
"""

import asyncio
import time
from typing import Optional, Dict, List, Any

# --- Default Configuration ---
DEFAULT_CONFIG = {
    "LATENCY_MULTIPLIER": 3.0,      # Multiplier for avg latency to determine a "slow" path
    "MIN_LATENCY_THRESHOLD": 1.5,   # Minimum threshold for slowness, in seconds
    "BLOCK_COOLDOWN_S": 60,         # Base cooldown replaced by dynamic cooldown
    "MAX_CONSECUTIVE_FAILURES": 3,  # Legacy metric, retained but less critical with health scores
    "LATENCY_HISTORY_SIZE": 100,    # How many recent latency values to average
    "HEALTH_THRESHOLD": 0.4,        # Below this, a path enters cooldown
    "EMERGENCY_HEALTH_THRESHOLD": 0.3,  # Average health below this triggers Emergency Mode
    "MIN_HEALTH_THRESHOLD": 0.5,    # Minimum health to use a path in Emergency Mode
    "BASE_COOLDOWN": 120,           # Base cooldown in seconds for dynamic calculation
}

class StrategyPlanner:
    """
    Manages and dynamically adapts the attack strategy based on real-time feedback.

    The "Adaptive Ninja" with HealthScore-based path management, smart cooldowns,
    and dynamic attack modes (Emergency vs Aggressive).

    Attributes:
        config (Dict[str, Any]): Configuration settings for the planner
        path_states (Dict[str, Dict]): Stores the dynamic state of each attack path
        latency_history (List[float]): A list of recent successful request latencies
        avg_latency (float): The current average latency of successful requests
        lock (asyncio.Lock): A lock for thread-safe operations
    """
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initializes the StrategyPlanner with default or custom config."""
        self.config = {**DEFAULT_CONFIG, **(config or {})}
        self.path_states: Dict[str, Dict[str, Any]] = {}
        self.latency_history: List[float] = []
        self.avg_latency: float = 0.0
        self.lock = asyncio.Lock()

    async def _get_or_create_path_state(self, path: str) -> Dict[str, Any]:
        """Retrieves or initializes the state for a given path with a health score."""
        if path not in self.path_states:
            self.path_states[path] = {
                "health_score": 1.0,  # Starts healthy
                "last_seen": 0,
                "last_failure": 0,
                "consecutive_failures": 0,
            }
        return self.path_states[path]

    async def _update_latency(self, latency: float):
        """Updates the running average latency for successful requests."""
        self.latency_history.append(latency)
        if len(self.latency_history) > self.config["LATENCY_HISTORY_SIZE"]:
            self.latency_history.pop(0)
        if self.latency_history:
            self.avg_latency = sum(self.latency_history) / len(self.latency_history)

    async def analyze(self, path: str, status_code: Optional[int], latency: float):
        """
        Analyzes a request's result, updates the path's health score, and manages cooldowns.

        Args:
            path (str): The resource path that was requested
            status_code (Optional[int]): The HTTP status code of the response
            latency (float): The request latency in seconds
        """
        async with self.lock:
            state = await self._get_or_create_path_state(path)
            state["last_seen"] = time.monotonic()

            is_successful = status_code is not None and 200 <= status_code < 300
            is_blocked_by_waf = status_code in {403, 429}
            is_server_error = status_code is not None and 500 <= status_code < 600
            is_connection_failure = status_code is None
            is_high_latency = latency > 3.0  # Fixed threshold of 3s as per team example

            if is_successful:
                state["health_score"] += 0.1
                if is_high_latency:
                    state["health_score"] -= 0.3
                state["consecutive_failures"] = 0
                await self._update_latency(latency)
            else:
                state["consecutive_failures"] += 1
                state["last_failure"] = time.monotonic()
                if is_blocked_by_waf:
                    state["health_score"] -= 0.5
                elif is_server_error or is_connection_failure:
                    state["health_score"] -= 0.4

            # Clamp health_score between 0 and 1
            state["health_score"] = max(0.0, min(1.0, state["health_score"]))

            # Smart Cooldown Timer: Enter cooldown if health_score falls below threshold
            if state["health_score"] < self.config["HEALTH_THRESHOLD"]:
                cooldown_period = self.config["BASE_COOLDOWN"] * (1 - state["health_score"])
                state["rest_until"] = time.monotonic() + cooldown_period

    async def get_average_health(self) -> float:
        """Calculates the average health score across all paths."""
        async with self.lock:
            if not self.path_states:
                return 1.0
            total_health = sum(state["health_score"] for state in self.path_states.values())
            return total_health / len(self.path_states)

    async def is_path_dangerous(self, path: str) -> bool:
        """
        Determines if a path should be avoided based on its health score and attack mode.

        Args:
            path (str): The path to check

        Returns:
            bool: True if the path should be avoided, False otherwise
        """
        async with self.lock:
            state = await self._get_or_create_path_state(path)
            if "rest_until" in state and time.monotonic() < state["rest_until"]:
                return True
            avg_health = await self.get_average_health()
            if avg_health < self.config["EMERGENCY_HEALTH_THRESHOLD"] and state["health_score"] < self.config["MIN_HEALTH_THRESHOLD"]:
                return True
            return False

    async def summary(self) -> Dict[str, Any]:
        """
        Provides a summary of the planner's current state, including attack mode.

        Returns:
            A dictionary with current stats
        """
        async with self.lock:
            blocked_paths = [
                path for path, state in self.path_states.items()
                if "rest_until" in state and time.monotonic() < state["rest_until"]
            ]
            avg_health = await self.get_average_health()
            mode = "Emergency Mode" if avg_health < self.config["EMERGENCY_HEALTH_THRESHOLD"] else "Aggressive Mode"
            return {
                "mode": mode,
                "average_health": f"{avg_health:.2f}",
                "blocked_paths": sorted(blocked_paths),
                "active_paths_count": len(self.path_states) - len(blocked_paths),
                "avg_latency_ms": f"{self.avg_latency * 1000:.2f}" if self.avg_latency > 0 else "N/A",
            }