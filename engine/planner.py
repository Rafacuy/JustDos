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
    "LATENCY_HISTORY_SIZE": 100,
    "HEALTH_THRESHOLD": 0.4,
    "EMERGENCY_HEALTH_THRESHOLD": 0.3,
    "MIN_HEALTH_THRESHOLD": 0.5,
    "BASE_COOLDOWN": 60,
    "STALE_PATH_TIMEOUT": 3600,  # 1 hour
    "CLEANUP_INTERVAL": 300,     # 5 minutes
    "HIGH_LATENCY_MULTIPLIER": 2.0,
    "MIN_HIGH_LATENCY": 1.0,     # 1 second
}

class StrategyPlanner:
    """
    Manages and dynamically adapts the attack strategy based on real-time feedback.
    """
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initializes the StrategyPlanner with default or custom config."""
        self.config = {**DEFAULT_CONFIG, **(config or {})}
        self.path_states: Dict[str, Dict[str, Any]] = {}
        self.latency_history: List[float] = []
        self.avg_latency: float = 0.0
        self.total_health: float = 0.0
        self.path_count: int = 0
        self.last_cleanup: float = 0
        self.lock = asyncio.Lock()

    def _get_or_create_path_state(self, path: str) -> Dict[str, Any]:
        """Retrieves or initializes the state for a given path."""
        if path not in self.path_states:
            self.path_states[path] = {
                "health_score": 1.0,
                "last_seen": time.monotonic(),
                "rest_until": 0,
            }
            self.total_health += 1.0
            self.path_count += 1
        return self.path_states[path]

    def _update_latency(self, latency: float):
        """Updates the running average latency."""
        self.latency_history.append(latency)
        if len(self.latency_history) > self.config["LATENCY_HISTORY_SIZE"]:
            self.latency_history.pop(0)
        if self.latency_history:
            self.avg_latency = sum(self.latency_history) / len(self.latency_history)

    def _high_latency_threshold(self) -> float:
        """Calculates the dynamic threshold for high latency."""
        return max(self.config["MIN_HIGH_LATENCY"], self.avg_latency * self.config["HIGH_LATENCY_MULTIPLIER"])

    async def analyze(self, path: str, status_code: Optional[int], latency: float):
        """
        Analyzes a request's result and updates the path's health score.
        """
        current_time = time.monotonic()
        async with self.lock:
            state = self._get_or_create_path_state(path)
            old_health = state["health_score"]
            state["last_seen"] = current_time

            is_successful = status_code is not None and 200 <= status_code < 300
            is_blocked = status_code in {403, 429}
            is_server_error = status_code is not None and 500 <= status_code < 600
            is_high_latency = latency > self._high_latency_threshold()

            if is_successful and not is_high_latency:
                state["health_score"] = min(1.0, state["health_score"] + 0.05)
                self._update_latency(latency)
            else:
                if is_blocked:
                    state["health_score"] -= 0.4
                elif is_server_error:
                    state["health_score"] -= 0.2
                else:
                    state["health_score"] -= 0.1
            
            state["health_score"] = max(0.0, state["health_score"])

            new_health = state["health_score"]
            self.total_health += new_health - old_health

            if state["health_score"] < self.config["HEALTH_THRESHOLD"]:
                cooldown_period = self.config["BASE_COOLDOWN"] * (1 - state["health_score"])
                state["rest_until"] = current_time + cooldown_period

            # Cleanup stale paths if it's time
            if current_time - self.last_cleanup > self.config["CLEANUP_INTERVAL"]:
                to_remove = [
                    p for p, s in self.path_states.items()
                    if current_time - s["last_seen"] > self.config["STALE_PATH_TIMEOUT"]
                ]
                for p in to_remove:
                    self.total_health -= self.path_states[p]["health_score"]
                    del self.path_states[p]
                    self.path_count -= 1
                self.last_cleanup = current_time

    async def get_average_health(self) -> float:
        """Calculates the average health score across all paths."""
        async with self.lock:
            if self.path_count == 0:
                return 1.0
            return self.total_health / self.path_count

    async def is_path_dangerous(self, path: str) -> bool:
        """Determines if a path should be avoided."""
        async with self.lock:
            state = self._get_or_create_path_state(path)
            if time.monotonic() < state.get("rest_until", 0):
                return True
            
            avg_health = self.total_health / self.path_count if self.path_count > 0 else 1.0
            if avg_health < self.config["EMERGENCY_HEALTH_THRESHOLD"]:
                return state["health_score"] < self.config["MIN_HEALTH_THRESHOLD"]
            
            return False

    async def summary(self) -> Dict[str, Any]:
        """Provides a summary of the planner's current state."""
        async with self.lock:
            blocked_paths = [
                path for path, state in self.path_states.items()
                if time.monotonic() < state.get("rest_until", 0)
            ]
            avg_health = self.total_health / self.path_count if self.path_count > 0 else 1.0
            mode = "Emergency" if avg_health < self.config["EMERGENCY_HEALTH_THRESHOLD"] else "Aggressive"
            return {
                "mode": mode,
                "average_health": f"{avg_health:.2f}",
                "blocked_paths_count": len(blocked_paths),
                "active_paths_count": self.path_count - len(blocked_paths),
                "avg_latency_ms": f"{self.avg_latency * 1000:.2f}" if self.avg_latency > 0 else "N/A",
            }