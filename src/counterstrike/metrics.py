"""Small dependency-free Prometheus exporter for bounded API request metrics."""

from __future__ import annotations

import threading
from collections import defaultdict


class HTTPMetrics:
    """Thread-safe request counters and duration buckets labelled by route template."""

    BUCKETS = (0.01, 0.05, 0.1, 0.3, 0.5, 1.0, 3.0, 10.0)
    METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"})

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._requests: dict[tuple[str, str, str], int] = defaultdict(int)
        self._durations: dict[tuple[str, str, str], list[int]] = defaultdict(
            lambda: [0] * (len(self.BUCKETS) + 1)
        )
        self._duration_sums: dict[tuple[str, str, str], float] = defaultdict(float)
        self._duration_counts: dict[tuple[str, str, str], int] = defaultdict(int)

    def observe(self, method: str, route: str, status_code: int, duration_seconds: float) -> None:
        bounded_method = method.upper() if method.upper() in self.METHODS else "OTHER"
        bounded_route = route if route.startswith("/") and len(route) <= 200 else "unmatched"
        bounded_status = str(status_code) if 100 <= status_code <= 599 else "500"
        key = (bounded_method, bounded_route, bounded_status)
        duration = max(0.0, duration_seconds)
        with self._lock:
            self._requests[key] += 1
            self._duration_counts[key] += 1
            self._duration_sums[key] += duration
            for index, bound in enumerate(self.BUCKETS):
                if duration <= bound:
                    self._durations[key][index] += 1
            self._durations[key][-1] += 1

    @staticmethod
    def _escape(value: str) -> str:
        return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')

    def render(self) -> str:
        with self._lock:
            request_rows = sorted(self._requests.items())
            duration_rows = {
                key: (
                    list(self._durations[key]),
                    self._duration_sums[key],
                    self._duration_counts[key],
                )
                for key, _ in request_rows
            }
        lines = [
            "# HELP counterstrike_http_requests_total Completed HTTP requests.",
            "# TYPE counterstrike_http_requests_total counter",
        ]
        for (method, route, status), count in request_rows:
            labels = (
                f'method="{self._escape(method)}",route="{self._escape(route)}",'
                f'status="{self._escape(status)}"'
            )
            lines.append(f"counterstrike_http_requests_total{{{labels}}} {count}")
        lines.extend(
            [
                "# HELP counterstrike_http_request_duration_seconds HTTP request duration.",
                "# TYPE counterstrike_http_request_duration_seconds histogram",
            ]
        )
        for (method, route, status), (
            buckets,
            duration_sum,
            duration_count,
        ) in duration_rows.items():
            labels = (
                f'method="{self._escape(method)}",route="{self._escape(route)}",'
                f'status="{self._escape(status)}"'
            )
            for index, bound in enumerate(self.BUCKETS):
                lines.append(
                    f"counterstrike_http_request_duration_seconds_bucket"
                    f'{{{labels},le="{bound:g}"}} '
                    f"{buckets[index]}"
                )
            lines.append(
                f'counterstrike_http_request_duration_seconds_bucket{{{labels},le="+Inf"}} '
                f"{buckets[-1]}"
            )
            lines.append(
                f"counterstrike_http_request_duration_seconds_sum{{{labels}}} {duration_sum:.9g}"
            )
            lines.append(
                f"counterstrike_http_request_duration_seconds_count{{{labels}}} {duration_count}"
            )
        return "\n".join(lines) + "\n"
