"""
Anomaly Engine Module
Maintains behavioral baselines and computes five-point anomaly scores.

Five evaluation points:
- traffic_patterns: connection rates/ports compared to baseline
- location: geo/country changes by entity
- device: MAC/vendor fingerprint changes
- applications: services/ports accessed distribution
- time: access time-of-day pattern deviation
"""

from typing import Dict, Any, Optional, Tuple
from collections import defaultdict, deque
from datetime import datetime, timedelta
import math


class AnomalyEngine:
    """Compute anomaly scores against rolling baselines for entities.

    The engine tracks per-entity baselines. An entity_id can be an IP, a user, or device id.
    Scores are 0-2 per facet (0 normal, 1 unusual, 2 highly anomalous). Total in [0, 10].
    """

    def __init__(self, config: Dict):
        self.config = config or {}
        self.window_hours = self.config.get('window_hours', 24)
        self.min_samples_for_strict = self.config.get('min_samples_for_strict', 50)
        self.connection_rate_threshold = self.config.get('connection_rate_threshold', 3.0)
        self.port_novelty_threshold = self.config.get('port_novelty_threshold', 0.05)
        self.location_change_penalty = self.config.get('location_change_penalty', 2)
        self.device_change_penalty = self.config.get('device_change_penalty', 2)
        self.app_change_penalty = self.config.get('app_change_penalty', 1)
        self.time_bucket_hours = self.config.get('time_bucket_hours', 1)

        # Rolling data stores per entity
        self._entity_connections: Dict[str, deque] = defaultdict(lambda: deque())  # timestamps
        self._entity_ports_count: Dict[str, Dict[int, int]] = defaultdict(lambda: defaultdict(int))
        self._entity_locations: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self._entity_devices: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self._entity_apps: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self._entity_time_buckets: Dict[str, Dict[int, int]] = defaultdict(lambda: defaultdict(int))

    def _prune_old(self, entity_id: str, now: datetime) -> None:
        cutoff = now - timedelta(hours=self.window_hours)
        timestamps = self._entity_connections[entity_id]
        while timestamps and timestamps[0] < cutoff:
            timestamps.popleft()

    def _bucket_for_time(self, dt: datetime) -> int:
        bucket = (dt.hour // self.time_bucket_hours) * self.time_bucket_hours
        return bucket

    def update_and_score(self, entity_id: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Update baselines with the current observation and return facet scores.

        Context expected keys (best-effort):
        - src_ip, dst_ip, src_mac, user_id
        - port (int), app (str)
        - country (str)
        - timestamp (datetime)
        """
        now = context.get('timestamp') or datetime.utcnow()
        country = context.get('country') or 'Unknown'
        device = context.get('src_mac') or 'Unknown'
        port = context.get('port')
        app = context.get('app') or (f"port:{port}" if port is not None else 'Unknown')

        # Ensure structures
        self._prune_old(entity_id, now)
        self._entity_connections[entity_id].append(now)
        if port is not None:
            self._entity_ports_count[entity_id][int(port)] += 1
        if country:
            self._entity_locations[entity_id][country] += 1
        if device:
            self._entity_devices[entity_id][device] += 1
        if app:
            self._entity_apps[entity_id][app] += 1
        bucket = self._bucket_for_time(now)
        self._entity_time_buckets[entity_id][bucket] += 1

        return self._score_current(entity_id, now, port, country, device, app, bucket)

    def _score_current(
        self,
        entity_id: str,
        now: datetime,
        port: Optional[int],
        country: str,
        device: str,
        app: str,
        bucket: int,
    ) -> Dict[str, Any]:
        # Traffic patterns: rate of connections vs average in window
        timestamps = self._entity_connections[entity_id]
        hours = max(1.0, (timestamps[-1] - timestamps[0]).total_seconds() / 3600.0) if len(timestamps) > 1 else 1.0
        rate = len(timestamps) / hours
        baseline_rate = max(1.0, (len(timestamps) - 1) / hours) if len(timestamps) > 2 else 1.0
        traffic_score = 0
        if rate > baseline_rate * self.connection_rate_threshold:
            traffic_score = 2
        elif rate > baseline_rate * (self.connection_rate_threshold * 0.67):
            traffic_score = 1

        # Location: if dominant location differs or new country observed
        loc_counts = self._entity_locations[entity_id]
        dominant_country, dominant_count = self._max_kv(loc_counts)
        location_score = 0
        if dominant_country and country != dominant_country:
            location_score = self.location_change_penalty
        elif loc_counts.get(country, 0) <= 1 and len(loc_counts) > 1:
            location_score = 1

        # Device: change in MAC/vendor
        dev_counts = self._entity_devices[entity_id]
        dominant_device, _ = self._max_kv(dev_counts)
        device_score = 0
        if dominant_device and device != dominant_device:
            device_score = self.device_change_penalty
        elif dev_counts.get(device, 0) <= 1 and len(dev_counts) > 1:
            device_score = 1

        # Applications: port/app distribution, novelty
        app_counts = self._entity_apps[entity_id]
        total_app_obs = sum(app_counts.values())
        app_score = 0
        if total_app_obs > 0 and app_counts.get(app, 0) / total_app_obs < self.port_novelty_threshold:
            app_score = min(2, self.app_change_penalty)

        # Time: bucket usage rarity
        time_counts = self._entity_time_buckets[entity_id]
        total_time_obs = sum(time_counts.values())
        time_score = 0
        if total_time_obs > 0 and time_counts.get(bucket, 0) / total_time_obs < 0.1:
            time_score = 1
        if total_time_obs >= self.min_samples_for_strict and time_counts.get(bucket, 0) / total_time_obs < 0.05:
            time_score = 2

        total = sum([traffic_score, location_score, device_score, app_score, time_score])

        return {
            'entity_id': entity_id,
            'timestamp': now,
            'scores': {
                'traffic_patterns': traffic_score,
                'location': location_score,
                'device': device_score,
                'applications': app_score,
                'time': time_score,
            },
            'total_score': total,
            'context': {
                'country': country,
                'device': device,
                'port': port,
                'app': app,
                'time_bucket': bucket,
            }
        }

    def _max_kv(self, d: Dict[str, int]) -> Tuple[Optional[str], int]:
        if not d:
            return None, 0
        key = max(d, key=lambda k: d[k])
        return key, d[key]
