"""Discovery: turn artifacts and authorized browsing into an endpoint inventory."""

from app.discovery.normalize import (
    DiscoveredEndpoint,
    endpoint_fingerprint,
    merge_endpoints,
)

__all__ = ["DiscoveredEndpoint", "endpoint_fingerprint", "merge_endpoints"]
