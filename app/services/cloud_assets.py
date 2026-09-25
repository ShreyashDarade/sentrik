"""Cloud / identity asset authorization seam (BS-18 / C42).

Cross-domain attack paths (app → cloud → identity) start by *enumerating* assets in a cloud
or identity provider. Sentrik keeps that behind a provider interface and — crucially — every
enumerated asset is deny-by-default: it may only be tested after it is covered by a verified
``AuthorizationRecord``. This module supplies the interface and a fake provider so the seam is
exercised offline; a real AWS/Azure/Okta provider implements the same interface later.

The security property under test: discovering an asset never grants permission to test it.
``evaluate_assets`` runs each asset host through ``ScopeGuard.evaluate_new_asset`` — the same
deterministic gate the crawler uses for newly discovered hosts.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from app.security.scope import ScopeGuard


@dataclass
class CloudAsset:
    asset_id: str
    kind: str  # e.g. "s3_bucket", "ec2_instance", "okta_app"
    host: str
    metadata: dict = field(default_factory=dict)


@dataclass
class AssetEvaluation:
    asset: CloudAsset
    authorized: bool
    reason: str
    code: str = ""


class CloudAssetProvider(ABC):
    name = "base"

    @abstractmethod
    async def enumerate_assets(self) -> list[CloudAsset]: ...


class FakeCloudProvider(CloudAssetProvider):
    """Deterministic lab provider — returns a fixed set of pretend cloud/identity assets."""

    name = "fake"

    def __init__(self, assets: list[CloudAsset] | None = None):
        self._assets = assets if assets is not None else [
            CloudAsset("s3-001", "s3_bucket", "assets.example-corp.com", {"region": "us-east-1"}),
            CloudAsset("ec2-001", "ec2_instance", "10.0.4.17", {"vpc": "vpc-lab"}),
            CloudAsset("okta-001", "okta_app", "login.example-corp.com", {"app": "sso"}),
        ]

    async def enumerate_assets(self) -> list[CloudAsset]:
        return list(self._assets)


def get_provider(kind: str) -> CloudAssetProvider:
    if kind == "fake":
        return FakeCloudProvider()
    raise ValueError(f"unknown cloud-asset provider {kind!r} (available: fake)")


def evaluate_assets(guard: ScopeGuard, assets: list[CloudAsset]) -> list[AssetEvaluation]:
    """Deny-by-default authorization gate for each enumerated asset."""
    out: list[AssetEvaluation] = []
    for asset in assets:
        decision = guard.evaluate_new_asset(asset.host)
        out.append(
            AssetEvaluation(
                asset=asset,
                authorized=decision.allowed,
                reason=decision.reason,
                code=getattr(decision, "code", "") or "",
            )
        )
    return out
