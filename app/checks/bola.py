"""BOLA / IDOR check — cross-account object access with two authenticated roles.

Requires at least two test-account sessions whose owned object ids differ. Using
session A, we request an object owned by session B (substituted into the endpoint's
id parameter/path). If A receives B's object (2xx with B's identifier present), the
object-level authorization is broken. SAFE_ACTIVE, non-state-changing (GET only).
"""

from __future__ import annotations

import re

from app.checks.base import BaseCheck, CheckContext, RawEvidence, RawFinding, registry
from app.core.enums import CheckClass, Confidence, Severity, TestIntensity
from app.security.http_client import TargetUnreachable
from app.security.redaction import build_evidence_exchange

_PATH_ID = re.compile(r"\{id\}|\{[^}]*id[^}]*\}", re.IGNORECASE)


class BolaCheck(BaseCheck):
    name = "bola.cross_account"
    check_class = CheckClass.BOLA
    intensity = TestIntensity.SAFE_ACTIVE
    cwe = "CWE-639"
    state_changing = False

    async def applies_to(self, ctx: CheckContext) -> bool:
        if ctx.endpoint.method != "GET":
            return False
        has_id = bool(_PATH_ID.search(ctx.endpoint.path_template)) or any(
            "id" in p.get("name", "").lower() for p in ctx.endpoint.parameters
        )
        return has_id and len([s for s in ctx.sessions if not s.expired]) >= 2

    async def run(self, ctx: CheckContext) -> list[RawFinding]:
        active = [s for s in ctx.sessions if not s.expired]
        if len(active) < 2:
            return []
        findings: list[RawFinding] = []
        # For each ordered pair (attacker, victim) try to reach victim's object as attacker.
        for attacker in active:
            for victim in active:
                if attacker is victim or not victim.owns_object_ids:
                    continue
                victim_obj = str(victim.owns_object_ids[0])
                finding = await self._attempt(ctx, attacker, victim, victim_obj)
                if finding:
                    findings.append(finding)
                    return findings  # one confirmed cross-access is enough per endpoint
        return findings

    async def _attempt(self, ctx, attacker, victim, victim_obj) -> RawFinding | None:
        url, params = self._build_target(ctx, victim_obj)
        headers = dict(attacker.headers)
        try:
            resp = await ctx.client.get(url, headers=headers, params=params)
        except TargetUnreachable:
            return None

        # Signal: attacker got a success response that references the victim's object id.
        accessible = resp.status_code == 200 and victim_obj in resp.text
        # Corroborate: the same request WITHOUT auth should NOT succeed (else it's just public).
        if accessible:
            try:
                anon = await ctx.client.get(url, params=params)
                if anon.status_code == 200 and victim_obj in anon.text:
                    return None  # resource is simply public, not a BOLA
            except TargetUnreachable:
                pass
            ev = RawEvidence(
                kind="http_exchange",
                note=(
                    f"account '{attacker.role_name}' accessed object {victim_obj} "
                    f"owned by '{victim.role_name}'"
                ),
                **build_evidence_exchange(
                    request={
                        "method": "GET",
                        "url": resp.url,
                        "headers": resp.request_headers,
                        "body": None,
                    },
                    response={
                        "status": resp.status_code,
                        "headers": resp.headers,
                        "body": resp.text,
                        "elapsed_ms": resp.elapsed_ms,
                    },
                ),
            )
            return RawFinding(
                check_class=self.check_class.value,
                title=f"Broken object-level authorization (BOLA) on {ctx.endpoint.path_template}",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                cwe=self.cwe,
                description=(
                    f"Account '{attacker.role_name}' successfully retrieved object '{victim_obj}' "
                    f"belonging to account '{victim.role_name}'. The endpoint does not enforce "
                    f"that the requester owns the referenced object."
                ),
                remediation=(
                    "Enforce object ownership on every request server-side (compare the object's "
                    "owner to the authenticated principal). Do not rely on unguessable ids. "
                    "Adopt centralized authorization checks."
                ),
                evidence=[ev],
                endpoint_url=ctx.endpoint.url,
                dedup_seed=f"bola:{ctx.endpoint.path_template}",
                reproduction={
                    "method": "GET",
                    "url": url,
                    "attacker_role": attacker.role_name,
                    "victim_role": victim.role_name,
                    "object_id": victim_obj,
                    "detector": "cross_account_access",
                },
            )
        return None

    def _build_target(self, ctx: CheckContext, obj_id: str) -> tuple[str, dict]:
        url = ctx.endpoint.url
        params: dict = {}
        if _PATH_ID.search(url):
            url = _PATH_ID.sub(obj_id, url)
        elif _PATH_ID.search(ctx.endpoint.path_template):
            # substitute the last path segment with the id
            url = re.sub(r"/[^/]*$", f"/{obj_id}", url)
        else:
            id_param = next(
                (
                    p["name"]
                    for p in ctx.endpoint.parameters
                    if "id" in p.get("name", "").lower()
                ),
                None,
            )
            if id_param:
                params[id_param] = obj_id
        return url, params


registry.register(BolaCheck())
