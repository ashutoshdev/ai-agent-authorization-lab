from dataclasses import dataclass
from datetime import datetime, timedelta, timezone


@dataclass(frozen=True)
class Capability:
    capability_id: str
    name: str
    issuer: str
    subject: str
    tenant_id: str
    audience: str
    issued_at: datetime
    expires_at: datetime
    revoked: bool = False


@dataclass(frozen=True)
class CapabilityDecision:
    allowed: bool
    reason: str


def create_capability(
    capability_id: str = "cap-001",
    tenant_id: str = "tenant-a",
    subject: str = "agent-tenant-a",
    audience: str = "document-service",
    lifetime_seconds: int = 300,
    now: datetime | None = None,
) -> Capability:
    if now is None:
        now = datetime.now(
            timezone.utc
        )

    return Capability(
        capability_id=capability_id,
        name="read_document",
        issuer="authorization-service",
        subject=subject,
        tenant_id=tenant_id,
        audience=audience,
        issued_at=now,
        expires_at=(
            now
            + timedelta(
                seconds=lifetime_seconds
            )
        ),
    )


def validate_capability(
    capability: Capability,
    caller_subject: str,
    caller_tenant: str,
    expected_audience: str,
    now: datetime,
) -> CapabilityDecision:
    if capability.revoked:
        return CapabilityDecision(
            allowed=False,
            reason="Capability has been revoked.",
        )

    if now >= capability.expires_at:
        return CapabilityDecision(
            allowed=False,
            reason="Capability has expired.",
        )

    if (
        capability.subject
        != caller_subject
    ):
        return CapabilityDecision(
            allowed=False,
            reason=(
                "Capability subject does not "
                "match caller."
            ),
        )

    if (
        capability.tenant_id
        != caller_tenant
    ):
        return CapabilityDecision(
            allowed=False,
            reason=(
                "Capability tenant does not "
                "match caller tenant."
            ),
        )

    if (
        capability.audience
        != expected_audience
    ):
        return CapabilityDecision(
            allowed=False,
            reason=(
                "Capability audience does not "
                "match target service."
            ),
        )

    return CapabilityDecision(
        allowed=True,
        reason=(
            "Capability passed lifecycle validation."
        ),
    )


def test_valid_capability():
    now = datetime(
        2026,
        1,
        1,
        tzinfo=timezone.utc,
    )

    capability = create_capability(
        now=now
    )

    decision = validate_capability(
        capability=capability,
        caller_subject="agent-tenant-a",
        caller_tenant="tenant-a",
        expected_audience="document-service",
        now=now + timedelta(
            seconds=10
        ),
    )

    assert decision.allowed is True


def test_expired_capability():
    now = datetime(
        2026,
        1,
        1,
        tzinfo=timezone.utc,
    )

    capability = create_capability(
        now=now,
        lifetime_seconds=60,
    )

    decision = validate_capability(
        capability=capability,
        caller_subject="agent-tenant-a",
        caller_tenant="tenant-a",
        expected_audience="document-service",
        now=now + timedelta(
            seconds=61
        ),
    )

    assert decision.allowed is False

    assert (
        "expired"
        in decision.reason.lower()
    )


def test_revoked_capability():
    now = datetime(
        2026,
        1,
        1,
        tzinfo=timezone.utc,
    )

    capability = create_capability(
        now=now
    )

    revoked = Capability(
        capability_id=capability.capability_id,
        name=capability.name,
        issuer=capability.issuer,
        subject=capability.subject,
        tenant_id=capability.tenant_id,
        audience=capability.audience,
        issued_at=capability.issued_at,
        expires_at=capability.expires_at,
        revoked=True,
    )

    decision = validate_capability(
        capability=revoked,
        caller_subject="agent-tenant-a",
        caller_tenant="tenant-a",
        expected_audience="document-service",
        now=now + timedelta(
            seconds=10
        ),
    )

    assert decision.allowed is False

    assert (
        "revoked"
        in decision.reason.lower()
    )


def test_wrong_subject():
    now = datetime(
        2026,
        1,
        1,
        tzinfo=timezone.utc,
    )

    capability = create_capability(
        now=now
    )

    decision = validate_capability(
        capability=capability,
        caller_subject="agent-tenant-b",
        caller_tenant="tenant-a",
        expected_audience="document-service",
        now=now,
    )

    assert decision.allowed is False


def test_wrong_tenant():
    now = datetime(
        2026,
        1,
        1,
        tzinfo=timezone.utc,
    )

    capability = create_capability(
        now=now
    )

    decision = validate_capability(
        capability=capability,
        caller_subject="agent-tenant-a",
        caller_tenant="tenant-b",
        expected_audience="document-service",
        now=now,
    )

    assert decision.allowed is False

    assert (
        "tenant"
        in decision.reason.lower()
    )


def test_wrong_audience():
    now = datetime(
        2026,
        1,
        1,
        tzinfo=timezone.utc,
    )

    capability = create_capability(
        now=now
    )

    decision = validate_capability(
        capability=capability,
        caller_subject="agent-tenant-a",
        caller_tenant="tenant-a",
        expected_audience="admin-service",
        now=now,
    )

    assert decision.allowed is False

    assert (
        "audience"
        in decision.reason.lower()
    )


def test_tenant_substitution():
    now = datetime(
        2026,
        1,
        1,
        tzinfo=timezone.utc,
    )

    original = create_capability(
        tenant_id="tenant-a",
        subject="agent-tenant-a",
        now=now,
    )

    substituted = Capability(
        capability_id=original.capability_id,
        name=original.name,
        issuer=original.issuer,
        subject=original.subject,
        tenant_id="tenant-b",
        audience=original.audience,
        issued_at=original.issued_at,
        expires_at=original.expires_at,
        revoked=original.revoked,
    )

    decision = validate_capability(
        capability=substituted,
        caller_subject="agent-tenant-a",
        caller_tenant="tenant-a",
        expected_audience="document-service",
        now=now,
    )

    assert decision.allowed is False


def test_audience_substitution():
    now = datetime(
        2026,
        1,
        1,
        tzinfo=timezone.utc,
    )

    original = create_capability(
        audience="document-service",
        now=now,
    )

    substituted = Capability(
        capability_id=original.capability_id,
        name=original.name,
        issuer=original.issuer,
        subject=original.subject,
        tenant_id=original.tenant_id,
        audience="admin-service",
        issued_at=original.issued_at,
        expires_at=original.expires_at,
        revoked=original.revoked,
    )

    decision = validate_capability(
        capability=substituted,
        caller_subject="agent-tenant-a",
        caller_tenant="tenant-a",
        expected_audience="document-service",
        now=now,
    )

    assert decision.allowed is False


def test_replay_after_expiration():
    now = datetime(
        2026,
        1,
        1,
        tzinfo=timezone.utc,
    )

    capability = create_capability(
        now=now,
        lifetime_seconds=30,
    )

    first_use = validate_capability(
        capability=capability,
        caller_subject="agent-tenant-a",
        caller_tenant="tenant-a",
        expected_audience="document-service",
        now=now + timedelta(
            seconds=10
        ),
    )

    replay = validate_capability(
        capability=capability,
        caller_subject="agent-tenant-a",
        caller_tenant="tenant-a",
        expected_audience="document-service",
        now=now + timedelta(
            seconds=31
        ),
    )

    assert first_use.allowed is True
    assert replay.allowed is False


def test_cross_service_reuse():
    now = datetime(
        2026,
        1,
        1,
        tzinfo=timezone.utc,
    )

    capability = create_capability(
        audience="document-service",
        now=now,
    )

    decision = validate_capability(
        capability=capability,
        caller_subject="agent-tenant-a",
        caller_tenant="tenant-a",
        expected_audience="storage-service",
        now=now,
    )

    assert decision.allowed is False


def run_test(
    name,
    test,
):
    try:
        test()

        print(
            f"PASS: {name}"
        )

        return True

    except AssertionError as exc:
        print(
            f"FAIL: {name}"
        )

        if str(exc):
            print(
                f"  {exc}"
            )

        return False


def main():
    print(
        "=" * 70
    )

    print(
        "CAPABILITY LIFECYCLE SECURITY TEST"
    )

    print(
        "=" * 70
    )

    tests = [
        (
            "Valid capability",
            test_valid_capability,
        ),
        (
            "Expired capability",
            test_expired_capability,
        ),
        (
            "Revoked capability",
            test_revoked_capability,
        ),
        (
            "Wrong subject",
            test_wrong_subject,
        ),
        (
            "Wrong tenant",
            test_wrong_tenant,
        ),
        (
            "Wrong audience",
            test_wrong_audience,
        ),
        (
            "Tenant substitution",
            test_tenant_substitution,
        ),
        (
            "Audience substitution",
            test_audience_substitution,
        ),
        (
            "Replay after expiration",
            test_replay_after_expiration,
        ),
        (
            "Cross-service reuse",
            test_cross_service_reuse,
        ),
    ]

    passed = 0

    for name, test in tests:
        print()

        if run_test(
            name,
            test,
        ):
            passed += 1

    print(
        "\n"
        + "=" * 70
    )

    print(
        f"Result: "
        f"{passed}/{len(tests)} tests passed"
    )

    print(
        "=" * 70
    )

    if passed != len(tests):
        raise SystemExit(1)

    print(
        "\nSECURITY INVARIANT: PASSED"
    )


if __name__ == "__main__":
    main()