"""Regression coverage for finding-category secret boundaries."""

from scanner.cli.appguardrail import _finding_category


def test_sensitive_database_credentials_are_secret_findings() -> None:
    """Credential-bearing database rule IDs must not fall through to misconfig/storage."""
    assert _finding_category("frontend-database-dsn-exposure") == "secrets"
    assert _finding_category("hardcoded-db-url") == "secrets"
    assert _finding_category("supabase-service-role-client") == "secrets"
