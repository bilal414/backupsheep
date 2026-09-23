"""Explicit provider registry; provider names never resolve arbitrary imports."""

from __future__ import annotations

from collections.abc import Iterable

from ..errors import KeyProviderConfigurationError
from .base import KeyProvider


def ensure_provider_allowed(provider: KeyProvider, *, enterprise_mode: bool) -> None:
    if enterprise_mode and getattr(provider, "enterprise_eligible", False) is not True:
        raise KeyProviderConfigurationError(
            "Enterprise mode requires an explicitly production-eligible key provider."
        )


class KeyProviderRegistry:
    def __init__(self, providers: Iterable[KeyProvider] = ()):
        self._providers: dict[str, KeyProvider] = {}
        for provider in providers:
            self.register(provider)

    def register(self, provider: KeyProvider) -> None:
        name = str(getattr(provider, "name", ""))
        if not name or name != name.strip() or "." in name or "/" in name:
            raise KeyProviderConfigurationError(
                "The key provider has an invalid registry name."
            )
        if name in self._providers:
            raise KeyProviderConfigurationError(
                "The key provider registry contains a duplicate name."
            )
        self._providers[name] = provider

    def get(self, name: str, *, enterprise_mode: bool = False) -> KeyProvider:
        try:
            provider = self._providers[str(name)]
        except KeyError:
            raise KeyProviderConfigurationError(
                "The requested key provider is not registered."
            ) from None
        ensure_provider_allowed(provider, enterprise_mode=enterprise_mode)
        return provider
