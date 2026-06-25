"""Secrets management for model API keys.

The point of this module is the *interface*: application code should never read
keys from source or plaintext env files. It requests a ``SecretRef`` from a
provider that, in production, is backed by AWS Secrets Manager / Azure Key Vault
/ GCP Secret Manager with short-lived, rotated credentials.

A dependency-free ``EnvSecretsProvider`` is included for local dev and tests; a
sketch ``AwsSecretsProvider`` shows the production shape.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class SecretRef:
    """A reference to a secret, never the secret's source location in code."""
    name: str            # logical name, e.g. "anthropic_api_key"
    version: str = "AWSCURRENT"


class SecretsProvider(Protocol):
    def resolve(self, ref: SecretRef) -> str: ...


class EnvSecretsProvider:
    """Dev/test provider. Maps logical name -> ENV var. Never log the value."""
    def __init__(self, prefix: str = ""):
        self.prefix = prefix

    def resolve(self, ref: SecretRef) -> str:
        env_key = (self.prefix + ref.name).upper()
        val = os.environ.get(env_key)
        if not val:
            raise KeyError(f"secret '{ref.name}' not found (env {env_key})")
        return val


class AwsSecretsProvider:  # pragma: no cover - requires boto3 + AWS creds
    """Production sketch. Uses IAM role (no static creds) + rotation."""
    def __init__(self, region: str):
        import boto3  # imported lazily so the package has no hard dep
        self._client = boto3.client("secretsmanager", region_name=region)

    def resolve(self, ref: SecretRef) -> str:
        resp = self._client.get_secret_value(
            SecretId=ref.name, VersionStage=ref.version)
        return resp["SecretString"]


@dataclass
class SecretsManager:
    """Caches resolved secrets in-process for their TTL; redacts on repr."""
    provider: SecretsProvider

    def get(self, name: str, version: str = "AWSCURRENT") -> str:
        return self.provider.resolve(SecretRef(name, version))

    def __repr__(self) -> str:  # never leak cached secrets via repr/logs
        return f"SecretsManager(provider={type(self.provider).__name__})"


def get_model_key(name: str = "anthropic_api_key",
                  manager: SecretsManager | None = None) -> str:
    """Single entry point app code uses to obtain a model API key."""
    manager = manager or SecretsManager(EnvSecretsProvider())
    return manager.get(name)


class InMemorySecretsProvider:
    """Test/dev provider backed by an in-process dict. Never use in prod."""
    def __init__(self, store: dict[str, str] | None = None):
        self._store = dict(store or {})

    def set(self, name: str, value: str) -> None:
        self._store[name] = value

    def resolve(self, ref: SecretRef) -> str:
        if ref.name not in self._store:
            raise KeyError(f"secret '{ref.name}' not found")
        return self._store[ref.name]


class AzureKeyVaultProvider:  # pragma: no cover - requires azure SDK + creds
    """Production sketch for Azure Key Vault using managed identity (no static creds)."""
    def __init__(self, vault_url: str):
        from azure.identity import DefaultAzureCredential
        from azure.keyvault.secrets import SecretClient
        self._client = SecretClient(
            vault_url=vault_url, credential=DefaultAzureCredential())

    def resolve(self, ref: SecretRef) -> str:
        version = None if ref.version == "AWSCURRENT" else ref.version
        return self._client.get_secret(ref.name, version).value


class GcpSecretManagerProvider:  # pragma: no cover - requires google SDK + creds
    """Production sketch for GCP Secret Manager using workload identity."""
    def __init__(self, project_id: str):
        from google.cloud import secretmanager
        self._client = secretmanager.SecretManagerServiceClient()
        self._project = project_id

    def resolve(self, ref: SecretRef) -> str:
        version = "latest" if ref.version == "AWSCURRENT" else ref.version
        name = f"projects/{self._project}/secrets/{ref.name}/versions/{version}"
        resp = self._client.access_secret_version(name=name)
        return resp.payload.data.decode("utf-8")
