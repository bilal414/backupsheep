# Technical reference

This directory is the canonical reference for the self-hosted BackupSheep implementation
on the `develop` branch. Use the operator [guides](../guides/README.md) for procedures.

| Reference | Contents |
| --- | --- |
| [Architecture](architecture.md) | Services, queues, volumes, data flow, durable execution and trust boundaries |
| [Environment variables](environment-variables.md) | Runtime keys, defaults, units, precedence and restart behavior |
| [Provider matrix](provider-matrix.md) | Source, restore and storage capabilities present in the repository |

The provider matrix distinguishes implemented behavior from integrations that are merely
seeded or shown as coming soon. Runtime validation still depends on provider credentials,
account permissions, API versions, region support and the provider's current service.
