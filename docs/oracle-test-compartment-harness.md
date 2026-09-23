# Oracle test compartment/network harness

`scripts/oracle_test_compartment_e2e.py` is the safety boundary for the Oracle
fixture used by `scripts/oracle_live_ui_e2e.py`. It is offline by default:
`--phase plan` returns before configuration or environment validation and does
not load the OCI profile, construct SDK clients, create ledger files, or call
OCI.

## Safety contract

Mutating phases require all of the following:

- `BACKUPSHEEP_E2E_APPLY=YES`
- a new DNS-safe `BACKUPSHEEP_E2E_RUN_ID`
- `ORACLE_E2E_ALLOWED_TENANCY_OCID` matching the tenancy in the selected
  `OCI_CLI_PROFILE` exactly
- `ORACLE_E2E_REGION=us-ashburn-1` (or the default)
- an exact `ORACLE_E2E_AVAILABILITY_DOMAIN`
- `ORACLE_E2E_CALLER_CIDRS` containing only `/32` or `/128` host CIDRs
- `BACKUPSHEEP_E2E_NETWORK_LEDGER_PATH` outside the repository and `_docs`

The harness creates one child compartment and one owned VCN, internet gateway,
dedicated route table, security list, and public subnet. OCI also creates one
default route table, security list, and DHCP-options resource with each VCN;
the harness adopts those exact VCN-scoped OCIDs into the ledger as provider-
created dependencies. OCI prohibits deleting these three VCN defaults
individually, so the harness never sends direct delete requests for them.
Ingress is limited to SSH and
the configured `ORACLE_E2E_DATABASE_PORTS` from the exact caller host CIDRs.
Egress is limited to TCP 53/80/443 and UDP 53/123, with the default route
explicitly documented as the OCI internet-gateway route required by the public
subnet.

The durable resource ledger and `.network-intents.json` file are fsynced before
and after provider mutations. A lost create response is reconciled by a bounded
complete cursor scan and one exact ownership/name/parent match; duplicate or
foreign matches stop safely and never trigger a second create. Cleanup requires
`BACKUPSHEEP_E2E_CLEANUP=YES` and verifies the complete dependency graph
immediately before deletion. It directly deletes only the custom subnet,
security list, route table, internet gateway, and VCN, in dependency order.
After exact VCN absence is proven, it waits for the provider cascade and marks
the three default-resource ledger rows `absent` only after exact reads prove
each default OCID is gone. The child compartment is deleted last. A surviving
default, unresolved intent, ownership/source drift, unledgered child resource,
or ambiguous provider 404 blocks cleanup without deleting the compartment.

## Handoff to the Oracle live harness

After an explicitly approved live run, the `provision` JSON contains only the
non-secret values required by `oracle_live_ui_e2e.py`:

```text
ORACLE_E2E_ALLOWED_TENANCY_OCID
ORACLE_E2E_COMPARTMENT_OCID
ORACLE_E2E_ALLOWED_COMPARTMENT_OCID
ORACLE_E2E_SUBNET_OCID
ORACLE_E2E_AVAILABILITY_DOMAIN
```

Copy those values into the environment for the existing Oracle source/UI
harness. Keep the network ledger path and run ID unchanged until both the Oracle
fixture and its dependent UI resources have been verified and cleaned.

Focused offline coverage is in
`apps/tests/test_oracle_test_compartment_harness.py`; it uses injected clients
and never reads an OCI profile or contacts Oracle.
