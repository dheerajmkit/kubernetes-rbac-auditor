# kubernetes-rbac-auditor

Audits Kubernetes RBAC manifests (Role, ClusterRole, RoleBinding,
ClusterRoleBinding) for over-privileged grants: wildcard verbs and
resources, cluster-admin bindings, secrets access, and pod exec rights.
Manifests are parsed with a small built-in YAML-subset parser — no
PyYAML dependency.

This is a **personal portfolio project** exploring Kubernetes RBAC
analysis and security automation. It is a learning exercise, not a
production tool, and it has never been deployed at any employer.

## Quickstart

No dependencies to install — the standard library is all you need:

```bash
python3 run.py samples/admin-role.yaml
python3 run.py samples/readonly-role.yaml
```

Exit codes: `2` = usage error or unreadable manifest, `1` = at least
one high or critical finding, `0` = no high or critical findings.

## Day-1 scope

- Multi-document YAML parsing (mappings, sequences, nested blocks,
  flow lists like `verbs: ["*"]`).
- Checks: wildcard admin roles, wildcard verbs/resources, secrets
  access, pods/exec and pods/attach, cluster-admin bindings, empty roles.
- Text and JSON (`--json`) findings reports with severity counts.
