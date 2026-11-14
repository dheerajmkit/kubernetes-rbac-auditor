"""Resolve bindings to effective per-subject access."""

from .checks import check_role, _as_list


def _subject_key(subject):
    kind = subject.get("kind", "?")
    name = subject.get("name", "?")
    ns = subject.get("namespace", "")
    return f"{kind}:{ns}/{name}" if ns else f"{kind}:{name}"


def resolve_bindings(docs):
    """Map subject key -> list of bound role names."""
    mapping = {}
    for doc in docs:
        if doc.get("kind") not in ("RoleBinding", "ClusterRoleBinding"):
            continue
        ref = doc.get("roleRef") or {}
        role = ref.get("name", "?")
        for subject in doc.get("subjects") or []:
            mapping.setdefault(_subject_key(subject), []).append(role)
    return mapping


def check_effective(docs):
    """Flag subjects effectively bound to over-privileged roles.

    Also flags ServiceAccounts that auto-mount their API token.
    """
    findings = []
    roles = {}
    for doc in docs:
        if doc.get("kind") in ("Role", "ClusterRole"):
            roles[(doc.get("metadata") or {}).get("name")] = doc
    role_severity = {}
    for name, doc in roles.items():
        worst = None
        for f in check_role(doc):
            if f["severity"] in ("CRITICAL", "HIGH"):
                worst = f["severity"] if worst != "CRITICAL" else worst
        role_severity[name] = worst

    for subject, bound in resolve_bindings(docs).items():
        for role in bound:
            sev = role_severity.get(role)
            if sev == "CRITICAL":
                findings.append({
                    "check": "effective-admin", "severity": "CRITICAL",
                    "object": subject,
                    "message": f"{subject} is bound to over-privileged role {role}",
                })
            elif sev == "HIGH":
                findings.append({
                    "check": "effective-privileged", "severity": "HIGH",
                    "object": subject,
                    "message": f"{subject} is bound to privileged role {role}",
                })

    for doc in docs:
        if doc.get("kind") == "ServiceAccount":
            auto = (doc.get("automountServiceAccountToken") is True)
            name = (doc.get("metadata") or {}).get("name", "?")
            if auto:
                findings.append({
                    "check": "sa-token-automount", "severity": "MEDIUM",
                    "object": name,
                    "message": f"ServiceAccount {name} auto-mounts its API token",
                })
    return findings
