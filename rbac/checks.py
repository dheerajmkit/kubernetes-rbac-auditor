"""Over-privilege checks for Kubernetes RBAC manifests."""

ADMIN_ROLES = ("cluster-admin",)


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return list(value)


def _name(doc):
    return (doc.get("metadata") or {}).get("name", "<unnamed>")


def check_role(doc):
    """Check a Role or ClusterRole document."""
    kind = doc["kind"]
    name = _name(doc)
    rules = doc.get("rules") or []
    findings = []
    if not rules:
        findings.append({
            "check": "empty-role", "severity": "LOW", "object": name,
            "message": f"{kind} {name} has no rules",
        })
        return findings
    for rule in rules:
        verbs = _as_list(rule.get("verbs"))
        resources = _as_list(rule.get("resources"))
        if "*" in verbs and "*" in resources:
            findings.append({
                "check": "wildcard-admin", "severity": "CRITICAL",
                "object": name,
                "message": f"{kind} {name} allows verbs ['*'] on resources ['*']",
            })
            continue
        if "*" in verbs:
            findings.append({
                "check": "wildcard-verbs", "severity": "HIGH", "object": name,
                "message": f"{kind} {name} allows verbs ['*'] on {resources}",
            })
        if "*" in resources:
            findings.append({
                "check": "wildcard-resources", "severity": "HIGH",
                "object": name,
                "message": f"{kind} {name} allows {verbs} on resources ['*']",
            })
        if "secrets" in resources and ("get" in verbs or "*" in verbs):
            findings.append({
                "check": "secrets-access", "severity": "HIGH", "object": name,
                "message": f"{kind} {name} can read secrets",
            })
        if ("pods/exec" in resources or "pods/attach" in resources) \
                and "create" in verbs:
            findings.append({
                "check": "pod-exec", "severity": "HIGH", "object": name,
                "message": f"{kind} {name} can exec into pods",
            })
    return findings


def check_binding(doc):
    """Check a RoleBinding or ClusterRoleBinding document."""
    kind = doc["kind"]
    name = _name(doc)
    ref = doc.get("roleRef") or {}
    ref_name = ref.get("name", "")
    findings = []
    if ref_name in ADMIN_ROLES:
        findings.append({
            "check": "cluster-admin-binding", "severity": "CRITICAL",
            "object": name,
            "message": f"{kind} {name} binds cluster-admin",
        })
    elif "admin" in ref_name.lower():
        findings.append({
            "check": "admin-binding", "severity": "HIGH", "object": name,
            "message": f"{kind} {name} binds admin role {ref_name}",
        })
    return findings


def check_doc(doc):
    """Dispatch one manifest document to the right checker."""
    kind = doc.get("kind")
    if kind in ("Role", "ClusterRole"):
        return check_role(doc)
    if kind in ("RoleBinding", "ClusterRoleBinding"):
        return check_binding(doc)
    return []


def check_manifests(docs):
    """Return all findings for a list of manifest documents."""
    findings = []
    for doc in docs:
        findings.extend(check_doc(doc))
    return findings
