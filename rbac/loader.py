"""Load Kubernetes RBAC manifests from YAML files."""

from .yamlmini import parse_yaml


def load_manifests(path):
    """Load a YAML manifest file; return the list of object dicts."""
    with open(path, encoding="utf-8") as fh:
        docs = parse_yaml(fh.read())
    return [d for d in docs if isinstance(d, dict) and "kind" in d]
