from functools import lru_cache
from pathlib import Path

import yaml

from app.core.config import get_settings
from app.schemas.rule import DetectionRule


def resolve_rules_path() -> Path:
    configured = get_settings().rules_path
    if configured:
        return Path(configured).expanduser().resolve()

    candidates = (
        Path.cwd() / "rules",
        Path.cwd().parent / "rules",
        Path(__file__).resolve().parents[3] / "rules",
        Path("/app/rules"),
    )
    return next((path for path in candidates if path.is_dir()), candidates[0])


@lru_cache(maxsize=8)
def _load_rules(path_string: str) -> tuple[DetectionRule, ...]:
    path = Path(path_string)
    if not path.is_dir():
        raise RuntimeError(f"rules directory does not exist: {path}")

    rules: list[DetectionRule] = []
    for rule_file in sorted(path.glob("*.yaml")):
        with rule_file.open(encoding="utf-8") as stream:
            document = yaml.safe_load(stream)
        documents = document if isinstance(document, list) else [document]
        for item in documents:
            rules.append(DetectionRule.model_validate(item))

    if not rules:
        raise RuntimeError(f"no YAML rules found in: {path}")
    identifiers = [rule.id for rule in rules]
    if len(identifiers) != len(set(identifiers)):
        raise RuntimeError("rule IDs must be unique")
    return tuple(rules)


def load_rules() -> tuple[DetectionRule, ...]:
    return _load_rules(str(resolve_rules_path()))
