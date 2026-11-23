"""The companion deploy-unit.toml against the dotmac.deploy_unit/1 contract.

Design rev3 sections 2.2, 2.7 and 2.8.

Static checks on the committed descriptor. They read TOML as text: no database,
no network, no import of the application. The descriptor's Foundation spec
(deploy/companion/product.toml) is the I3 deliverable and does not exist yet, so
the spec-dependent checks hold the pending state and switch on when it lands.

The contract checker below is written against the design document, not against
Control a18 (not yet built); it is deliberately small and refuses by name.
"""

from __future__ import annotations

import ast
import copy
import re
import tomllib
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
COMPANION = ROOT / "deploy" / "companion"
UNIT_PATH = COMPANION / "deploy-unit.toml"
SPEC_PATH = COMPANION / "product.toml"

SCHEMA = "dotmac.deploy_unit/1"
NAMESPACE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
EXPECTED_NAMESPACE = "erp-integrator"
PARAM_TYPES = frozenset(
    {
        "string",
        "int",
        "bool",
        "enum",
        "hostname",
        "cidr",
        "url",
        "duration_seconds",
        "path",
        "image_digest",
        "image_repository",
    }
)
WRITERS = frozenset({"generated", "operator", "ceremony", "integration"})
ROTATIONS = frozenset({"copy_only", "manual"})
HEALTH_GATES = frozenset(
    {
        "migrate",
        "grant_mirror",
        "heads",
        "live",
        "ready",
        "composition_equals_pins",
        "runtime_policy_digest",
        "census_zero_enabled",
    }
)
BINDING_STATES = frozenset({"pre_staged", "active"})
MATERIAL_NAME = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")
# Control is default-deny: legacy_env_file_allowed_targets is empty until Michael
# enables a target (ERP v2 is the only intended one), and a descriptor under
# deploy/companion/ is always refused.
LEGACY_ALLOWED_DEFAULT = frozenset({"dotmac-erp-v2"})
REFUSED_BY_DEFAULT = frozenset({"dotmac-sub", "dotmac-integrator-companion"})
SECRET_NAME_HINT = re.compile(r"(SECRET|TOKEN|PASSWORD|KEY|DATABASE_URL|_DSN)$")
# Values a params file could never carry: secret-shaped content and estate addresses.
SECRET_SHAPED = re.compile(
    r"(-----BEGIN|bao://|hvs\.|s\.[A-Za-z0-9]{20,}|[A-Za-z][A-Za-z0-9+.-]*://[^/\s:@]+:[^@\s]+@)"
)
IPV4_LITERAL = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")


def _load(path: Path) -> dict[str, Any]:
    return tomllib.loads(path.read_text(encoding="utf-8"))


def _walk_strings(node: object) -> list[str]:
    if isinstance(node, str):
        return [node]
    if isinstance(node, dict):
        return [s for value in node.values() for s in _walk_strings(value)]
    if isinstance(node, list):
        return [s for value in node for s in _walk_strings(value)]
    return []


def _bad_value(value: str) -> bool:
    """Values Foundation's env parser would alter (F1), plus secret shapes."""

    if "\n" in value or "\r" in value or "\x00" in value:
        return True
    if value != value.strip():
        return True
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return True
    return bool(SECRET_SHAPED.search(value))


def check_unit(
    unit: dict[str, Any],
    spec: dict[str, Any],
    *,
    companion_path: bool = False,
) -> list[str]:
    """Return refusal codes for a descriptor; empty means it satisfies the contract."""

    problems: list[str] = []
    if unit.get("schema") != SCHEMA:
        problems.append("schema")
    product = unit.get("product", "")
    if not product:
        problems.append("product")
    namespace = unit.get("secrets_namespace")
    if not isinstance(namespace, str) or NAMESPACE.fullmatch(namespace) is None:
        problems.append("secrets-namespace")
    if unit.get("spec") != "deploy/companion/product.toml":
        problems.append("spec-path")
    if "spec_digest" in unit:
        # Digests are bound by the release record, never stored beside a sentinel image.
        problems.append("spec-digest-in-descriptor")

    # [image]: absent means transfer; pull is never self-declared (section 2.7).
    source = unit.get("image", {}).get("source", "transfer")
    if source not in {"transfer", "pull"}:
        problems.append("image-source")
    if source == "pull":
        problems.append("image-pull-requires-allowlist")

    materials = set(spec.get("runtime_materials", {}).get("names", []))
    params = unit.get("params", {})
    seen_materials: dict[str, str] = {}
    for name, param in params.items():
        if param.get("type") not in PARAM_TYPES:
            problems.append(f"param-type:{name}")
        material = param.get("material")
        if material is not None:
            if not MATERIAL_NAME.match(material):
                problems.append(f"param-material-name:{name}")
            if materials and material not in materials:
                problems.append(f"param-material-unknown:{name}")
            if material in seen_materials:
                problems.append(f"param-material-duplicate:{name}")
            seen_materials[material] = name
            if SECRET_NAME_HINT.search(material):
                problems.append(f"param-material-secret-class:{name}")
        for key in ("default", "pattern"):
            value = param.get(key)
            if isinstance(value, str) and key == "default" and _bad_value(value):
                problems.append(f"param-value:{name}")
        if param.get("type") == "duration_seconds" and "max" not in param:
            problems.append(f"param-unbounded:{name}")

    bindings = unit.get("bindings", [])
    binding_names: set[str] = set()
    active_binding_names: set[str] = set()
    for binding in bindings:
        name = binding.get("name", "")
        if not MATERIAL_NAME.match(name):
            problems.append(f"binding-name:{name}")
        if name in binding_names:
            problems.append(f"binding-duplicate:{name}")
        binding_names.add(name)
        if binding.get("state", "active") not in BINDING_STATES:
            problems.append(f"binding-state:{name}")
        elif binding.get("state", "active") == "active":
            active_binding_names.add(name)
        if binding.get("writer") not in WRITERS:
            problems.append(f"binding-writer:{name}")
        if binding.get("rotation") not in ROTATIONS:
            problems.append(f"binding-rotation:{name}")
        if not binding.get("roles") or not binding.get("kind"):
            problems.append(f"binding-incomplete:{name}")
        if "single_use" not in binding or not isinstance(binding["single_use"], bool):
            problems.append(f"binding-single-use:{name}")
        # A binding is a pointer: it never carries a value or a reference literal.
        if {"value", "secret_ref", "default"} & binding.keys():
            problems.append(f"binding-carries-value:{name}")
        if name in seen_materials:
            problems.append(f"binding-collides-with-param:{name}")

    legacy = unit.get("legacy_env_file")
    if legacy is not None:
        if product not in LEGACY_ALLOWED_DEFAULT or companion_path:
            problems.append("legacy-refused")
        names = legacy.get("names", [])
        if not names or len(set(names)) != len(names):
            problems.append("legacy-names")
        for name in names:
            if not MATERIAL_NAME.match(name):
                problems.append(f"legacy-name-shape:{name}")
            if not SECRET_NAME_HINT.search(name):
                problems.append(f"legacy-nonsecret-name:{name}")
            if name in seen_materials or name == "APP_IMAGE":
                problems.append(f"legacy-collides-with-param:{name}")
            if name in active_binding_names:
                problems.append(f"legacy-collides-with-binding:{name}")
        if set(legacy) - {"names", "path_param"}:
            problems.append("legacy-extra-keys")
        path_param = params.get(legacy.get("path_param", ""), {})
        if (
            path_param.get("type") != "path"
            or "material" in path_param
            or "default" in path_param
        ):
            problems.append("legacy-path-param")

    for companion in unit.get("companions", []):
        if companion.get("order") != "after_primary_ready":
            problems.append("companion-order")
        if not isinstance(companion.get("required_at_switch"), bool):
            problems.append("companion-required-at-switch")
        if companion.get("host") not in {"same", "param"}:
            problems.append("companion-host")
        if not companion.get("product") or not companion.get("descriptor"):
            problems.append("companion-incomplete")

    for hold in unit.get("hold_points", []):
        timeout = params.get(hold.get("timeout_param", ""), {})
        if (
            timeout.get("type") != "duration_seconds"
            or timeout.get("max", 10**9) > 3600
        ):
            problems.append(f"hold-point-unbounded:{hold.get('name')}")

    for name, param in params.items():
        if ("min" in param or "max" in param) and param.get("type") not in {
            "int",
            "duration_seconds",
        }:
            problems.append(f"param-bounds-type:{name}")
    for job in unit.get("jobs", []):
        if job.get("trigger") != "operator":
            problems.append(f"job-trigger:{job.get('name')}")
        known = {p["material"] for p in params.values() if "material" in p}
        for material in job.get("materials", []):
            if material not in known | binding_names:
                problems.append(f"job-material-unknown:{material}")
        runbook = job.get("runbook", "")
        if runbook.startswith("/") or ".." in runbook.split("/"):
            problems.append(f"job-runbook-path:{job.get('name')}")
    for hold in unit.get("hold_points", []):
        if hold.get("member") not in {"primary", "companion"}:
            problems.append("hold-member")
        if hold.get("before") not in {"migrate", "start", "switch"}:
            problems.append("hold-before")
        if hold.get("on_timeout") != "abandon_member_record_deviation":
            problems.append("hold-on-timeout")
        if hold.get("released_by") != "operator":
            problems.append("hold-released-by")
    health = unit.get("health")
    if health is not None:
        gates = health.get("gates", [])
        if set(health) != {"gates"} or len(set(gates)) != len(gates):
            problems.append("health-shape")
        if not set(gates) <= HEALTH_GATES:
            problems.append("health-gate-unknown")
    for text in _walk_strings(unit):
        if SECRET_SHAPED.search(text):
            problems.append("secret-shaped-string")
        if IPV4_LITERAL.search(text):
            problems.append("ip-literal")
    return problems


def _unit() -> dict[str, Any]:
    return _load(UNIT_PATH)


def _spec() -> dict[str, Any]:
    """The companion spec, or an empty document while it is pending (I3)."""

    return _load(SPEC_PATH) if SPEC_PATH.is_file() else {}


def _check(unit: dict[str, Any]) -> list[str]:
    return check_unit(unit, _spec(), companion_path=True)


def test_descriptor_satisfies_the_contract() -> None:
    assert _check(_unit()) == []


def test_spec_is_the_companion_product_toml() -> None:
    unit = _unit()
    assert unit["spec"] == "deploy/companion/product.toml"
    assert unit["product"] == "dotmac-integrator-companion"
    # The generic spec is the I3 deliverable. Until it lands the descriptor is
    # inert; once it exists, its product and schema must agree with this file.
    if SPEC_PATH.is_file():
        spec = _spec()
        assert spec["schema"] in {
            "ProductDeploymentSpec.v3",
            "ProductDeploymentSpec.v4",
        }
        assert spec["product"] == unit["product"]
    stored = copy.deepcopy(unit)
    stored["spec_digest"] = "sha256:" + "1" * 64
    assert "spec-digest-in-descriptor" in _check(stored)
    moved = copy.deepcopy(unit)
    moved["spec"] = "deploy/product.toml"
    assert "spec-path" in _check(moved)


def test_image_source_default_transfer() -> None:
    unit = _unit()
    assert unit["image"]["source"] == "transfer"
    # An absent [image] table means transfer, not pull.
    absent = copy.deepcopy(unit)
    del absent["image"]
    assert _check(absent) == []
    # A descriptor cannot widen this by itself.
    pulled = copy.deepcopy(unit)
    pulled["image"]["source"] = "pull"
    assert "image-pull-requires-allowlist" in _check(pulled)
    other = copy.deepcopy(unit)
    other["image"]["source"] = "registry"
    assert "image-source" in _check(other)


def test_legacy_never_products() -> None:
    # Every descriptor under deploy/companion/ is refused by default by Control.
    unit = _unit()
    assert unit["product"] in REFUSED_BY_DEFAULT
    assert "legacy_env_file" not in unit
    refused = copy.deepcopy(unit)
    refused["legacy_env_file"] = {
        "names": ["JWT_SECRET"],
        "path_param": "legacy_env_path",
    }
    assert "legacy-refused" in _check(refused)
    # Renaming the product does not escape: the companion path itself is refused.
    renamed = copy.deepcopy(refused)
    renamed["product"] = "some-other-product"
    assert "legacy-refused" in _check(renamed)
    for path in COMPANION.rglob("*"):
        if path.is_file() and path.suffix == ".toml":
            text = path.read_text(encoding="utf-8")
            assert "legacy_env_file" not in text
            assert "path_param" not in text


def test_runtime_files_only_no_environment_file_anywhere() -> None:
    assert not [
        p
        for p in COMPANION.rglob("*")
        if p.name == ".env" or p.name.startswith(".env.")
    ]
    for path in COMPANION.rglob("*"):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        assert not re.search(r"^\s*env_file\s*[:=]", text, re.MULTILINE), path.name
        assert "--env-file" not in text, path.name


def test_descriptor_is_generic_not_app_or_resource_specific() -> None:
    lines = UNIT_PATH.read_text(encoding="utf-8").lower().splitlines()
    # The per-deployment secrets namespace is the one place an app name appears.
    text = "\n".join(x for x in lines if not x.startswith("secrets_namespace"))
    for word in ("erp", "traccar", "academy", "shadow", "dotmac_default"):
        assert word not in text, word


def test_bindings_are_pointers_never_values() -> None:
    unit = _unit()
    assert unit["bindings"]
    for binding in unit["bindings"]:
        assert {
            "name",
            "kind",
            "roles",
            "writer",
            "rotation",
            "single_use",
        } <= binding.keys()
        assert not {"value", "secret_ref", "default"} & binding.keys()
        assert binding.get("state", "active") == "active"
    leaky = copy.deepcopy(unit)
    leaky["bindings"][0]["secret_ref"] = "bao://production/companion/kv/api/x"
    assert "binding-carries-value:" + leaky["bindings"][0]["name"] in _check(leaky)


def test_one_role_per_credential_and_migrate_is_single_use() -> None:
    by_name = {b["name"]: b for b in _unit()["bindings"]}
    assert by_name["MIGRATION_DATABASE_URL"]["roles"] == ["migrate"]
    assert by_name["MIGRATION_DATABASE_URL"]["single_use"] is True
    assert by_name["BACKUP_DATABASE_URL"]["roles"] == ["backup"]
    for name in ("DATABASE_URL", "JWT_SECRET", "METRICS_TOKEN"):
        assert by_name[name]["roles"] == ["api"]
        assert by_name[name]["single_use"] is False


def test_params_and_bindings_do_not_share_a_name() -> None:
    unit = _unit()
    bound = {b["name"] for b in unit["bindings"]}
    materials = {p["material"] for p in unit["params"].values() if "material" in p}
    assert bound.isdisjoint(materials)
    collide = copy.deepcopy(unit)
    collide["bindings"][0]["name"] = "DEPLOYMENT_ID"
    assert "binding-collides-with-param:DEPLOYMENT_ID" in _check(collide)


def test_params_are_typed_and_refuse_unsafe_values() -> None:
    unit = _unit()
    assert {p["type"] for p in unit["params"].values()} <= PARAM_TYPES
    for value in (
        "a\nb",
        "nul\x00",
        " lead",
        "trail ",
        '"quoted"',
        "'quoted'",
        "bao://x/y",
        "-----BEGIN KEY",
    ):
        bad = copy.deepcopy(unit)
        bad["params"]["deployment_id"]["default"] = value
        assert "param-value:deployment_id" in _check(bad), repr(value)
    unknown = copy.deepcopy(unit)
    unknown["params"]["deployment_id"]["type"] = "secret"
    assert "param-type:deployment_id" in _check(unknown)
    secretish = copy.deepcopy(unit)
    secretish["params"]["deployment_id"]["material"] = "JWT_SECRET"
    assert "param-material-secret-class:deployment_id" in _check(secretish)


def test_safe_defaults_are_fixed_by_the_descriptor() -> None:
    params = _unit()["params"]
    # Zero tuples enabled at install.
    assert params["product_query_enabled"]["default"] is False
    # The kill switch is always reachable: fixed on.
    kill = params["operator_killswitch_routes_enabled"]
    assert kill["default"] is True and kill["choices"] == [True]
    # Mirror is the safe port mode.
    assert params["product_port_mode"]["default"] == "mirror"


def _settings_fields() -> set[str]:
    """Field names of `Settings`, read from source so nothing is imported."""

    tree = ast.parse(
        (ROOT / "src" / "dotmac_integrator" / "settings.py").read_text(encoding="utf-8")
    )
    fields: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == "Settings":
            for item in node.body:
                if isinstance(item, ast.AnnAssign) and isinstance(
                    item.target, ast.Name
                ):
                    fields.add(item.target.id)
    return fields


def test_param_and_binding_names_match_integrator_settings() -> None:
    fields = _settings_fields()
    assert "product_port_mode" in fields
    unit = _unit()
    for name, param in unit["params"].items():
        material = param.get("material")
        if material is not None:
            assert material.lower() in fields, name
    # The backup credential is read by the backup job, not by Settings.
    for binding in unit["bindings"]:
        if binding["name"] != "BACKUP_DATABASE_URL":
            assert binding["name"].lower() in fields, binding["name"]


def test_health_gates_cover_the_companion_order() -> None:
    gates = _unit()["health"]["gates"]
    assert gates == [
        "migrate",
        "grant_mirror",
        "heads",
        "live",
        "ready",
        "composition_equals_pins",
        "runtime_policy_digest",
        "census_zero_enabled",
    ]


def test_descriptor_holds_no_secret_shaped_value_or_host_address() -> None:
    for text in _walk_strings(_load(UNIT_PATH)):
        assert not SECRET_SHAPED.search(text)
        assert not IPV4_LITERAL.search(text)


def test_foundation_validate_accepts_the_companion_spec_when_present() -> None:
    # The spec is the I3 deliverable; the read-back switches on when it lands and
    # where a Foundation release that reads its schema is installed.
    if not SPEC_PATH.is_file():
        pytest.skip("deploy/companion/product.toml is pending (I3)")
    cli = pytest.importorskip("dotmac_deployment_foundation.cli")
    assert cli.main(["-f", str(SPEC_PATH), "validate"]) == 0


def test_secrets_namespace_matches_the_segment_grammar() -> None:
    unit = _unit()
    assert unit["secrets_namespace"] == EXPECTED_NAMESPACE
    assert NAMESPACE.fullmatch(unit["secrets_namespace"])
    for bad in ("", "Erp", "-x", "a/b", "a b", "x" * 65, "a\n", "staging/erp"):
        broken = copy.deepcopy(unit)
        broken["secrets_namespace"] = bad
        assert "secrets-namespace" in _check(broken), repr(bad)
    missing = copy.deepcopy(unit)
    del missing["secrets_namespace"]
    assert "secrets-namespace" in _check(missing)


def test_authored_openbao_config_uses_the_descriptor_namespace() -> None:
    # No app-authored OpenBao config exists under deploy/companion yet (I3), so this
    # holds vacuously until one lands; then every bao:// reference in it must
    # use the descriptor's namespace as its <product> segment.
    namespace = _unit()["secrets_namespace"]
    for path in sorted(ROOT.joinpath("deploy/companion").rglob("*")):
        if path.is_file() and "openbao" in path.parts:
            for match in re.finditer(r"bao://[^/\s]+/([^/\s]+)/", path.read_text()):
                assert match.group(1) == namespace, path.name
