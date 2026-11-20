"""Digest-bound classes, provenance and selected-graph constraints."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import re
import time
from urllib.parse import unquote, urlsplit

from .model import (array, boolean, bounded_text, canonical, choice, digest, fail, fields, guarded,
                    integer, licence, loads, package_ref, safe_path, sha256, text,
                    unique, version)

PLATFORMS = ("web", "server", "ios", "macos", "tvos", "android", "windows")
FOUNDATION_FIELDS = "platforms toolchains classes implements upstream compatibility maintenance"


CLASS_FORMAT = 2
CATEGORY = re.compile(r"[a-z0-9-]+(?:/[a-z0-9-]+)*")


def validate_class_reference(value: object) -> dict:
    """A class name, version and digest; a class version is MAJOR.MINOR.PATCH, never a preview."""
    ref = package_ref(value)
    version(ref["version"], "class.version")
    return ref


def category(value: object, path: str) -> str:
    """A category path: lower-case segments of letters, digits and hyphens, joined by `/`."""
    if type(value) is not str or len(value) > 256 or not CATEGORY.fullmatch(value):
        fail("invalid-category", path)
    return value


@guarded
def validate_categories(value: object, class_categories=()) -> list[dict]:
    """classes/categories.json: unique ids, each parent the id less its last segment (null at the top) and present, and each
    given class category present."""
    document = fields(value, "format categories", "categories")
    if type(document["format"]) is not int or document["format"] != 1:
        fail("invalid-format", "categories")
    entries = array(document["categories"], "categories.categories")
    for entry in entries:
        fields(entry, "id title parent", "categories.categories")
        category(entry["id"], "categories.id")
        bounded_text(entry["title"], "categories.title")
        expected = entry["id"].rpartition("/")[0] or None
        if entry["parent"] != expected:
            fail("category-parent", entry["id"])
    unique([entry["id"] for entry in entries], "categories.id")
    parents = {entry["id"]: entry["parent"] for entry in entries}
    for entry in entries:
        seen, current = set(), entry["id"]
        while current is not None:
            if current in seen:
                fail("category-cycle", entry["id"])
            seen.add(current)
            if current not in parents:
                fail("category-unknown", current)
            current = parents[current]
    for item in class_categories:
        if item not in parents:
            fail("category-unknown", item)
    return entries


def _strings(value, path, nonempty=False):
    items = array(value, path, nonempty)
    for item in items:
        text(item, path)
    unique(items, path)
    return items


def _inventory(value, path):
    items = array(value, path, True)
    for item in items:
        fields(item, "path digest", path)
        safe_path(item["path"], path)
        sha256(item["digest"], path)
    unique([item["path"] for item in items], path)
    return items


def _command(argv, inventory, tools):
    for arg in array(argv, "class.argv", True):
        text(arg, "class.argv")
    if argv[0].startswith("./"):
        if argv[0][2:] not in inventory:
            fail("class-command-inventory", argv[0])
    elif argv[0] not in tools or len(argv) < 2 or argv[1] not in inventory:
        fail("class-command-inventory", "class.argv")


@guarded
def validate_class_descriptor(value: object) -> dict:
    if type(value) is dict and value.get("format") == 1:
        fail("class-format-outdated", "class")
    c = fields(value, "format name version title summary category presentation provides requires settings inventory verification", "class")
    if type(c["format"]) is not int or c["format"] != CLASS_FORMAT:
        fail("invalid-format", "class")
    bounded_text(c["title"], "class.title")
    bounded_text(c["summary"], "class.summary", 500)
    category(c["category"], "class.category")
    choice(c["presentation"], ("visual", "none"), "class.presentation")
    validate_class_reference({"name": c["name"], "version": c["version"], "digest": digest(canonical(c))})
    inventory = {item["path"] for item in _inventory(c["inventory"], "class.inventory")}
    for key in ("provides", "requires"):
        ports = array(c[key], "class." + key)
        for port in ports:
            fields(port, "type version path modules" if key == "provides" else "type version", "class." + key)
            text(port["type"], "class.type")
            version(port["version"], "class.version")
            if key == "provides":
                if safe_path(port["path"]) not in inventory:
                    fail("class-interface-inventory", port["path"])
                if type(port["modules"]) is not dict or not port["modules"]:
                    fail("class-modules", "class.provides")
                for platform, paths in port["modules"].items():
                    choice(platform, PLATFORMS, "class.platform")
                    for path in _strings(paths, "class.modules", True):
                        safe_path(path, "class.modules")
        unique([(p["type"], p["version"]) for p in ports], "class." + key)
    settings = fields(c["settings"], "type properties required additionalProperties", "class.settings")
    if settings["type"] != "object" or settings["additionalProperties"] is not False or type(settings["properties"]) is not dict:
        fail("class-settings", "class.settings")
    from .recipe import GRAMMARS
    patterns = {"^" + pattern + "$" for pattern in GRAMMARS.values()}
    for key, prop in settings["properties"].items():
        text(key, "class.settings")
        fields(prop, "type", "class.settings.property", "pattern")
        choice(prop["type"], ("string", "boolean", "integer"), "class.settings.type")
        if prop["type"] == "string":
            if prop.get("pattern") not in patterns:
                fail("class-setting-pattern", key)
        elif "pattern" in prop:
            fail("class-setting-pattern", key)
    required = _strings(settings["required"], "class.settings.required")
    if not set(required) <= settings["properties"].keys():
        fail("class-settings", "class.settings.required")
    for suite in array(c["verification"], "class.verification", True):
        fields(suite, "id root argv cwd prepare tools fixtures locks network timeoutSeconds expectedExit scope requirements", "class.verification")
        if not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", text(suite["id"], "class.suite.id")):
            fail("class-suite-id", "class.verification")
        if suite["root"] != "package" or suite["scope"] != "required-local" or suite["requirements"] != []:
            fail("class-suite-scope", "class.verification")
        if suite["cwd"] != ".":
            fail("class-suite-cwd", "class.verification")
        if type(suite["tools"]) is not dict:
            fail("expected-object", "class.tools")
        for tool, pin in suite["tools"].items():
            if not re.fullmatch(r"[A-Za-z0-9_-]+", tool) or type(pin) is not str or not re.fullmatch(r"(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){0,2}", pin):
                fail("invalid-tool-version", "class.tools")
        _command(suite["argv"], inventory, suite["tools"])
        for prep in array(suite["prepare"], "class.prepare"):
            fields(prep, "argv cwd network", "class.prepare")
            if prep["cwd"] != ".":
                fail("class-suite-cwd", "class.prepare")
            _command(prep["argv"], inventory, suite["tools"])
            boolean(prep["network"], "class.prepare.network")
        for key in ("fixtures", "locks"):
            for path in _strings(suite[key], "class." + key, key == "fixtures"):
                if path not in inventory:
                    fail("class-suite-inventory", path)
        boolean(suite["network"], "class.network")
        if not 1 <= integer(suite["timeoutSeconds"], "class.timeoutSeconds") <= 900 or type(suite["expectedExit"]) is not int or suite["expectedExit"] != 0:
            fail("class-suite-limit", "class.verification")
    unique([s["id"] for s in c["verification"]], "class.verification")
    return c


def _bounds(expression):
    text(expression, "compatibility.range")
    terms = expression.split(" ")
    lower, upper = (0, 0, 0), None
    for term in terms:
        match = re.fullmatch(r"(>=|<=|=|>|<)((?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*))", term)
        if match is None:
            fail("invalid-version-range", expression)
        op, raw = match.groups()
        v = tuple(map(int, raw.split(".")))
        successor = (v[0], v[1], v[2] + 1)
        if op in (">=", ">", "="):
            lower = max(lower, successor if op == ">" else v)
        if op in ("<=", "<", "="):
            bound = v if op == "<" else successor
            upper = bound if upper is None else min(upper, bound)
    if upper is not None and lower >= upper:
        fail("empty-version-range", expression)
    return lower, upper


def _url(value, path, *, mail=False):
    from .model import execution_url
    if mail and type(value) is str and re.fullmatch(r"mailto:[^\s@]+@[^\s@]+", value):
        return
    execution_url(value, path, ("https",))


# A package URL by spec section 6a of the catalogue format paper, the rule the catalogue shares; both pass
# tests/fixtures/purl-cases.json. pkg:type/namespace/name@version?qualifiers#subpath, each part percent-decoded.
PURL_NAMESPACE = {"maven": 1, "golang": 1, "github": 1, "bitbucket": 1, "composer": 1, "swift": 2}
PURL_NO_NAMESPACE = {"cargo", "gem", "pypi", "nuget", "hex", "pub", "cocoapods", "hackage", "conda"}
PURL_FORBIDDEN = {"Cc", "Cf", "Zs", "Zl", "Zp", "Co", "Cs"}


def _decode(raw: str) -> str | None:
    """Strict percent-decoding to UTF-8, then no control, format, separator, private-use or surrogate character."""
    import unicodedata
    if re.search(r"%(?![0-9A-Fa-f]{2})", raw):
        return None
    try:
        value = unquote(raw, errors="strict")
    except UnicodeDecodeError:
        return None
    return None if any(unicodedata.category(c) in PURL_FORBIDDEN for c in value) else value


def parse_purl(value) -> dict | None:
    """{type, namespace, name, version, qualifiers (sorted), subpath} of a package URL, or None when it is refused."""
    if type(value) is not str or len(value) > 1000 or not re.fullmatch(r"[\x21-\x7e]+", value) or not value.startswith("pkg:"):
        return None
    rest, subpath, qualifiers = value[4:], None, None
    if "#" in rest:
        rest, subpath = rest.split("#", 1)
    if "?" in rest:
        rest, qualifiers = rest.split("?", 1)
    if "/" not in rest:
        return None
    kind, path = rest.split("/", 1)
    if not re.fullmatch(r"[a-z][a-z0-9.+-]*", kind):
        return None
    version = None
    at = path.rfind("@")
    if at > path.rfind("/"):
        path, raw = path[:at], path[at + 1:]
        if raw == "" or (version := _decode(raw)) is None:
            return None
    raws = path.split("/")
    if any(item == "" for item in raws):
        return None
    segments = [_decode(item) for item in raws]
    if any(item is None for item in segments):
        return None
    name, namespace = segments[-1], segments[:-1]
    if name == "" or name.startswith("@"):
        return None
    if kind in PURL_NO_NAMESPACE and namespace or len(namespace) < PURL_NAMESPACE.get(kind, 0):
        return None
    if kind == "swift" and "." not in namespace[0]:
        return None
    if kind == "npm" and namespace and (len(namespace) > 1 or not namespace[0].startswith("@") or len(namespace[0]) < 2):
        return None
    pairs = {}
    if qualifiers is not None:
        if qualifiers == "":
            return None
        for pair in qualifiers.split("&"):
            if "=" not in pair:
                return None
            key, raw = pair.split("=", 1)
            if not re.fullmatch(r"[a-z][a-z0-9._-]*", key) or key in pairs or raw == "":
                return None
            decoded = _decode(raw)
            if not decoded:
                return None
            pairs[key] = decoded
    parts = []
    if subpath is not None:
        if subpath == "":
            return None
        for raw in subpath.split("/"):
            segment = _decode(raw)
            if segment in (None, "", ".", ".."):
                return None
            parts.append(segment)
    return {"type": kind, "namespace": namespace, "name": name, "version": version,
            "qualifiers": dict(sorted(pairs.items())), "subpath": parts}


def _purl(value, path, expected_version=None):
    parsed = parse_purl(text(value, path))
    if parsed is None:
        fail("invalid-purl", path)
    if parsed["version"] != expected_version:
        fail("upstream-purl" if expected_version is not None else "dependency-name", path)


@guarded
def validate_foundations(manifest: dict) -> None:
    platforms = _strings(manifest["platforms"], "platforms", True)
    for platform in platforms:
        choice(platform, PLATFORMS, "platforms")
    from .toolchains import validate_toolchains
    validate_toolchains(manifest)
    identities = []
    refs = []
    for item in array(manifest["classes"], "classes"):
        fields(item, "reference descriptor", "classes")
        ref = validate_class_reference(item["reference"])
        descriptor = validate_class_descriptor(item["descriptor"])
        if (ref["name"], ref["version"], ref["digest"]) != (descriptor["name"], descriptor["version"], digest(canonical(descriptor))):
            fail("class-digest", ref["name"])
        identities.append((ref["name"], ref["version"]))
        refs.append(ref)
    unique(identities, "classes")
    implementations = array(manifest["implements"], "implements", manifest["kind"] == "component")
    for ref in implementations:
        validate_class_reference(ref)
        if ref not in refs:
            fail("class-unavailable", ref["name"])
    unique([canonical(ref) for ref in implementations], "implements")
    files = {item["path"] for item in manifest["files"]}
    for item in manifest["classes"]:
        for entry in item["descriptor"]["inventory"]:
            if entry["path"] not in files:
                fail("class-file-missing", entry["path"])
    for upstream in array(manifest["upstream"], "upstream"):
        fields(upstream, "name version revision repository purl licence notices delivery", "upstream")
        for key in ("name", "version", "purl"):
            text(upstream[key], "upstream." + key)
        if upstream["revision"] is not None:
            text(upstream["revision"], "upstream.revision")
        _purl(upstream["purl"], "upstream.purl", upstream["version"])
        _url(upstream["repository"], "upstream.repository")
        licence(upstream["licence"], "upstream.licence")
        for path in _strings(upstream["notices"], "upstream.notices", True):
            if safe_path(path) not in files:
                fail("upstream-notice-missing", path)
        delivery = upstream["delivery"]
        if type(delivery) is not dict:
            fail("expected-object", "upstream.delivery")
        if upstream["revision"] is None and not (delivery.get("manager") == "gradle" or "gradleWrapper" in delivery):
            fail("upstream-source-revision", upstream["name"])
        if delivery.get("kind") == "bundled":
            fields(delivery, "kind files", "upstream.delivery", "gradleWrapper")
            for entry in _inventory(delivery["files"], "upstream.delivery.files"):
                if entry["path"] not in files:
                    fail("upstream-source-missing", entry["path"])
        from .provenance import validate_delivery
        validate_delivery(upstream, files)
    wrappers = {item["delivery"]["gradleWrapper"]["jar"] for item in manifest["upstream"] if "gradleWrapper" in item["delivery"]}
    for path in files:
        if path.rsplit("/", 1)[-1] == "gradle-wrapper.jar" and path not in wrappers:
            fail("upstream-wrapper-unattributed", path)
    unique([item["purl"] for item in manifest["upstream"]], "upstream")
    compat = fields(manifest["compatibility"], "runtimes frameworks dependencies styles", "compatibility")
    for key in ("runtimes", "frameworks"):
        if type(compat[key]) is not dict:
            fail("expected-object", "compatibility." + key)
        for identifier, expression in compat[key].items():
            text(identifier, "compatibility." + key)
            if key == "frameworks":
                fields(expression, "name range", "compatibility.frameworks")
                text(expression["name"], "compatibility.frameworks.name")
                _bounds(expression["range"])
            else:
                _bounds(expression)
    for dep in array(compat["dependencies"], "compatibility.dependencies"):
        fields(dep, "name version isolation", "compatibility.dependencies")
        _purl(dep["name"], "compatibility.dependencies.name")
        if (type(dep["version"]) is not str or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", dep["version"])
                or dep["version"].lower().startswith("latest.") or dep["version"].upper() in ("LATEST", "RELEASE")
                or dep["version"].upper().endswith("-SNAPSHOT")):
            fail("invalid-dependency-version", "compatibility.dependencies")
        choice(dep["isolation"], ("shared", "isolated"), "compatibility.dependencies")
    unique([d["name"] for d in compat["dependencies"]], "compatibility.dependencies")
    styles = fields(compat["styles"], "scope namespaces conflicts", "compatibility.styles")
    choice(styles["scope"], ("none", "scoped", "global"), "compatibility.styles.scope")
    _strings(styles["namespaces"], "styles.namespaces", styles["scope"] != "none")
    _strings(styles["conflicts"], "styles.conflicts")
    if styles["scope"] == "none" and (styles["namespaces"] or styles["conflicts"]):
        fail("stylesheet-scope", "compatibility.styles")
    maintenance = fields(manifest["maintenance"], "owners contact repository updates", "maintenance")
    _strings(maintenance["owners"], "maintenance.owners", True)
    _url(maintenance["contact"], "maintenance.contact", mail=True)
    _url(maintenance["repository"], "maintenance.repository")
    updates = fields(maintenance["updates"], "source strategy", "maintenance.updates")
    _url(updates["source"], "maintenance.updates.source")
    choice(updates["strategy"], ("manual", "release"), "maintenance.updates.strategy")


@guarded
def validate_package_foundations(manifest: dict, payloads: dict[str, bytes]) -> dict[str, dict]:
    validate_foundations(manifest)
    result = {}
    bound = {}
    for item in manifest["classes"]:
        descriptor = item["descriptor"]
        for entry in descriptor["inventory"]:
            path = entry["path"]
            if path not in payloads or digest(payloads[path]) != entry["digest"]:
                fail("class-file-digest", path)
            if path in bound and bound[path] != entry["digest"]:
                fail("class-file-conflict", path)
            bound[path] = entry["digest"]
        result[item["reference"]["digest"]] = descriptor
    for upstream in manifest["upstream"]:
        for path in upstream["notices"]:
            if not payloads[path].strip():
                fail("upstream-notice-empty", path)
        delivery = upstream["delivery"]
        if delivery["kind"] == "bundled":
            for entry in delivery["files"]:
                if digest(payloads[entry["path"]]) != entry["digest"]:
                    fail("upstream-file-digest", entry["path"])
        from .provenance import validate_delivery_bytes
        validate_delivery_bytes(upstream, payloads)
    from .images import validate_images
    validate_images(manifest, payloads)
    if manifest["kind"] == "recipe" and "recipe.json" in payloads:
        from .recipe import validate_recipe_document
        recipe = validate_recipe_document(loads(payloads["recipe.json"], "recipe.json"))
        for slot in array(recipe["components"], "recipe.components"):
            class_descriptor(manifest, payloads, slot["class"])
    return result


def class_descriptor(manifest: dict, payloads: dict[str, bytes], reference: dict) -> dict:
    validate_class_reference(reference)
    for item in manifest["classes"]:
        if item["reference"] == reference:
            descriptor = validate_class_descriptor(item["descriptor"])
            if digest(canonical(descriptor)) != reference["digest"]:
                fail("class-digest", reference["name"])
            for entry in descriptor["inventory"]:
                if entry["path"] not in payloads or digest(payloads[entry["path"]]) != entry["digest"]:
                    fail("class-file-digest", entry["path"])
            return descriptor
    fail("class-unavailable", reference["name"])


def module_sources(manifest: dict, root: Path, *, slot: str | None = None) -> dict[str, str]:
    from .application import install_path
    if slot is not None:
        from .model import slot_condition
        slot_condition(slot, "module.slot")
    return {(install_path(item["destination"], manifest["identity"]["name"], slot, manifest["kind"] == "recipe") if slot is not None else item["destination"]):
            str(Path(root) / item["source"]) for item in manifest["artefacts"]}


def source_for_module(manifest: dict, root: Path, installed_path: str, *, slot: str | None = None) -> Path:
    safe_path(installed_path, "module")
    sources = module_sources(manifest, root, slot=slot)
    if installed_path not in sources:
        fail("module-unavailable", installed_path)
    return Path(sources[installed_path])


def selected_targets(recipe_manifest: dict, answers: dict) -> list[str]:
    if "targets" not in answers:
        return list(recipe_manifest["platforms"])
    targets = _strings(answers["targets"], "answers.targets", True)
    for target in targets:
        choice(target, PLATFORMS, "answers.targets")
        if target not in recipe_manifest["platforms"]:
            fail("unsupported-platform", target)
    return sorted(set(targets) | ({"server"} if "server" in recipe_manifest["platforms"] else set()))


@guarded
def validate_graph(manifests: list[dict], targets: list[str] | None = None) -> None:
    identities, pins, ranges, frameworks = {}, {}, {}, {}
    styles = []
    for manifest in manifests:
        validate_foundations(manifest)
        if targets is not None and not set(targets).intersection(manifest["platforms"]):
            fail("unsupported-platform", manifest["identity"]["name"])
        for item in manifest["classes"]:
            ref = item["reference"]
            key = (ref["name"], ref["version"])
            if key in identities and identities[key] != ref["digest"]:
                fail("class-identity-conflict", ref["name"])
            identities[key] = ref["digest"]
        compat = manifest["compatibility"]
        for kind in ("runtimes", "frameworks"):
            for name, expression in compat[kind].items():
                key = (kind, name)
                if kind == "frameworks":
                    if name in frameworks and frameworks[name] != expression["name"]:
                        fail("framework-conflict", name)
                    frameworks[name] = expression["name"]
                    expression = expression["range"]
                lower, upper = _bounds(expression)
                old_lower, old_upper = ranges.get(key, ((0, 0, 0), None))
                lower = max(lower, old_lower)
                upper = old_upper if upper is None else upper if old_upper is None else min(upper, old_upper)
                if upper is not None and lower >= upper:
                    fail("compatibility-range-conflict", kind + "." + name)
                ranges[key] = lower, upper
        for dep in compat["dependencies"]:
            if dep["isolation"] == "shared":
                if dep["name"] in pins and pins[dep["name"]] != dep["version"]:
                    fail("shared-dependency-conflict", dep["name"])
                pins[dep["name"]] = dep["version"]
        current = compat["styles"]
        for other in styles:
            overlap = set(current["namespaces"]) & set(other["namespaces"])
            if ((overlap and "global" in (current["scope"], other["scope"]))
                    or set(current["conflicts"]) & set(other["namespaces"])
                    or set(other["conflicts"]) & set(current["namespaces"])):
                fail("stylesheet-conflict", manifest["identity"]["name"])
        styles.append(current)
    if targets is not None:
        from .toolchains import merge_toolchains
        merge_toolchains(manifests, targets)


def class_suites(manifest: dict) -> list[dict]:
    result = []
    for ref in manifest["implements"]:
        item = next(item for item in manifest["classes"] if item["reference"] == ref)
        descriptor = item["descriptor"]
        for suite in descriptor["verification"]:
            result.append({**suite, "id": "class:" + ref["digest"] + ":" + suite["id"],
                           "class": ref, "classInventory": descriptor["inventory"]})
    return result


def class_result_evidence(suite: dict, source: Path, started_at: int | None = None, completed_at: int | None = None) -> dict:
    """The constant-size record of one class suite: its class and the digest of the inventory it ran.

    The inventory bytes stay in the package archive, which the report binds through its package digests; the staged bytes
    the suite ran are checked against that inventory here."""
    for item in suite["classInventory"]:
        if digest((Path(source) / item["path"]).read_bytes()) != item["digest"]:
            fail("class-file-digest", item["path"])
    completed = int(time.time()) if completed_at is None else completed_at
    return {"reference": suite["class"], "inventoryDigest": digest(canonical(suite["classInventory"])),
            "startedAt": completed if started_at is None else started_at, "completedAt": completed}


def validate_class_result_evidence(result: dict, suite: dict) -> None:
    if "class" not in suite:
        if "classEvidence" in result:
            fail("class-evidence-unexpected", "report.suites")
        return
    evidence = fields(result.get("classEvidence"), "reference inventoryDigest startedAt completedAt", "classEvidence")
    if evidence["reference"] != suite["class"]:
        fail("class-evidence-binding", "classEvidence")
    if sha256(evidence["inventoryDigest"], "classEvidence.inventoryDigest") != digest(canonical(suite["classInventory"])):
        fail("class-evidence-inventory", "classEvidence")
    if not 0 <= integer(evidence["startedAt"], "classEvidence.startedAt") <= integer(evidence["completedAt"], "classEvidence.completedAt"):
        fail("class-evidence-time", "classEvidence")


@guarded
def maintenance_facts(ref: dict, store: Path, policy: Path) -> dict:
    from .bundle import read_package
    from .trust import REVIEW, verify, verify_package
    manifest, _ = read_package(ref, store)
    verify_package(ref, store, policy)
    statement, _ = verify((store / "statements" / ref["digest"] / "guardian.dsse.json").read_bytes(), "guardian", policy, REVIEW)
    report_digest = statement["predicate"]["inputAttestations"][0]["digest"]["sha256"]
    report = loads((store / "reports" / (report_digest + ".json")).read_bytes(), "report")
    times = [item["classEvidence"]["completedAt"] for item in report["suites"] if "classEvidence" in item]
    completed = report["execution"]["completedAt"] if "execution" in report else max(times) if times else None
    return {"package": ref, "maintenance": manifest["maintenance"], "platforms": manifest["platforms"],
            "lastSuccessfulVerification": datetime.fromtimestamp(completed, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if completed is not None else None,
            "reportDigest": report_digest, "reviewSignedAt": statement["predicate"]["timeVerified"]}
