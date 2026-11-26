"""Packaged dependency pins, native checksums and Gradle wrapper inventories."""

import base64
import re
from urllib.parse import unquote, urlsplit
from xml.etree import ElementTree

from .model import array, choice, digest, fail, fields, loads, safe_path, sha256, text, unique


def _file(record, files):
    fields(record, "path digest", "upstream.file")
    if safe_path(record["path"]) not in files:
        fail("upstream-lock-missing", record["path"])
    sha256(record["digest"], "upstream.file.digest")


def _artifacts(items):
    for item in array(items, "upstream.artifacts", True):
        fields(item, "name digest", "upstream.artifacts")
        if "/" in safe_path(item["name"]):
            fail("upstream-artifact-name", item["name"])
        sha256(item["digest"], "upstream.artifacts.digest")
    unique([item["name"] for item in items], "upstream.artifacts")


def _coordinate(upstream):
    path = unquote(urlsplit(upstream["purl"]).path)
    match = re.fullmatch(r"maven/([^/:@]+)/([^/:@]+)@(.+)", path)
    if match is None or match[2] != upstream["name"] or match[3] != upstream["version"]:
        fail("upstream-coordinate", upstream["purl"])
    return tuple(match.groups())


def validate_delivery(upstream: dict, files: set[str]) -> None:
    delivery = upstream["delivery"]
    if delivery["kind"] == "bundled":
        fields(delivery, "kind files", "upstream.delivery", "gradleWrapper")
        if "gradleWrapper" in delivery:
            wrapper = fields(delivery["gradleWrapper"], "jar properties distribution", "upstream.gradleWrapper")
            inventory = {item["path"] for item in delivery["files"]}
            for key in ("jar", "properties"):
                if safe_path(wrapper[key]) not in inventory:
                    fail("upstream-wrapper-inventory", wrapper[key])
            if not wrapper["jar"].endswith("gradle-wrapper.jar") or wrapper["jar"] == wrapper["properties"]:
                fail("upstream-wrapper-jar", "upstream.gradleWrapper")
            distribution = fields(wrapper["distribution"], "url digest", "upstream.distribution")
            from .model import execution_url
            parsed = execution_url(distribution["url"], "upstream.distribution.url", ("https",))
            expected = "gradle-" + upstream["version"]
            if parsed.query or parsed.fragment or parsed.path.rsplit("/", 1)[-1] not in (expected + "-bin.zip", expected + "-all.zip"):
                fail("upstream-distribution-version", distribution["url"])
            sha256(distribution["digest"], "upstream.distribution.digest")
        return
    manager = delivery.get("manager")
    choice(manager, ("npm", "gradle", "swift"), "upstream.delivery.manager")
    extras = {"npm": "packagePath integrity", "gradle": "verification configurations artifacts", "swift": ""}[manager]
    fields(delivery, "kind manager lock digest " + extras, "upstream.delivery")
    choice(delivery["kind"], ("build-time",), "upstream.delivery.kind")
    expected_type = {"npm": "npm", "gradle": "maven", "swift": "swift"}[manager]
    if urlsplit(upstream["purl"]).path.split("/", 1)[0] != expected_type:
        fail("unsupported-upstream-delivery", upstream["purl"])
    _file({"path": delivery["lock"], "digest": delivery["digest"]}, files)
    if manager == "npm":
        package_path = safe_path(delivery["packagePath"], "upstream.delivery.packagePath")
        segment = r"node_modules/(?:@[A-Za-z0-9._-]+/)?[A-Za-z0-9._-]+"
        name = unquote(urlsplit(upstream["purl"]).path[4:].rsplit("@", 1)[0])
        if (not re.fullmatch(segment + r"(?:/" + segment + r")*", package_path)
                or package_path.rsplit("node_modules/", 1)[-1] != upstream["name"] or name != upstream["name"]):
            fail("upstream-package-path", "upstream.delivery.packagePath")
        integrity = text(delivery["integrity"], "upstream.delivery.integrity")
        try:
            if not integrity.startswith("sha512-") or len(base64.b64decode(integrity[7:], validate=True)) != 64:
                fail("upstream-integrity", "upstream.delivery")
        except ValueError:
            fail("upstream-integrity", "upstream.delivery")
    elif manager == "swift":
        if type(upstream["revision"]) is not str or not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", upstream["revision"]):
            fail("upstream-source-revision", upstream["name"])
    else:
        _coordinate(upstream)
        _file(delivery["verification"], files)
        configurations = array(delivery["configurations"], "upstream.configurations", True)
        for value in configurations:
            if type(value) is not str or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]*", value):
                fail("upstream-configuration", "upstream.configurations")
        unique(configurations, "upstream.configurations")
        _artifacts(delivery["artifacts"])


def _bound_file(path, expected, payloads):
    if path not in payloads or digest(payloads[path]) != expected:
        fail("upstream-lock-digest", path)
    return payloads[path]


def _gradle_lock(raw):
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeError:
        fail("upstream-lock-format", "gradle")
    result = {}
    empty_seen = False
    for line in lines:
        if not line or line.startswith("#"):
            continue
        coordinate, separator, configurations = line.partition("=")
        if not separator:
            fail("upstream-lock-format", "gradle")
        if coordinate == "empty":
            if empty_seen:
                fail("upstream-lock-duplicate", "empty")
            empty_seen = True
            if configurations:
                for configuration in configurations.split(","):
                    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]*", configuration):
                        fail("upstream-lock-format", "gradle.empty")
            continue
        parts = coordinate.split(":")
        if len(parts) != 3 or any(not part or re.search(r"\s|[=,]", part) for part in parts):
            fail("upstream-lock-format", coordinate)
        names = configurations.split(",")
        unique(names, "upstream.lock.configurations")
        for configuration in names:
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]*", configuration):
                fail("upstream-lock-format", coordinate)
            key = (parts[0], parts[1], configuration)
            if key in result:
                fail("upstream-lock-duplicate", coordinate)
            result[key] = parts[2]
    if not result:
        fail("upstream-lock-format", "gradle")
    return result


def _gradle_checksums(raw, coordinate):
    if len(raw) > 1024 * 1024 or re.search(br"<!DOCTYPE|<!ENTITY", raw, re.I):
        fail("upstream-verification-format", "gradle")
    try:
        root = ElementTree.fromstring(raw)
    except ElementTree.ParseError:
        fail("upstream-verification-format", "gradle")
    ns = "{https://schema.gradle.org/dependency-verification}"
    if root.tag != ns + "verification-metadata":
        fail("upstream-verification-format", "gradle")
    found = [item for item in root.findall(ns + "components/" + ns + "component")
             if (item.get("group"), item.get("name"), item.get("version")) == coordinate]
    if len(found) != 1:
        fail("upstream-verification-coordinate", ":".join(coordinate))
    result = {}
    for artifact in found[0].findall(ns + "artifact"):
        name = artifact.get("name")
        if not name or name in result:
            fail("upstream-verification-artifact", "gradle")
        values = []
        for checksum in artifact.findall(ns + "sha256"):
            values.append(sha256(checksum.get("value"), "upstream.verification.sha256"))
            values.extend(sha256(child.get("value"), "upstream.verification.sha256") for child in checksum.findall(ns + "also-trust"))
        if not values:
            fail("upstream-verification-checksum", name)
        result[name] = set(values)
    return result


def _wrapper(upstream, payloads):
    wrapper = upstream["delivery"]["gradleWrapper"]
    if not payloads[wrapper["jar"]].startswith(b"PK\x03\x04"):
        fail("upstream-wrapper-jar", wrapper["jar"])
    try:
        lines = payloads[wrapper["properties"]].decode("utf-8").splitlines()
    except UnicodeError:
        fail("upstream-wrapper-properties", wrapper["properties"])
    values = {}
    for line in lines:
        line = line.strip()
        if not line or line.startswith(("#", "!")):
            continue
        key, separator, value = line.partition("=")
        value = value.replace("\\:", ":")
        if not separator or key in values or "\\" in value:
            fail("upstream-wrapper-properties", wrapper["properties"])
        values[key] = value
    distribution = wrapper["distribution"]
    if values.get("distributionUrl") != distribution["url"] or values.get("distributionSha256Sum") != distribution["digest"]:
        fail("upstream-wrapper-distribution", wrapper["properties"])


def validate_delivery_bytes(upstream: dict, payloads: dict[str, bytes]) -> None:
    delivery = upstream["delivery"]
    if delivery["kind"] == "bundled":
        if "gradleWrapper" in delivery:
            _wrapper(upstream, payloads)
        return
    raw = _bound_file(delivery["lock"], delivery["digest"], payloads)
    if delivery["manager"] == "npm":
        lock = loads(raw, delivery["lock"])
        if type(lock) is not dict or lock.get("lockfileVersion") != 3 or type(lock.get("packages")) is not dict:
            fail("upstream-lock-format", delivery["lock"])
        found = lock["packages"].get(delivery["packagePath"])
        if type(found) is not dict or found.get("version") != upstream["version"] or found.get("integrity") != delivery["integrity"]:
            fail("upstream-lock-pin", upstream["name"])
    elif delivery["manager"] == "swift":
        lock = fields(loads(raw, delivery["lock"]), "originHash pins version", "upstream.swift")
        if type(lock["version"]) is not int or lock["version"] != 3:
            fail("upstream-lock-format", delivery["lock"])
        sha256(lock["originHash"], "upstream.swift.originHash")
        pins = array(lock["pins"], "upstream.swift.pins", True)
        for pin in pins:
            fields(pin, "identity kind location state", "upstream.swift.pin")
            choice(pin["kind"], ("remoteSourceControl",), "upstream.swift.kind")
            text(pin["identity"], "upstream.swift.identity")
            text(pin["location"], "upstream.swift.location")
            fields(pin["state"], "revision version", "upstream.swift.state")
            if type(pin["state"]["revision"]) is not str or not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", pin["state"]["revision"]):
                fail("upstream-source-revision", pin["identity"])
            text(pin["state"]["version"], "upstream.swift.version")
        unique([pin["identity"] for pin in pins], "upstream.swift.pins")
        found = next((pin for pin in pins if pin["identity"] == upstream["name"]), None)
        if found is None or found["location"] != upstream["repository"] or found["state"] != {"revision": upstream["revision"], "version": upstream["version"]}:
            fail("upstream-lock-pin", upstream["name"])
    else:
        coordinate = _coordinate(upstream)
        entries = _gradle_lock(raw)
        if any(entries.get((coordinate[0], coordinate[1], configuration)) != coordinate[2] for configuration in delivery["configurations"]):
            fail("upstream-lock-pin", upstream["name"])
        verification = delivery["verification"]
        metadata = _bound_file(verification["path"], verification["digest"], payloads)
        checksums = _gradle_checksums(metadata, coordinate)
        if {item["name"] for item in delivery["artifacts"]} != checksums.keys():
            fail("upstream-verification-inventory", upstream["name"])
        for artifact in delivery["artifacts"]:
            if artifact["digest"] not in checksums[artifact["name"]]:
                fail("upstream-verification-checksum", artifact["name"])
