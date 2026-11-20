# Package foundations

## Document formats

| Document | Format | An earlier format is refused with |
|---|---|---|
| Package manifest (`component.json`) | 3 | `manifest-format-outdated` |
| Class descriptor (`class.json`, and each descriptor embedded in a manifest) | 2 | `class-format-outdated` |
| `recipe.json` | 2 | `recipe-format-outdated` |
| `categories.json` | 1 | none earlier |
| Release and guardian statements | in-toto statement v1 with the release and guardian predicate types | none earlier |
| Review and verification report | 2 (with an execution record), 1 (without) | `report-format-outdated` for results without `storage` or `locks` |
| `.aepm/definition.json` | 2 | `definition-format-outdated` |
| `.aepm/lock.json` | 1 | none earlier |
| Update proposal | 2 | `proposal-format-outdated` |

The catalogue entry API is defined by the catalogue, not by aepm.

## Package manifest, format 3

Each check's `execution` is optional: a check without it runs in a private copy with no resources and no assertions; a check with it runs with its supplied context. `upgrade` is `{migration}`. These fields are required:

- `release`: `{channel, fixes}`. The version decides the channel: a preview `MAJOR.MINOR.PATCH-preview.N` is `preview`, patch 0 is `features`, patch above 0 is `security`. `fixes` lists the advisory ids a `security` release fixes (at least one, unique) and is `[]` otherwise; anything else is `release-channel`.
- `images`: at most 12 `{path, caption, platform, width, height}`. Each path is listed in `files` and ends `.png` or `.webp`; the file is at most 2 MiB; `width` and `height` equal the size in its PNG IHDR or WebP VP8, VP8L or VP8X header; `caption` is at most 140 characters; `platform` is one of the package's platforms. The first image is the main image. At least one is required when the package implements a class whose `presentation` is `visual`, and for a recipe with any platform other than `server` (`images-required`).
- `vulnerabilityWaivers`: `[{id, reason}]` with unique advisory ids and a non-empty reason of at most 2000 characters; `[]` when none.

Advisory ids are an upper-case prefix, a hyphen, then letters, digits, `.`, `:`, `_` or `-`, at most 64 characters.

## Categories

`classes/categories.json` is `{"format": 1, "categories": [{"id", "title", "parent"}]}`. Ids are unique paths of lower-case segments of letters, digits and hyphens joined by `/`; each parent is null or another entry's id; parents form no cycle. `aepm.foundations.validate_categories(document, class_categories)` checks this and that each given class category exists. aepm checks only a class's category form; the class generator, the publish tool and the catalogue check that it exists.

## Package foundations

All fields below are mandatory. Class references are exact `{name, version, digest}` objects. Names use `ourapps-ae/<slug>`, class and interface versions use three nonnegative integers, package versions may add `-preview.N`, and digests are lowercase SHA-256. `digest` is the hash of the RFC 8785 canonical descriptor. Each descriptor is an object inside the canonical package manifest. Every inventory entry hashes one packaged file; interface and behaviour files belong to that inventory. Class identity conflicts within a selected graph are errors.

## Manifest fields

These fields accompany the package manifest's other required fields. The complete component is [examples/counter/component.json](examples/counter/component.json), with its packaged interface, test, source and notice files:

```json
{
  "platforms": ["web", "server"],
  "toolchains": {
    "web": [{"name": "node", "versionRange": ">=22.0.0 <27.0.0", "probe": ["node", "--version"], "install": {"macos": ["brew", "install", "node"], "windows": ["winget", "install", "--exact", "--id", "OpenJS.NodeJS"], "linux": ["sudo", "apt-get", "install", "--yes", "nodejs"]}, "manual": null}],
    "server": [{"name": "node", "versionRange": ">=22.0.0 <27.0.0", "probe": ["node", "--version"], "install": {"macos": ["brew", "install", "node"], "windows": ["winget", "install", "--exact", "--id", "OpenJS.NodeJS"], "linux": ["sudo", "apt-get", "install", "--yes", "nodejs"]}, "manual": null}]
  },
  "classes": [{"reference": {"name": "ourapps-ae/counter-class", "version": "1.0.0", "digest": "69d916fa86d7379b357fb545e432eeaebaa634140ee688e770cd315cc8c63af9"}, "descriptor": {"format": 2, "name": "ourapps-ae/counter-class", "version": "1.0.0", "title": "Counter", "summary": "A number that goes up by one", "category": "examples/counters", "presentation": "visual", "provides": [{"type": "counter", "version": "1.0.0", "path": "classes/counter/interface.json", "modules": {"web": ["counter.mjs"], "server": ["counter.mjs"]}}], "requires": [], "settings": {"type": "object", "properties": {}, "required": [], "additionalProperties": false}, "inventory": [{"path": "classes/counter/interface.json", "digest": "316538fd92c18f09d76df05de128d1099d00d7cfbf34401f82b1bd56989ba0d2"}, {"path": "classes/counter/check.mjs", "digest": "7b6a4b0a9ba601c7c2f058f62d46b4d349c8010bd6c3f9f5d28b762209735770"}], "verification": [{"id": "behaviour", "root": "package", "argv": ["node", "classes/counter/check.mjs"], "cwd": ".", "prepare": [], "tools": {"node": "26"}, "fixtures": ["classes/counter/check.mjs"], "locks": [], "network": false, "timeoutSeconds": 30, "expectedExit": 0, "scope": "required-local", "requirements": []}]}}],
  "implements": [{"name": "ourapps-ae/counter-class", "version": "1.0.0", "digest": "69d916fa86d7379b357fb545e432eeaebaa634140ee688e770cd315cc8c63af9"}],
  "upstream": [],
  "compatibility": {
    "runtimes": {"node": ">=22.0.0 <27.0.0"},
    "frameworks": {},
    "dependencies": [],
    "styles": {"scope": "none", "namespaces": [], "conflicts": []}
  },
  "maintenance": {
    "owners": ["Example Maintainer"],
    "contact": "mailto:maintainer@example.org",
    "repository": "https://example.org/counter",
    "updates": {"source": "https://example.org/counter/releases", "strategy": "manual"}
  }
}
```

Platforms are `web`, `server`, `ios`, `macos`, `tvos`, `android`, `windows`. Components declare at least one implementation; recipes may declare none. Every implementation and recipe slot reference resolves to a packaged descriptor. A recipe slot's `class` contains only the reference. Package `platforms` describes actual supported targets. Each class-provided interface declares its own platform module map. Module paths are relative to `components/<package short name>/` destinations. An entry is a file or a directory containing installed artefacts.

## Class descriptor

A descriptor carries `title` (at most 256 characters), `summary` (at most 500), `category` (a category path) and `presentation` (`visual` when implementations render something people see, else `none`); its digest covers them.

```json
{
  "format": 2,
  "name": "ourapps-ae/counter-class",
  "version": "1.0.0",
  "title": "Counter",
  "summary": "A number that goes up by one",
  "category": "examples/counters",
  "presentation": "visual",
  "provides": [{"type": "counter", "version": "1.0.0", "path": "classes/counter/interface.json", "modules": {"web": ["counter.mjs"], "server": ["counter.mjs"]}}],
  "requires": [],
  "settings": {"type": "object", "properties": {}, "required": [], "additionalProperties": false},
  "inventory": [{"path": "classes/counter/interface.json", "digest": "316538fd92c18f09d76df05de128d1099d00d7cfbf34401f82b1bd56989ba0d2"}, {"path": "classes/counter/check.mjs", "digest": "7b6a4b0a9ba601c7c2f058f62d46b4d349c8010bd6c3f9f5d28b762209735770"}],
  "verification": [{"id": "behaviour", "root": "package", "argv": ["node", "classes/counter/check.mjs"], "cwd": ".", "prepare": [], "tools": {"node": "26"}, "fixtures": ["classes/counter/check.mjs"], "locks": [], "network": false, "timeoutSeconds": 30, "expectedExit": 0, "scope": "required-local", "requirements": []}]
}
```

Inventory paths are package-relative and unique. All class suites are required-local package suites without external prerequisites; their working directory is `.`. A command starts with a declared tool followed by an inventory-bound script, or an inventory-bound `./script`. Their preparation scripts, fixtures and locks are inventory-bound. Shared tests load candidate source using `AEPM_CANDIDATE_ROOT`, `AEPM_CANDIDATE_MANIFEST`, `AEPM_CANDIDATE_DIGEST`, `AEPM_CLASS_DIGEST`, and `AEPM_MODULE_MAP` (a JSON object mapping declared installed destination to absolute staged source path). The runner supplies these only for class suites. Each suite receives a fresh candidate package copy and the class inventory's verified bytes. Class suites use the same explicit trusted execution, tool pins, network authorization, private directory and credential-free environment as package suites. Suite declarations and results bind the candidate archive and descriptor/inventory digests in signed review evidence.

Settings use a closed JSON Schema subset: an object with `type`, `properties`, `required`, `additionalProperties: false`; properties have `type` (`string`, `boolean`, `integer`) and strings also have an anchored `pattern` equal to an aepm setting grammar. Candidate declarations must accept the class settings and must not introduce required settings without defaults.

## Upstream and dependencies

```json
{
  "upstream": [{
    "name": "example-library", "version": "4.2.0", "revision": "a1b2c3",
    "repository": "https://example.org/example-library", "purl": "pkg:npm/example-library@4.2.0",
    "licence": "MIT OR Apache-2.0", "notices": ["notices/example-library.txt"],
    "delivery": {"kind": "bundled", "files": [{"path": "vendor/example.mjs", "digest": "619a46d55f9b64f4ddb40b9ae15445c8eebe3aac51d77e50353a096d13f62ba2"}]}
  }]
}
```

The bundled example hashes the `src/counter.mjs` bytes in the complete example. Build-time delivery instead uses the following declaration and canonical npm package-lock version 3 content:

```json
{
  "delivery": {"kind": "build-time", "manager": "npm", "lock": "package-lock.json", "digest": "bc5f16109e2d1dc11a1a3f4dec296d0e6e6267843c03db69ec18de3bc6c05e0c", "packagePath": "node_modules/example-library", "integrity": "sha512-YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYQ=="},
  "lockContent": {"lockfileVersion": 3, "packages": {"node_modules/example-library": {"version": "4.2.0", "integrity": "sha512-YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYQ=="}}}
}
```

An npm upstream entry declares mandatory `packagePath`, the exact key under `packages`, including nested paths such as `node_modules/x/node_modules/y`. Its leaf package name equals both `upstream.name` and the package URL name. The exact version and integrity match that key's record. The lock and nonempty notice files are packaged. Build dependencies are never downloaded during installation. Bundled source has a nonempty file/digest inventory. Package `identity.licence` describes wrapper code; upstream expressions and notices remain separate in the bill of materials. Original packages have an empty upstream list.

Every build-time delivery names `manager`: `npm`, `gradle` or `swift`. The manager must match the package URL type (`npm`, `maven` or `swift`). Unsupported managers, missing pins and mismatched packaged bytes are errors.

### Swift

Swift delivery has exactly `{kind: "build-time", manager: "swift", lock, digest}`. The packaged `Package.resolved` is format 3, with `originHash`, `pins` and `version`. Each pin has `identity`, `kind: "remoteSourceControl"`, `location`, and `state: {revision, version}`. The selected pin's identity equals `upstream.name`, location equals `upstream.repository`, version equals `upstream.version`, and Git revision equals `upstream.revision`. Revisions are exact 40- or 64-character lowercase hexadecimal strings. Branch pins and local dependencies are unsupported. A resolved Git revision does not verify source-tree or binary-target bytes; those require their own inventories and execution evidence.

### Gradle

Gradle delivery has exactly `{kind: "build-time", manager: "gradle", lock, digest, verification: {path, digest}, configurations, artifacts}`. Both files are packaged and digest-bound. `upstream.purl` is `pkg:maven/<group>/<artifact>@<version>`, and `upstream.name` equals the artifact name. The exact coordinate must occur in the Gradle dependency lock for every declared configuration. A coordinate/configuration pair has only one version. `artifacts` is a nonempty array of `{name, digest}` records, containing exactly the artifact names of that component in Gradle's namespaced `verification-metadata.xml`; each digest matches a declared SHA-256 checksum. Maven `upstream.revision` is null when a source revision is unavailable. Artifact checksums do not establish a source revision, source licence, complete transitive inventory or successful dependency resolution. Notices remain separately required.

### Bundled Gradle wrapper

A bundled Gradle wrapper has its own upstream record, notices and file/digest inventory, separate from application dependencies. Its bundled delivery adds `gradleWrapper: {jar, properties, distribution: {url, digest}}`; `jar` and `properties` name files in the inventory. A packaged `gradle-wrapper.jar` requires this separate attribution. The wrapper properties contain exactly matching `distributionUrl` and `distributionSha256Sum`, and the distribution URL names `gradle-<upstream.version>-bin.zip` or `-all.zip`. The jar bytes are checked against their inventory digest. A wrapper's `upstream.revision` is null when its source revision is unavailable. This binds the packaged wrapper and declared distribution checksum; it does not download the distribution or independently establish the upstream authority of a checksum.

Compatibility dependencies are `{name, version, isolation}` objects, where `name` is a package URL without a version, `version` is an exact nonempty version identifier using letters, digits, dots, underscores and hyphens, and `isolation` is `shared` or `isolated`. Shared pins must agree across the graph. Isolated pins may differ. Runtime maps contain ranges. Framework maps identify a shared role, such as `web-ui`, with `{name, range}`; different framework names in one role conflict. Ranges use a conjunction of space-separated comparators `=`, `>`, `>=`, `<`, `<=` followed immediately by an exact three-integer version. No wildcards, disjunctions, prereleases, caret or tilde forms are accepted. Intersections must contain at least one version.

Styles use scope `none`, `scoped` or `global`. `none` has empty namespaces and conflicts; other scopes declare nonempty unique namespace strings. Global namespace overlaps and either package's declared conflicts with the other's namespaces fail graph validation. Design checks selected platforms from `answers.targets`, or all recipe platforms when that answer is absent. A recipe supporting `server` includes that target in every selection. Every package must support at least one selected target; fit checks every selected target declared by each class interface. Installation checks the definition's retained answers by the same rule.

Maintenance has nonempty owners, contact and repository, and updates with a source and strategy `manual` or `release`. Verification dates are facts derived from validated signed review reports outside manifests. A manifest has no verification timestamp or self-referencing archive digest.

## Dependency reuse

- npm seeds, per run: cache content whose bytes match a package-lock SHA-512 integrity, copied into later checks' private npm caches. They save downloads, not disk space.
- Swift seeds, per run: fresh bare repositories built from object files that `git fsck --full --strict` verifies, holding the pinned revision complete, with no hooks or configuration from the source.
- Android SDK and Gradle home: one cloned private writable copy per check.
- Gradle seeding is not implemented: Gradle needs its metadata stores, which no lock pins.

## Toolchains

`toolchains` maps every declared platform, and only those, to the tools a machine needs to build that platform's outputs. A list may be empty. Test-suite `tools` pins remain separate. A complete declaration for a package supporting web, iOS and Android:

```json
{
  "toolchains": {
    "web": [
      {"name": "node", "versionRange": ">=22.0.0 <27.0.0", "probe": ["node", "--version"],
       "install": {"macos": ["brew", "install", "node"], "windows": ["winget", "install", "--exact", "--id", "OpenJS.NodeJS"], "linux": ["sudo", "apt-get", "install", "--yes", "nodejs"]},
       "manual": null}
    ],
    "ios": [
      {"name": "xcodebuild", "versionRange": ">=16.0.0 <27.0.0", "probe": ["xcodebuild", "-version"],
       "install": {"macos": null, "windows": null, "linux": null},
       "manual": "Install Xcode from the Mac App Store, open it once and accept the licence."},
      {"name": "xcodegen", "versionRange": ">=2.40.0 <3.0.0", "probe": ["xcodegen", "--version"],
       "install": {"macos": ["brew", "install", "xcodegen"], "windows": null, "linux": null},
       "manual": null}
    ],
    "android": [
      {"name": "java", "versionRange": ">=21.0.0 <27.0.0", "probe": ["java", "-version"],
       "install": {"macos": ["brew", "install", "--cask", "temurin"], "windows": ["winget", "install", "--exact", "--id", "EclipseAdoptium.Temurin.21.JDK"], "linux": ["sudo", "apt-get", "install", "--yes", "openjdk-21-jdk"]},
       "manual": null},
      {"name": "sdkmanager", "versionRange": ">=12.0.0", "probe": ["sdkmanager", "--version"],
       "install": {"macos": ["brew", "install", "--cask", "android-commandlinetools"], "windows": null, "linux": null},
       "manual": "Set ANDROID_HOME, then run sdkmanager --licenses and accept every licence."}
    ]
  }
}
```

A tool has exactly `name`, `versionRange`, `probe`, `install` and `manual`:

- `name`: lowercase letters, digits, `.`, `+` and `-`, starting with a letter. Names are unique within a platform.
- `versionRange`: the comparator subset used for runtimes.
- `probe`: an argument list whose first item is a command name without a path; aepm finds it on `PATH` (version-manager shims resolve to the selected executable). The first version number in the combined output, `MAJOR[.MINOR[.PATCH]]` padded with zeros, is compared with the range. A probe exiting nonzero gives no version.
- `install`: exactly `macos`, `windows` and `linux`, each null or an argument list beginning `brew install`, `winget install`, or `apt-get install` / `sudo apt-get install` respectively, with at least one further argument.
- `manual`: text for steps no package manager performs, or null. A tool with no installer and no manual text is invalid.

Declarations of one tool name, within a package or across a graph, share identical `probe`, `install` and `manual`; their ranges intersect, and an empty intersection is `toolchain-conflict`. Design and installation check these merges over the selected targets.

## Doctor

`aepm doctor RECIPE@VERSION --store STORE [--answers FILE] [--install]` evaluates the design as `design` does, resolves its package graph, merges the toolchains of the selected targets, and probes each tool. It prints `{"ok": BOOL, "result": {host, targets, tools}}`, where `host` is `{os, architecture}` with `os` one of `macos`, `windows`, `linux`, and each tool is `{name, required, platforms, found, version, status, install, manual}`. `required` is the merged range in `>=X.Y.Z[ <X.Y.Z]` form, `found` is the resolved executable path or null, `status` is `ok`, `missing` or `wrong-version`, and `install` is the argument list for this host or null. `ok` is true only when every tool is `ok`; otherwise the command exits 1.

`--install` runs, one at a time, the host's install argument list for each `missing` tool that has one, writing `$ COMMAND` to standard error before each and sending installer output to standard error. It adds `installed: [{name, argv, exitCode}]` and probes again. Wrong versions and manual steps are reported, not changed. Without `--install`, doctor installs nothing.

```json
{"ok": false, "result": {
  "host": {"architecture": "arm64", "os": "macos"},
  "targets": ["ios", "server", "web"],
  "tools": [
    {"found": "/opt/homebrew/Cellar/node/26.5.0/bin/node", "install": ["brew", "install", "node"], "manual": null, "name": "node",
     "platforms": ["server", "web"], "required": ">=22.0.0 <27.0.0", "status": "ok", "version": "26.5.0"},
    {"found": "/Applications/Xcode.app/Contents/Developer/usr/bin/xcodebuild", "install": null,
     "manual": "Install Xcode from the Mac App Store, open it once and accept the licence.", "name": "xcodebuild",
     "platforms": ["ios"], "required": ">=16.0.0 <27.0.0", "status": "ok", "version": "26.1.0"},
    {"found": null, "install": ["brew", "install", "xcodegen"], "manual": null, "name": "xcodegen",
     "platforms": ["ios"], "required": ">=2.40.0 <3.0.0", "status": "missing", "version": null}
  ]}}
```

## Public helpers

```python
validate_class_reference(value: object) -> dict
validate_class_descriptor(value: object) -> dict
validate_foundations(manifest: dict) -> None
validate_package_foundations(manifest: dict, payloads: dict[str, bytes]) -> dict[str, dict]
validate_graph(manifests: list[dict], targets: list[str] | None = None) -> None
class_descriptor(manifest: dict, payloads: dict[str, bytes], reference: dict) -> dict
module_sources(manifest: dict, root: Path, *, slot: str | None = None) -> dict[str, str]
source_for_module(manifest: dict, root: Path, installed_path: str, *, slot: str | None = None) -> Path
selected_targets(recipe_manifest: dict, answers: dict) -> list[str]
maintenance_facts(ref: dict, store: Path, policy: Path) -> dict
class_suites(manifest: dict) -> list[dict]
class_result_evidence(suite: dict, source: Path, started_at: int | None = None, completed_at: int | None = None) -> dict
validate_class_result_evidence(result: dict, suite: dict) -> None
```

`aepm.toolchains` provides `validate_tool(value, path) -> dict`, `merge_toolchains(manifests, targets=None) -> list[dict]` and `probe_version(output) -> tuple | None`; `aepm.doctor.doctor(recipe, version, store, answers, *, install=False, host=None, which, runner, installer, announce) -> dict` accepts replacement lookup, probe and installer functions.

`aepm.foundations` owns these helpers. `aepm.recipe.fit(reference, package, authority, targets=None)` returns fit failure reasons; `authority` is a package containing the authoritative class bytes, independent of a preferred implementation.

`module_sources` and `source_for_module` map manifest artefacts to packaged source; `slot` remaps `components/<package name>/` to `components/<slot>/`. An unknown installed module is an error.

`aepm.trust.publish_review(store: Path, ref: PackageRef, report: dict, private_key: Path, *, policy: Path) -> dict` validates the complete report and its retained evidence before guardian signing. Each class result carries `classEvidence: {reference, inventoryDigest, startedAt, completedAt}`: the class reference, the SHA-256 of the canonical class inventory the suite ran, and Unix timestamps from execution. The record has the same size whatever the inventory holds. The inventory bytes are the package archive's own files: every report binds its archives through `packages` and the suite declarations through `suiteSetDigest`, archives are checked against the inventory when read, staged suite files are checked before their result is recorded, and an installed application's retained package files are checked for exact membership and digests before any report is accepted. `maintenance_facts` validates the signed guardian and report, and returns `package`, `maintenance`, `platforms`, `lastSuccessfulVerification`, `reportDigest`, and `reviewSignedAt`. The successful verification time comes from execution evidence; a report without timed execution returns null.
