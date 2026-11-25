"""Frozen local installer commands."""

import argparse
from pathlib import Path
import shutil
import sys

from .application import assemble, read_assembly, requirements, validate_definition
from .bundle import pack, read_package, resolve
from .export import export_design
from .fetch import CATALOGUE
from .io import fail, linked, load, write
from .model import SCOPE, AepmError, canonical, digest
from .trust import sign
from .verification import review_package, verify_application


class Parser(argparse.ArgumentParser):
    def error(self, message):
        fail("arguments", "command")


def parser():
    root = Parser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)
    specifications = {
        "pack": ("source", ("store",)), "inspect": ("digest", ("store",)), "bom": ("digest", ("store", "out")),
        "resolve": ("definition", ("catalogue", "out")), "sign": ("statement", ("role", "key", "out")),
        "install": ("definition", ("lock", "store", "policy", "target")),
        "verify": ("app", ("policy",)), "review": ("digest", ("store", "policy")),
        "export": ("app", ("out",)), "propose-update": ("app", ("store", "policy", "out")),
        "approve": ("proposal", ("key", "policy", "out")), "apply": ("app proposal", ("approval", "policy")),
        "recover": ("app", ()),
    }
    for command, (positions, flags) in specifications.items():
        child = commands.add_parser(command)
        for position in positions.split():
            child.add_argument(position)
        for flag in flags:
            child.add_argument("--" + flag, required=True)
        if command == "propose-update":
            child.add_argument("definition", nargs="?")
            child.add_argument("--channel", choices=("security", "features", "preview"))
            child.add_argument("--update-policy")
            child.add_argument("--from", dest="origin", default=CATALOGUE)
        if command in ("verify", "review", "propose-update"):
            child.add_argument("--trusted", action="store_true")
            child.add_argument("--allow-network", action="store_true")
            for option in ("context", "authorization", "execution-state", "secrets"):
                child.add_argument("--" + option, type=Path)
            child.add_argument("--allow-live", action="store_true")
    request = commands.add_parser("execution-request")
    target = request.add_mutually_exclusive_group(required=True)
    target.add_argument("--app", type=Path)
    target.add_argument("--review")
    request.add_argument("--store", type=Path)
    for option in ("context", "policy", "execution-state", "out"):
        request.add_argument("--" + option, type=Path, required=True)
    request.add_argument("--expires-at", type=int, required=True)
    request.add_argument("--suite", action="append")
    design = commands.add_parser("design")
    design.add_argument("recipe")
    design.add_argument("--store", type=Path, required=True)
    design.add_argument("--answers", type=Path)
    design.add_argument("--out", type=Path, required=True)
    design.add_argument("--substitute", action="append", default=[])
    design.add_argument("--update-policy")
    stale = commands.add_parser("outdated")
    stale.add_argument("app", type=Path)
    stale.add_argument("--from", dest="origin", default=CATALOGUE)
    other = commands.add_parser("alternatives")
    other.add_argument("recipe")
    other.add_argument("slot")
    other.add_argument("--store", type=Path, required=True)
    other.add_argument("--from", dest="origin", default=CATALOGUE)
    get = commands.add_parser("fetch")
    get.add_argument("packages", nargs="+")
    get.add_argument("--store", type=Path, required=True)
    get.add_argument("--from", dest="origin", default=CATALOGUE)
    get.add_argument("--with-dependencies", action="store_true")
    check = commands.add_parser("doctor")
    check.add_argument("recipe")
    check.add_argument("--store", type=Path, required=True)
    check.add_argument("--answers", type=Path)
    check.add_argument("--install", action="store_true")
    room = commands.add_parser("space")
    room.add_argument("path", type=Path)
    room.add_argument("--need", type=int, default=0)
    commands.add_parser("locks")
    hold = commands.add_parser("lock")
    hold.add_argument("kind")
    hold.add_argument("--timeout", type=float, default=3600)
    hold.add_argument("--purpose", default="command")
    hold.add_argument("argv", nargs="*")
    commands.add_parser("runs")
    tidy = commands.add_parser("clean")
    tidy.add_argument("--apply", action="store_true")
    tidy.add_argument("--older-than")
    ask = commands.add_parser("questions")
    ask.add_argument("recipe")
    ask.add_argument("--store", type=Path, required=True)
    ask.add_argument("--answers", type=Path)
    authorize = commands.add_parser("authorize-execution")
    authorize.add_argument("request", type=Path)
    for option in ("key", "policy", "out"):
        authorize.add_argument("--" + option, type=Path, required=True)
    return root


def reference(archive_digest, store):
    catalogue = load(Path(store) / "catalogue.json")
    matches = [item for item in catalogue["entries"] if item["digest"] == archive_digest]
    if len(matches) != 1:
        fail("unknown-package", "digest")
    return matches[0]


def identity(value):
    """NAME@VERSION, with NAME a package name or its short form."""
    from .model import name, package_version
    package, separator, number = value.rpartition("@")
    if not separator:
        fail("arguments", "package")
    package = package if "/" in package else f"{SCOPE}/{package}"
    return name(package, "package"), package_version(number, "package")


class Refused(Exception):
    def __init__(self, errors):
        self.errors = errors


def dispatch(args):
    command = args.command
    if command == "fetch":
        from .fetch import fetch
        return fetch(args.store, [identity(item) for item in args.packages], with_dependencies=args.with_dependencies,
                     origin=args.origin)
    if command == "alternatives":
        from .fetch import fetch, providers
        from .recipe import World, slot_fit, _class_payloads
        world = World.from_store(*identity(args.recipe), args.store)
        if args.slot not in world.slots:
            fail("unknown-slot", args.slot)
        spec = world.slots[args.slot]
        from .foundations import class_descriptor
        authority = world.authority
        descriptor = class_descriptor(authority.manifest, _class_payloads(authority, spec["class"]), spec["class"])
        found = providers([item["type"] for item in descriptor["provides"]], origin=args.origin)
        fetch(args.store, found, origin=args.origin)
        result = []
        for package_name, package_version in found:
            candidate = World.from_store(*identity(args.recipe), args.store, {args.slot: (package_name, package_version)})
            reasons = slot_fit(candidate, args.slot, candidate.filling[args.slot])
            result.append({"name": package_name, "version": package_version, "fits": not reasons, "reasons": reasons})
        return result
    if command == "space":
        from .space import free_bytes, margin, require_space, reserved_by_others
        total = shutil.disk_usage(args.path if args.path.exists() else next(p for p in args.path.absolute().parents if p.exists())).total
        value = {"path": str(args.path), "free": free_bytes(args.path), "total": total, "margin": margin(),
                 "reserved": reserved_by_others(args.path), "need": args.need}
        try:
            require_space(args.path, args.need, purpose="space command")
            value["ok"] = True
        except AepmError as error:
            if error.code != "insufficient-space":
                raise
            value["ok"] = False
        return value
    if command == "locks":
        from .locks import holders
        return holders()
    if command == "lock":
        from .locks import heavy
        import subprocess
        argv = args.argv[1:] if args.argv[:1] == ["--"] else args.argv
        if not argv:
            fail("arguments", "command")
        with heavy(args.kind, purpose=args.purpose, timeout=args.timeout) as waited:
            code = subprocess.run(argv).returncode
        return {"kind": args.kind, "waitedSeconds": round(waited, 3), "exitCode": code}
    if command == "runs":
        from .ledger import runs
        return runs()
    if command == "clean":
        from .clean import clean
        return clean(apply=args.apply, older_than=args.older_than)
    if command == "doctor":
        from .doctor import Refused as DesignRefused, doctor
        answers = load(args.answers) if args.answers is not None else {}
        if type(answers) is not dict:
            fail("invalid-answers", "answers")
        try:
            return doctor(*identity(args.recipe), args.store, answers, install=args.install)
        except DesignRefused as refused:
            raise Refused(refused.errors)
    if command in ("design", "questions"):
        from .recipe import World, evaluate, questions
        substitutes = {}
        for value in getattr(args, "substitute", []):
            slot, separator, package = value.partition("=")
            if not separator or not slot:
                fail("arguments", "substitute")
            substitutes[slot] = identity(package)
        world = World.from_store(*identity(args.recipe), args.store, substitutes)
        if command == "questions":
            partial = load(args.answers) if args.answers is not None else {}
            if type(partial) is not dict:
                fail("invalid-answers", "answers")
            return questions(world.recipe, world, partial)
        answers = load(args.answers) if args.answers is not None else {}
        if type(answers) is not dict:
            fail("invalid-answers", "answers")
        result = evaluate(world, answers)
        if not result["ok"]:
            raise Refused(result["errors"])
        if args.update_policy is not None:
            from .application import parse_update_policy
            result["design"]["updatePolicy"] = parse_update_policy(args.update_policy)
        definition = validate_definition(result["design"])
        write(args.out, definition)
        return {"definition": str(args.out), "digest": digest(canonical(definition)), "components": len(definition["components"])}
    execution_options = {}
    if command in ("verify", "review", "propose-update"):
        execution_options = {"execution_context": args.context, "authorization": args.authorization,
                             "execution_state": args.execution_state, "secrets": args.secrets, "allow_live": args.allow_live}
    if command == "execution-request":
        from .authorization import execution_request
        if args.review is not None and args.store is None:
            fail("arguments", "store")
        selected_pairs = None
        if args.suite is not None:
            selected_pairs = []
            for value in args.suite:
                package, separator, identifier = value.partition(":")
                if not separator or not package or not identifier:
                    fail("invalid-selection", "suite")
                selected_pairs.append({"package": package, "id": identifier})
        return execution_request(app=args.app, ref=reference(args.review, args.store) if args.review else None,
                                 store=args.store, context=args.context, policy=args.policy,
                                 execution_state=args.execution_state, expires_at=args.expires_at, out=args.out, selected_pairs=selected_pairs)
    if command == "authorize-execution":
        from .authorization import authorize_execution
        return authorize_execution(args.request, args.key, args.policy, args.out)
    if command == "pack":
        return pack(Path(args.source), Path(args.store))
    if command == "inspect":
        return read_package(reference(args.digest, args.store), Path(args.store))[0]
    if command == "bom":
        from .bom import bill_of_materials
        document = bill_of_materials(reference(args.digest, args.store), Path(args.store))
        write(args.out, document)
        return {"bom": str(Path(args.out)), "components": len(document["components"])}
    if command == "resolve":
        definition = validate_definition(load(args.definition))
        result = resolve(requirements(definition), Path(args.catalogue), definition["id"], digest(canonical(definition)))
        write(args.out, result)
        return result
    if command == "sign":
        envelope = sign(load(args.statement), args.role, Path(args.key))
        write(args.out, envelope)
        return {"envelope": str(Path(args.out))}
    if command == "install":
        return assemble(validate_definition(load(args.definition)), load(args.lock), Path(args.store), Path(args.target), Path(args.policy))
    if command == "verify":
        return verify_application(Path(args.app), Path(args.policy), args.trusted, allow_network=args.allow_network, **execution_options)
    if command == "review":
        return review_package(reference(args.digest, args.store), Path(args.store), Path(args.policy), args.trusted, allow_network=args.allow_network, **execution_options)
    if command == "export":
        return export_design(read_assembly(Path(args.app)), Path(args.out))
    if command == "outdated":
        from .channels import outdated
        return outdated(args.app, args.origin)
    if command == "propose-update":
        from .update import propose
        if (args.definition is None) == (args.channel is None):
            fail("arguments", "propose-update")
        skipped = []
        if args.channel is not None:
            from .channels import next_definition
            definition, skipped = next_definition(Path(args.app), args.channel, Path(args.store), args.origin)
        else:
            definition = validate_definition(load(args.definition))
        policy = None
        if args.update_policy is not None:
            from .application import parse_update_policy
            policy = parse_update_policy(args.update_policy)
        result = propose(Path(args.app), definition, Path(args.store), Path(args.policy), args.trusted,
                         allow_network=args.allow_network, channel=args.channel, skipped=skipped, update_policy=policy,
                         **execution_options)
        write(args.out, result)
        return result
    if command == "approve":
        from .update import approve
        source = approve(Path(args.proposal), Path(args.key), Path(args.policy))
        destination = Path(args.out)
        if source.absolute() != destination.absolute():
            if destination.exists() or linked(destination):
                fail("approval-output-exists", "approval")
            shutil.copyfile(source, destination)
        return {"approval": str(destination)}
    if command == "apply":
        from .update import apply
        return apply(Path(args.app), Path(args.proposal), Path(args.approval), Path(args.policy))
    from .update import recover
    return recover(Path(args.app))


def args_command(argv):
    values = list(sys.argv[1:] if argv is None else argv)
    return str(values[0]) if values else "command"


def main(argv=None):
    try:
        args = parser().parse_args(argv)
        result = dispatch(args)
        if args.command == "space":
            print(canonical({"ok": result["ok"], "result": result}).decode("utf-8"))
            return int(not result["ok"])
        if args.command == "lock":
            print(canonical({"ok": result["exitCode"] == 0, "result": result}).decode("utf-8"))
            return result["exitCode"] if 0 < result["exitCode"] < 256 else int(result["exitCode"] != 0)
        if args.command == "clean" and result.get("failed"):
            print(canonical({"ok": False, "result": result}).decode("utf-8"))
            return 1
        if args.command == "doctor":
            healthy = all(tool["status"] == "ok" for tool in result["tools"])
            print(canonical({"ok": healthy, "result": result}).decode("utf-8"))
            return int(not healthy)
        print(canonical({"ok": True, "result": result}).decode("utf-8"))
        return int(args.command in ("verify", "review") and result["summary"]["required-local"] != "passed")
    except Refused as refused:
        print(canonical({"ok": False, "errors": refused.errors}).decode("utf-8"))
    except AepmError as error:
        print(canonical({"ok": False, "error": error.document()}).decode("utf-8"))
    except OSError as error:
        from .space import from_os_error, out_of_space
        document = from_os_error(error, args_command(argv)).document() if out_of_space(error) else {"code": "invalid-input-or-filesystem", "path": "command"}
        print(canonical({"ok": False, "error": document}).decode("utf-8"))
    except (ValueError, KeyError, TypeError):
        print(canonical({"ok": False, "error": {"code": "invalid-input-or-filesystem", "path": "command"}}).decode("utf-8"))
    return 1


if __name__ == "__main__":
    sys.exit(main())
