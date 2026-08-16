#!/usr/bin/env python3

from __future__ import annotations

import argparse
import datetime as dt
import gzip
import hashlib
import json
import os
import platform
import re
import stat
import subprocess
import tarfile
import tempfile
from pathlib import Path, PurePosixPath


PACKAGE = "git-vws"
REPOSITORY = "https://github.com/Fuxx-1/git-vws"
LICENSE_FILES = ["README.md", "LICENSE", "LICENSE-MIT", "LICENSE-APACHE"]
TARGETS = {
    "aarch64-apple-darwin": ("Darwin", "arm64"),
    "x86_64-apple-darwin": ("Darwin", "x86_64"),
    "x86_64-unknown-linux-musl": ("Linux", "x86_64"),
}
VERSION_PATTERN = re.compile(
    r"[0-9]+\.[0-9]+\.[0-9]+-[0-9A-Za-z]+(?:[0-9A-Za-z.-]*[0-9A-Za-z])?"
)
SOURCE_SHA_PATTERN = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
FORBIDDEN_MARKERS = [
    "M4CP/1",
    "GIT_VWS_M4_CONTROL_FD",
    "GIT_VWS_M4_NONCE",
    "GIT_VWS_M4_TARGET",
    "m4_checkpoint",
    "object-fetch-returned",
    "cas-child-returned-success",
    "cas-child-returned-nonzero",
    "conflict-aborted-parent-synced",
    "same-return",
    "session-tombstone-renamed",
    "session-tombstone-parent-synced",
    "session-owned-tree-removed",
    "record-deletion-unlinked",
    "record-deletion-parent-synced",
    "session-return",
    "template-tombstoned-record-temporary-synced",
    "template-tombstoned-record-namespace-applied",
    "template-tombstoned-record-exchange-old-unlinked",
    "template-tombstoned-record-parent-synced",
    "template-tombstoned-record",
    "template-tombstone-renamed",
    "template-tombstone-parent-synced",
    "template-owned-tree-removed",
    "template-return",
    "loose-object-unlinked",
    "loose-object-parent-synced",
    "loose-fanout-unlinked",
    "loose-fanout-parent-synced",
    "loose-return",
    "predecessor-tmp-unlinked",
    "predecessor-tmp-parent-synced",
    "predecessor-tmp-removed",
]


def fail(message: str) -> None:
    raise SystemExit(message)


def run(
    argv: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        argv,
        cwd=cwd,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if check and result.returncode != 0:
        fail(
            f"command failed ({result.returncode}): {argv!r}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result


def write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )


def read_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_release_identity(version: str, source_sha: str, epoch: int | None = None) -> None:
    if VERSION_PATTERN.fullmatch(version) is None:
        fail(f"invalid prerelease version: {version}")
    if SOURCE_SHA_PATTERN.fullmatch(source_sha) is None:
        fail(f"invalid source commit digest: {source_sha}")
    if epoch is not None and epoch <= 0:
        fail(f"invalid source date epoch: {epoch}")


def package_prefix(version: str) -> str:
    return f"{PACKAGE}-v{version}"


def archive_name(version: str, target: str) -> str:
    return f"{package_prefix(version)}-{target}.tar.gz"


def sbom_name(version: str) -> str:
    return f"{package_prefix(version)}.spdx.json"


def build_fragment_name(version: str, target: str) -> str:
    return f"{package_prefix(version)}-{target}.build.json"


def expected_release_assets(version: str) -> set[str]:
    archives = {archive_name(version, target) for target in TARGETS}
    checksums = {f"{archive}.sha256" for archive in archives}
    return archives | checksums | {
        "SHA256SUMS",
        sbom_name(version),
        "THIRD-PARTY-LICENSES.txt",
        "BUILD-METADATA.json",
    }


def cargo_metadata(root: Path) -> dict[str, object]:
    output = run(
        ["cargo", "metadata", "--locked", "--format-version", "1"], cwd=root
    ).stdout
    value = json.loads(output)
    if not isinstance(value, dict):
        fail("cargo metadata did not return an object")
    return value


def root_package(metadata: dict[str, object], version: str) -> dict[str, object]:
    packages = metadata.get("packages")
    if not isinstance(packages, list):
        fail("cargo metadata omitted packages")
    roots = [
        package
        for package in packages
        if isinstance(package, dict)
        and package.get("name") == PACKAGE
        and package.get("source") is None
    ]
    if len(roots) != 1 or roots[0].get("version") != version:
        fail(f"Cargo package version does not match {version}")
    return roots[0]


def spdx_id(package: dict[str, object]) -> str:
    identity = str(package.get("id", ""))
    label = re.sub(
        r"[^A-Za-z0-9.-]+",
        "-",
        f"{package.get('name', 'package')}-{package.get('version', 'unknown')}",
    )
    return f"SPDXRef-Package-{label}-{sha256_bytes(identity.encode())[:12]}"


def download_location(package: dict[str, object]) -> str:
    source = package.get("source")
    if not isinstance(source, str):
        return "NOASSERTION"
    for prefix in ("registry+", "git+"):
        if source.startswith(prefix):
            source = source[len(prefix) :]
    return source.split("#", 1)[0]


def create_common(args: argparse.Namespace) -> None:
    validate_release_identity(args.version, args.source_sha, args.epoch)
    root = Path(args.root).resolve()
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    metadata = cargo_metadata(root)
    root_pkg = root_package(metadata, args.version)
    packages = metadata.get("packages")
    resolve = metadata.get("resolve")
    if not isinstance(packages, list) or not isinstance(resolve, dict):
        fail("cargo metadata omitted dependency resolution")

    dependency_packages = sorted(
        (
            package
            for package in packages
            if isinstance(package, dict) and package.get("id") != root_pkg.get("id")
        ),
        key=lambda package: (str(package.get("name")), str(package.get("version"))),
    )
    license_lines = [
        f"Third-party Rust dependencies for {PACKAGE} {args.version}",
        "Generated from Cargo.lock with cargo metadata --locked.",
        "",
    ]
    for package in dependency_packages:
        license_value = package.get("license")
        if not isinstance(license_value, str) or not license_value.strip():
            fail(f"dependency has no declared license: {package.get('name')}")
        license_lines.extend(
            [
                f"{package.get('name')} {package.get('version')}",
                f"  license: {license_value}",
                f"  source: {package.get('source') or 'workspace'}",
                f"  repository: {package.get('repository') or 'NOASSERTION'}",
                "",
            ]
        )
    (output / "THIRD-PARTY-LICENSES.txt").write_text(
        "\n".join(license_lines), encoding="utf-8"
    )

    id_by_package = {
        str(package.get("id")): spdx_id(package)
        for package in packages
        if isinstance(package, dict)
    }
    root_id = id_by_package[str(root_pkg.get("id"))]
    spdx_packages = []
    for package in sorted(
        (package for package in packages if isinstance(package, dict)),
        key=lambda package: (str(package.get("name")), str(package.get("version"))),
    ):
        declared = package.get("license")
        spdx_packages.append(
            {
                "SPDXID": id_by_package[str(package.get("id"))],
                "name": package.get("name"),
                "versionInfo": package.get("version"),
                "downloadLocation": download_location(package),
                "filesAnalyzed": False,
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": declared or "NOASSERTION",
                "copyrightText": "NOASSERTION",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": (
                            f"pkg:cargo/{package.get('name')}@{package.get('version')}"
                        ),
                    }
                ],
            }
        )

    relationships = [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": root_id,
        }
    ]
    nodes = resolve.get("nodes")
    if not isinstance(nodes, list):
        fail("cargo metadata resolve omitted nodes")
    for node in nodes:
        if not isinstance(node, dict):
            continue
        source_id = id_by_package.get(str(node.get("id")))
        deps = node.get("deps")
        if source_id is None or not isinstance(deps, list):
            continue
        for dependency in deps:
            if not isinstance(dependency, dict):
                continue
            target_id = id_by_package.get(str(dependency.get("pkg")))
            if target_id is not None:
                relationships.append(
                    {
                        "spdxElementId": source_id,
                        "relationshipType": "DEPENDS_ON",
                        "relatedSpdxElement": target_id,
                    }
                )

    created = dt.datetime.fromtimestamp(args.epoch, dt.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    sbom = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": package_prefix(args.version),
        "documentNamespace": (
            f"{REPOSITORY}/sbom/{package_prefix(args.version)}/{args.source_sha}"
        ),
        "creationInfo": {
            "created": created,
            "creators": [f"Tool: {PACKAGE}-release.py/1"],
        },
        "packages": spdx_packages,
        "relationships": relationships,
    }
    write_json(output / sbom_name(args.version), sbom)


def command_version(argv: list[str]) -> str:
    result = run(argv)
    return result.stdout.strip() or result.stderr.strip()


def validate_binary(binary: Path, target: str, version: str) -> dict[str, object]:
    if target not in TARGETS:
        fail(f"unsupported release target: {target}")
    metadata = binary.stat()
    if not binary.is_file() or binary.is_symlink() or not metadata.st_mode & stat.S_IXUSR:
        fail(f"release binary is not an executable regular file: {binary}")

    file_output = command_version(["file", "-b", str(binary)])
    system, machine = TARGETS[target]
    if system == "Darwin":
        arch = command_version(["lipo", "-archs", str(binary)])
        if arch != machine:
            fail(f"expected single macOS architecture {machine}, got {arch}")
        if "Mach-O" not in file_output:
            fail(f"macOS binary is not Mach-O: {file_output}")
    else:
        if "ELF" not in file_output or "x86-64" not in file_output:
            fail(f"Linux binary is not x86-64 ELF: {file_output}")
        if "statically linked" not in file_output and "static-pie linked" not in file_output:
            fail(f"Linux musl binary is not static: {file_output}")
        program_headers = command_version(["readelf", "-lW", str(binary)])
        if " INTERP " in program_headers or "Requesting program interpreter" in program_headers:
            fail("Linux musl binary contains a dynamic interpreter")

    scan = run(["strings", str(binary)]).stdout
    symbols = run(["nm", "-a", str(binary)]).stdout
    for marker in FORBIDDEN_MARKERS:
        if marker in scan or marker in symbols:
            fail(f"release binary retains checkpoint marker: {marker}")

    version_result = run([str(binary), "--version"])
    if version_result.stdout.strip() != f"{PACKAGE} {version}" or version_result.stderr:
        fail(f"release binary reported an unexpected version: {version_result!r}")
    path = os.environ.copy()
    path["PATH"] = f"{binary.parent}{os.pathsep}{path.get('PATH', '')}"
    help_result = run(["git", "vws", "-h"], env=path)
    help_text = help_result.stdout + help_result.stderr
    for command in ["init", "create", "list", "exec", "remove", "publish", "doctor", "gc"]:
        if command not in help_text:
            fail(f"git vws help omitted command: {command}")
    return {
        "sha256": sha256_file(binary),
        "size": metadata.st_size,
        "file": file_output,
    }


def tar_info(name: str, mode: int, epoch: int, size: int = 0) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.mode = mode
    info.uid = 0
    info.gid = 0
    info.uname = "root"
    info.gname = "root"
    info.mtime = epoch
    info.size = size
    return info


def create_archive(path: Path, top: str, entries: dict[str, tuple[bytes, int]], epoch: int) -> None:
    with path.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=epoch) as compressed:
            with tarfile.open(
                mode="w", fileobj=compressed, format=tarfile.USTAR_FORMAT
            ) as archive:
                directory = tar_info(top, 0o755, epoch)
                directory.type = tarfile.DIRTYPE
                archive.addfile(directory)
                for name in sorted(entries):
                    payload, mode = entries[name]
                    info = tar_info(f"{top}/{name}", mode, epoch, len(payload))
                    archive.addfile(info, fileobj=io_bytes(payload))


def io_bytes(value: bytes):
    import io

    return io.BytesIO(value)


def create_package(args: argparse.Namespace) -> None:
    validate_release_identity(args.version, args.source_sha, args.epoch)
    root = Path(args.root).resolve()
    output = Path(args.output).resolve()
    common = Path(args.common).resolve()
    binary = Path(args.binary).resolve()
    output.mkdir(parents=True, exist_ok=True)
    root_package(cargo_metadata(root), args.version)
    binary_metadata = validate_binary(binary, args.target, args.version)

    build = {
        "schema": 1,
        "package": PACKAGE,
        "version": args.version,
        "source": {
            "repository": REPOSITORY,
            "commit": args.source_sha,
            "source_date_epoch": args.epoch,
        },
        "target": args.target,
        "runner": {
            "system": platform.system(),
            "machine": platform.machine(),
            "github_runner_os": os.environ.get("RUNNER_OS", "local"),
            "github_runner_arch": os.environ.get("RUNNER_ARCH", "local"),
            "image_os": os.environ.get("ImageOS", "local"),
        },
        "toolchain": {
            "rustc": command_version(["rustc", "--version", "--verbose"]),
            "cargo": command_version(["cargo", "--version"]),
            "git": command_version(["git", "--version"]),
        },
        "binary": {"path": PACKAGE, **binary_metadata},
    }
    fragment = output / build_fragment_name(args.version, args.target)
    write_json(fragment, build)

    entries: dict[str, tuple[bytes, int]] = {PACKAGE: (binary.read_bytes(), 0o755)}
    for name in LICENSE_FILES:
        entries[name] = ((root / name).read_bytes(), 0o644)
    for name in ["THIRD-PARTY-LICENSES.txt", sbom_name(args.version)]:
        entries[name] = ((common / name).read_bytes(), 0o644)
    entries["BUILD-METADATA.json"] = (fragment.read_bytes(), 0o644)

    top = f"{package_prefix(args.version)}-{args.target}"
    archive = output / archive_name(args.version, args.target)
    create_archive(archive, top, entries, args.epoch)
    digest = sha256_file(archive)
    (output / f"{archive.name}.sha256").write_text(
        f"{digest}  {archive.name}\n", encoding="ascii"
    )


def validate_common(directory: Path, version: str, source_sha: str) -> None:
    licenses = directory / "THIRD-PARTY-LICENSES.txt"
    if not licenses.is_file() or "Third-party Rust dependencies" not in licenses.read_text(
        encoding="utf-8"
    ):
        fail("third-party license list is absent or invalid")
    sbom = read_json(directory / sbom_name(version))
    if not isinstance(sbom, dict) or sbom.get("spdxVersion") != "SPDX-2.3":
        fail("release SBOM is not SPDX 2.3")
    if sbom.get("dataLicense") != "CC0-1.0" or not sbom.get("packages"):
        fail("release SBOM omitted packages or document license")
    if sbom.get("name") != package_prefix(version) or sbom.get("documentNamespace") != (
        f"{REPOSITORY}/sbom/{package_prefix(version)}/{source_sha}"
    ):
        fail("release SBOM identity does not match the release source")


def assemble(args: argparse.Namespace) -> None:
    validate_release_identity(args.version, args.source_sha)
    directory = Path(args.directory).resolve()
    validate_common(directory, args.version, args.source_sha)
    builds = []
    for target in TARGETS:
        fragment = directory / build_fragment_name(args.version, target)
        value = read_json(fragment)
        source = value.get("source") if isinstance(value, dict) else None
        if (
            not isinstance(value, dict)
            or value.get("package") != PACKAGE
            or value.get("version") != args.version
            or value.get("target") != target
            or not isinstance(source, dict)
            or source.get("commit") != args.source_sha
        ):
            fail(f"invalid build metadata fragment for {target}")
        archive = directory / archive_name(args.version, target)
        value["archive"] = {
            "name": archive.name,
            "sha256": sha256_file(archive),
            "size": archive.stat().st_size,
        }
        builds.append(value)
    combined = {
        "schema": 1,
        "package": PACKAGE,
        "version": args.version,
        "source_commit": args.source_sha,
        "builds": sorted(builds, key=lambda value: str(value["target"])),
    }
    write_json(directory / "BUILD-METADATA.json", combined)

    lines = []
    for target in sorted(TARGETS):
        archive = directory / archive_name(args.version, target)
        digest = sha256_file(archive)
        checksum = directory / f"{archive.name}.sha256"
        expected = f"{digest}  {archive.name}\n"
        if checksum.read_text(encoding="ascii") != expected:
            fail(f"per-archive checksum is invalid: {checksum.name}")
        lines.append(expected.rstrip("\n"))
    (directory / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="ascii")
    for target in TARGETS:
        (directory / build_fragment_name(args.version, target)).unlink()
    actual = {path.name for path in directory.iterdir() if path.is_file()}
    expected = expected_release_assets(args.version)
    if actual != expected:
        fail(f"assembled asset set mismatch: actual={sorted(actual)} expected={sorted(expected)}")


def safe_member_name(name: str) -> bool:
    path = PurePosixPath(name)
    return bool(name) and not path.is_absolute() and ".." not in path.parts and "\\" not in name


def archive_entries(
    archive_path: Path, version: str, target: str
) -> tuple[dict[str, bytes], dict[str, tarfile.TarInfo]]:
    top = f"{package_prefix(version)}-{target}"
    expected = {
        top,
        *{f"{top}/{name}" for name in [PACKAGE, *LICENSE_FILES]},
        f"{top}/THIRD-PARTY-LICENSES.txt",
        f"{top}/{sbom_name(version)}",
        f"{top}/BUILD-METADATA.json",
    }
    payloads: dict[str, bytes] = {}
    members: dict[str, tarfile.TarInfo] = {}
    with tarfile.open(archive_path, "r:gz") as archive:
        for member in archive.getmembers():
            if not safe_member_name(member.name) or member.name in members:
                fail(f"unsafe or duplicate archive member: {member.name!r}")
            if member.name == top:
                if not member.isdir():
                    fail("archive package root is not a directory")
            elif not member.isreg():
                fail(f"archive contains a non-regular payload: {member.name}")
            members[member.name] = member
            if member.isreg():
                source = archive.extractfile(member)
                if source is None:
                    fail(f"cannot read archive member: {member.name}")
                payloads[member.name] = source.read()
    if set(members) != expected:
        fail(
            f"archive member set mismatch for {target}: "
            f"actual={sorted(members)} expected={sorted(expected)}"
        )
    if members[f"{top}/{PACKAGE}"].mode & 0o777 != 0o755:
        fail("archive binary mode is not 0755")
    return payloads, members


def verify_assets(args: argparse.Namespace) -> None:
    validate_release_identity(args.version, args.source_sha)
    directory = Path(args.directory).resolve()
    actual = {path.name for path in directory.iterdir() if path.is_file()}
    expected = expected_release_assets(args.version)
    if actual != expected:
        fail(f"release asset set mismatch: actual={sorted(actual)} expected={sorted(expected)}")
    validate_common(directory, args.version, args.source_sha)

    sums = []
    archive_payloads: dict[str, dict[str, bytes]] = {}
    for target in sorted(TARGETS):
        archive = directory / archive_name(args.version, target)
        digest = sha256_file(archive)
        expected_line = f"{digest}  {archive.name}"
        checksum = (directory / f"{archive.name}.sha256").read_text(
            encoding="ascii"
        )
        if checksum != expected_line + "\n":
            fail(f"checksum file does not match archive: {archive.name}")
        sums.append(expected_line)
        payloads, _ = archive_entries(archive, args.version, target)
        top = f"{package_prefix(args.version)}-{target}"
        if payloads[f"{top}/THIRD-PARTY-LICENSES.txt"] != (
            directory / "THIRD-PARTY-LICENSES.txt"
        ).read_bytes():
            fail(f"archive license list drifted for {target}")
        if payloads[f"{top}/{sbom_name(args.version)}"] != (
            directory / sbom_name(args.version)
        ).read_bytes():
            fail(f"archive SBOM drifted for {target}")
        archive_payloads[target] = payloads
    if (directory / "SHA256SUMS").read_text(encoding="ascii") != "\n".join(sums) + "\n":
        fail("combined checksum manifest is invalid")

    combined = read_json(directory / "BUILD-METADATA.json")
    if (
        not isinstance(combined, dict)
        or combined.get("schema") != 1
        or combined.get("package") != PACKAGE
        or combined.get("version") != args.version
        or combined.get("source_commit") != args.source_sha
    ):
        fail("combined build metadata header is invalid")
    builds = combined.get("builds")
    if not isinstance(builds, list) or len(builds) != len(TARGETS):
        fail("combined build metadata omitted targets")
    by_target = {
        str(build.get("target")): build for build in builds if isinstance(build, dict)
    }
    if set(by_target) != set(TARGETS):
        fail("combined build metadata target set is invalid")
    for target, build in by_target.items():
        archive = directory / archive_name(args.version, target)
        archive_meta = build.get("archive")
        binary_meta = build.get("binary")
        if not isinstance(archive_meta, dict) or not isinstance(binary_meta, dict):
            fail(f"build metadata is incomplete for {target}")
        if archive_meta.get("sha256") != sha256_file(archive):
            fail(f"build metadata archive digest drifted for {target}")
        top = f"{package_prefix(args.version)}-{target}"
        payload = archive_payloads[target][f"{top}/{PACKAGE}"]
        if binary_meta.get("sha256") != sha256_bytes(payload):
            fail(f"build metadata binary digest drifted for {target}")
        embedded = json.loads(
            archive_payloads[target][f"{top}/BUILD-METADATA.json"].decode("utf-8")
        )
        if embedded.get("target") != target or embedded.get("source", {}).get(
            "commit"
        ) != args.source_sha:
            fail(f"embedded build metadata drifted for {target}")

    selected = args.target
    if selected not in TARGETS:
        fail(f"unsupported verification target: {selected}")
    expected_system, expected_machine = TARGETS[selected]
    if platform.system() != expected_system or platform.machine() != expected_machine:
        fail(
            f"verification runner mismatch for {selected}: "
            f"{platform.system()}/{platform.machine()}"
        )
    top = f"{package_prefix(args.version)}-{selected}"
    with tempfile.TemporaryDirectory(prefix="git-vws-release-") as temporary:
        root = Path(temporary) / top
        root.mkdir(mode=0o755)
        for name, payload in archive_payloads[selected].items():
            if name == top:
                continue
            destination = Path(temporary) / name
            destination.write_bytes(payload)
            destination.chmod(0o755 if destination.name == PACKAGE else 0o644)
        validate_binary(root / PACKAGE, selected, args.version)
        for name in LICENSE_FILES:
            if not (root / name).is_file():
                fail(f"release archive omitted {name}")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    subcommands = result.add_subparsers(dest="command", required=True)

    common = subcommands.add_parser("common")
    common.add_argument("--root", default=".")
    common.add_argument("--output", required=True)
    common.add_argument("--version", required=True)
    common.add_argument("--source-sha", required=True)
    common.add_argument("--epoch", required=True, type=int)
    common.set_defaults(function=create_common)

    package = subcommands.add_parser("package")
    package.add_argument("--root", default=".")
    package.add_argument("--output", required=True)
    package.add_argument("--common", required=True)
    package.add_argument("--version", required=True)
    package.add_argument("--source-sha", required=True)
    package.add_argument("--epoch", required=True, type=int)
    package.add_argument("--target", required=True)
    package.add_argument("--binary", required=True)
    package.set_defaults(function=create_package)

    assembled = subcommands.add_parser("assemble")
    assembled.add_argument("--directory", required=True)
    assembled.add_argument("--version", required=True)
    assembled.add_argument("--source-sha", required=True)
    assembled.set_defaults(function=assemble)

    verify = subcommands.add_parser("verify")
    verify.add_argument("--directory", required=True)
    verify.add_argument("--version", required=True)
    verify.add_argument("--source-sha", required=True)
    verify.add_argument("--target", required=True)
    verify.set_defaults(function=verify_assets)
    return result


def main() -> None:
    args = parser().parse_args()
    args.function(args)


if __name__ == "__main__":
    main()
