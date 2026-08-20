#!/usr/bin/env python3

from __future__ import annotations

import argparse
import base64
import binascii
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
CI_WORKFLOW = ".github/workflows/ci.yml"
PROVENANCE_BUNDLE = "PROVENANCE.sigstore.json"
REMOTE_MANIFEST_SCHEMA = 1
IN_TOTO_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
SLSA_PROVENANCE_TYPE = "https://slsa.dev/provenance/v1"
LICENSE_FILES = ["README.md", "LICENSE"]
TARGETS = {
    "aarch64-apple-darwin": ("Darwin", "arm64"),
    "x86_64-apple-darwin": ("Darwin", "x86_64"),
    "x86_64-unknown-linux-musl": ("Linux", "x86_64"),
}
VERSION_PATTERN = re.compile(
    r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z]+(?:[0-9A-Za-z.-]*[0-9A-Za-z])?)?"
)
SOURCE_SHA_PATTERN = re.compile(r"[0-9a-f]{40}")
GIT_OBJECT_SHA_PATTERN = re.compile(r"[0-9a-f]{40}")
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
GITHUB_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
RFC3339_PATTERN = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z"
)
CI_JOB_NAMES = (
    "Quality",
    "Linux musl release build",
    "macOS APFS (aarch64-apple-darwin)",
    "macOS APFS (x86_64-apple-darwin)",
    "Linux XFS FICLONE/FIEMAP",
)
SIGNER_PLACEHOLDER = "__" + "SIGNER_SHA" + "__"
REMOTE_MANIFEST_KEYS = {
    "assets",
    "draft",
    "prerelease",
    "repository",
    "repository_id",
    "release_id",
    "run_attempt",
    "run_id",
    "schema",
    "source_sha",
    "tag",
    "version",
}
REMOTE_ASSET_KEYS = {"digest", "id", "name", "size", "state", "updated_at"}
REPOSITORY_SLUG = "Fuxx-1/git-vws"
RUNTIME_TOKEN_ENV_NAMES = {
    "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
    "ACTIONS_ID_TOKEN_REQUEST_URL",
    "ACTIONS_RUNTIME_TOKEN",
    "GH_ENTERPRISE_TOKEN",
    "GH_TOKEN",
    "GITHUB_APP_TOKEN",
    "GITHUB_TOKEN",
    "RUNNER_TOKEN",
}
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
        fail(f"invalid release version: {version}")
    if SOURCE_SHA_PATTERN.fullmatch(source_sha) is None:
        fail(f"invalid source commit digest: {source_sha}")
    if epoch is not None and epoch <= 0:
        fail(f"invalid source date epoch: {epoch}")


def is_prerelease(version: str) -> bool:
    return "-" in version


def package_prefix(version: str) -> str:
    return f"{PACKAGE}-v{version}"


def archive_name(version: str, target: str) -> str:
    return f"{package_prefix(version)}-{target}.tar.gz"


def sbom_name(version: str) -> str:
    return f"{package_prefix(version)}.spdx.json"


def build_fragment_name(version: str, target: str) -> str:
    return f"{package_prefix(version)}-{target}.build.json"


def expected_unsigned_release_assets(version: str) -> set[str]:
    archives = {archive_name(version, target) for target in TARGETS}
    checksums = {f"{archive}.sha256" for archive in archives}
    return archives | checksums | {
        "SHA256SUMS",
        sbom_name(version),
        "THIRD-PARTY-LICENSES.txt",
        "BUILD-METADATA.json",
    }


def expected_release_assets(version: str) -> set[str]:
    return expected_unsigned_release_assets(version) | {PROVENANCE_BUNDLE}


def checksum_manifest_assets(version: str) -> set[str]:
    return expected_unsigned_release_assets(version) - {"SHA256SUMS"}


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

    with tempfile.TemporaryDirectory(prefix="git-vws-release-home-") as home:
        safe_env = {
            "PATH": f"{binary.parent}{os.pathsep}{os.environ.get('PATH', os.defpath)}",
            "HOME": home,
            "TMPDIR": home,
            "LANG": "C",
            "LC_ALL": "C",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_PAGER": "cat",
            "PAGER": "cat",
        }
        for name in RUNTIME_TOKEN_ENV_NAMES:
            if name in safe_env:
                fail(f"release binary environment retained a runtime token: {name}")
        version_result = run([str(binary), "--version"], cwd=Path(home), env=safe_env)
        if version_result.stdout.strip() != f"{PACKAGE} {version}" or version_result.stderr:
            fail(f"release binary reported an unexpected version: {version_result!r}")
        help_result = run(["git", "vws", "-h"], cwd=Path(home), env=safe_env)
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


def require_mapping(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        fail(f"{label} must be an object")
    return value


def require_positive_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        fail(f"{label} must be a positive integer")
    return value


def require_nonnegative_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        fail(f"{label} must be a non-negative integer")
    return value


def require_bool(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        fail(f"{label} must be a boolean")
    return value


def require_string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        fail(f"{label} must be a nonempty string")
    return value


def require_decimal(value: object, label: str) -> str:
    value = require_string(value, label)
    if not value.isdecimal() or int(value) <= 0:
        fail(f"{label} must be a positive decimal identifier")
    return value


def require_sha256(value: object, label: str) -> str:
    value = require_string(value, label)
    if SHA256_PATTERN.fullmatch(value) is None:
        fail(f"{label} must be a lowercase SHA-256 digest")
    return value


def require_source_sha(value: object, label: str) -> str:
    value = require_string(value, label)
    if SOURCE_SHA_PATTERN.fullmatch(value) is None:
        fail(f"{label} must be a Git object identifier")
    return value


def require_git_object_sha(value: object, label: str) -> str:
    value = require_string(value, label)
    if GIT_OBJECT_SHA_PATTERN.fullmatch(value) is None:
        fail(f"{label} must be a 40-character Git object identifier")
    return value


def require_regular_file(path: Path, label: str) -> None:
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        fail(f"{label} is absent: {path}")
    if not stat.S_ISREG(mode):
        fail(f"{label} is not a regular file: {path}")


def release_files(directory: Path, label: str) -> set[str]:
    if not directory.is_dir():
        fail(f"{label} is not a directory: {directory}")
    names = set()
    for path in directory.iterdir():
        require_regular_file(path, f"{label} member")
        names.add(path.name)
    return names


def reject_duplicate_json_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            fail(f"canonical JSON contains duplicate key: {key}")
        result[key] = value
    return result


def read_canonical_json(path: Path, label: str) -> object:
    require_regular_file(path, label)
    raw = path.read_bytes()
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicate_json_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"{label} is not valid JSON: {error}")
    canonical = json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    if raw != canonical.encode("utf-8"):
        fail(f"{label} is not canonical JSON")
    return value


def release_identity(args: argparse.Namespace) -> dict[str, object]:
    validate_release_identity(args.version, args.source_sha)
    if args.repository != REPOSITORY_SLUG:
        fail(f"release repository is invalid: {args.repository}")
    return {
        "repository": args.repository,
        "repository_id": require_decimal(args.repository_id, "release repository id"),
        "run_id": require_decimal(args.run_id, "release workflow run id"),
        "schema": REMOTE_MANIFEST_SCHEMA,
        "source_sha": args.source_sha,
        "tag": f"v{args.version}",
        "version": args.version,
    }


def snapshot_identity(args: argparse.Namespace, run_attempt: object) -> dict[str, object]:
    return {
        **release_identity(args),
        "run_attempt": require_decimal(run_attempt, "release workflow run attempt"),
    }


def normalize_remote_assets(value: object, version: str) -> list[dict[str, object]]:
    if not isinstance(value, list):
        fail("release assets must be an array")
    expected_names = expected_release_assets(version)
    by_name: dict[str, dict[str, object]] = {}
    asset_ids: set[int] = set()
    for raw_asset in value:
        asset = require_mapping(raw_asset, "release asset")
        asset_id = require_positive_int(asset.get("id"), "release asset id")
        if asset_id in asset_ids:
            fail(f"release assets duplicate id: {asset_id}")
        asset_ids.add(asset_id)
        name = require_string(asset.get("name"), "release asset name")
        if name in by_name:
            fail(f"release assets duplicate name: {name}")
        if name not in expected_names:
            fail(f"release assets contain an unexpected member: {name}")
        size = require_nonnegative_int(asset.get("size"), f"release asset {name} size")
        digest = require_string(asset.get("digest"), f"release asset {name} digest")
        if GITHUB_DIGEST_PATTERN.fullmatch(digest) is None:
            fail(f"release asset {name} digest is not a lowercase GitHub SHA-256")
        updated_at = require_string(asset.get("updated_at"), f"release asset {name} update")
        validate_timestamp(updated_at, f"release asset {name} update")
        if asset.get("state") != "uploaded":
            fail(f"release asset {name} is not uploaded")
        by_name[name] = {
            "digest": digest,
            "id": asset_id,
            "name": name,
            "size": size,
            "state": "uploaded",
            "updated_at": updated_at,
        }
    if set(by_name) != expected_names:
        fail(
            "release asset set mismatch: "
            f"actual={sorted(by_name)} expected={sorted(expected_names)}"
        )
    return [by_name[name] for name in sorted(by_name)]


def remote_release_manifest(
    release: object,
    args: argparse.Namespace,
    *,
    draft: bool,
    prerelease: bool,
    run_attempt: object,
) -> dict[str, object]:
    value = require_mapping(release, "GitHub release")
    if value.get("tag_name") != f"v{args.version}":
        fail("GitHub release tag does not match the release version")
    if (
        require_bool(value.get("draft"), "GitHub release draft") is not draft
        or require_bool(value.get("prerelease"), "GitHub release prerelease")
        is not prerelease
    ):
        fail("GitHub release state does not match the expected promotion state")
    return {
        **snapshot_identity(args, run_attempt),
        "assets": normalize_remote_assets(value.get("assets"), args.version),
        "draft": draft,
        "prerelease": prerelease,
        "release_id": require_positive_int(value.get("id"), "GitHub release id"),
    }


def validate_remote_manifest(
    value: object, args: argparse.Namespace
) -> dict[str, object]:
    manifest = require_mapping(value, "release snapshot manifest")
    if set(manifest) != REMOTE_MANIFEST_KEYS:
        fail("release snapshot manifest keys are invalid")
    if (
        require_positive_int(manifest.get("schema"), "release snapshot schema")
        != REMOTE_MANIFEST_SCHEMA
    ):
        fail("release snapshot manifest schema is invalid")
    expected_identity = release_identity(args)
    for key, expected in expected_identity.items():
        if key == "schema":
            continue
        if manifest.get(key) != expected:
            fail(f"release snapshot manifest {key} is invalid")
    run_attempt = require_decimal(
        manifest.get("run_attempt"), "release snapshot workflow run attempt"
    )
    if manifest.get("draft") is not True or manifest.get("prerelease") is not False:
        fail("release snapshot manifest is not a draft release candidate")
    release_id = require_positive_int(manifest.get("release_id"), "release snapshot id")
    raw_assets = manifest.get("assets")
    if not isinstance(raw_assets, list) or any(
        not isinstance(asset, dict) or set(asset) != REMOTE_ASSET_KEYS
        for asset in raw_assets
    ):
        fail("release snapshot manifest asset keys are invalid")
    assets = normalize_remote_assets(raw_assets, args.version)
    if raw_assets != assets:
        fail("release snapshot manifest assets are not in canonical name order")
    return {
        **expected_identity,
        "assets": assets,
        "draft": True,
        "prerelease": False,
        "release_id": release_id,
        "run_attempt": run_attempt,
    }


def validate_snapshot_assets(directory: Path, manifest: dict[str, object]) -> None:
    names = release_files(directory, "release snapshot assets")
    assets = manifest["assets"]
    if not isinstance(assets, list):
        fail("release snapshot manifest assets are invalid")
    by_name = {
        str(asset["name"]): asset
        for asset in assets
        if isinstance(asset, dict) and isinstance(asset.get("name"), str)
    }
    if names != set(by_name):
        fail(
            "release snapshot files do not match the manifest: "
            f"actual={sorted(names)} expected={sorted(by_name)}"
        )
    for name, asset in by_name.items():
        path = directory / name
        if path.stat().st_size != asset["size"]:
            fail(f"release snapshot asset size drifted: {name}")
        if f"sha256:{sha256_file(path)}" != asset["digest"]:
            fail(f"release snapshot asset digest drifted: {name}")


def snapshot_release(args: argparse.Namespace) -> None:
    manifest = remote_release_manifest(
        read_json(Path(args.release)),
        args,
        draft=True,
        prerelease=False,
        run_attempt=args.run_attempt,
    )
    validate_snapshot_assets(Path(args.assets), manifest)
    write_json(Path(args.output), manifest)


def emit_release_assets(args: argparse.Namespace) -> None:
    manifest = remote_release_manifest(
        read_json(Path(args.release)),
        args,
        draft=True,
        prerelease=False,
        run_attempt=args.run_attempt,
    )
    assets = manifest["assets"]
    if not isinstance(assets, list):
        fail("release asset manifest is invalid")
    for asset in assets:
        print(f"{asset['id']}\t{asset['name']}")


def verify_release_snapshot(args: argparse.Namespace) -> None:
    manifest = validate_remote_manifest(
        read_canonical_json(Path(args.manifest), "release snapshot manifest"), args
    )
    validate_snapshot_assets(Path(args.assets), manifest)
    if args.release is not None:
        expected_draft = not args.promoted
        expected_prerelease = args.promoted and is_prerelease(args.version)
        live = remote_release_manifest(
            read_json(Path(args.release)),
            args,
            draft=expected_draft,
            prerelease=expected_prerelease,
            run_attempt=manifest["run_attempt"],
        )
        expected = {**manifest, "draft": expected_draft, "prerelease": expected_prerelease}
        if live != expected:
            fail("GitHub release no longer matches the verified draft snapshot")


def validate_timestamp(value: object, label: str) -> dt.datetime:
    value = require_string(value, label)
    if RFC3339_PATTERN.fullmatch(value) is None:
        fail(f"{label} is not a UTC RFC3339 timestamp")
    try:
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        fail(f"{label} is not a valid timestamp: {error}")


def validate_ci_jobs(value: object, label: str) -> list[dict[str, object]]:
    if not isinstance(value, list) or len(value) != len(CI_JOB_NAMES):
        fail(f"{label} must contain exactly five CI jobs")
    by_name: dict[str, dict[str, object]] = {}
    for item in value:
        job = require_mapping(item, f"{label} job")
        name = require_string(job.get("name"), f"{label} job name")
        if name in by_name:
            fail(f"{label} contains duplicate CI job {name}")
        require_decimal(job.get("id"), f"{label} {name} id")
        if job.get("conclusion") != "success":
            fail(f"{label} {name} did not succeed")
        started = validate_timestamp(job.get("startedAt"), f"{label} {name} start")
        completed = validate_timestamp(job.get("completedAt"), f"{label} {name} completion")
        if completed < started:
            fail(f"{label} {name} completed before it started")
        labels = job.get("runnerLabels")
        if not isinstance(labels, list) or not labels:
            fail(f"{label} {name} omitted runner labels")
        if any(not isinstance(item, str) or not item for item in labels):
            fail(f"{label} {name} has invalid runner labels")
        if len(set(labels)) != len(labels):
            fail(f"{label} {name} has duplicate runner labels")
        by_name[name] = job
    if set(by_name) != set(CI_JOB_NAMES):
        fail(f"{label} CI job set is invalid")
    return [by_name[name] for name in CI_JOB_NAMES]


def validate_pretag_evidence(
    value: object,
    source_sha: str,
    expected_run_id: str | None = None,
    expected_run_attempt: str | None = None,
) -> dict[str, object]:
    evidence = require_mapping(value, "pre-tag CI evidence")
    if evidence.get("workflowPath") != CI_WORKFLOW:
        fail("pre-tag CI workflow path is invalid")
    run = require_mapping(evidence.get("run"), "pre-tag CI run")
    run_id = require_decimal(run.get("id"), "pre-tag CI run id")
    run_attempt = require_decimal(run.get("attempt"), "pre-tag CI run attempt")
    if expected_run_id is not None and run_id != expected_run_id:
        fail("pre-tag CI run id does not match the annotated tag")
    if expected_run_attempt is not None and run_attempt != expected_run_attempt:
        fail("pre-tag CI attempt does not match the annotated tag")
    if run.get("headSha") != source_sha:
        fail("pre-tag CI source commit is invalid")
    if run.get("event") != "push" or run.get("ref") != "refs/heads/main":
        fail("pre-tag CI must be the main push workflow")
    if run.get("conclusion") != "success":
        fail("pre-tag CI workflow did not succeed")
    return {
        "workflowPath": CI_WORKFLOW,
        "run": {
            "id": run_id,
            "attempt": run_attempt,
            "headSha": source_sha,
            "event": "push",
            "ref": "refs/heads/main",
            "conclusion": "success",
        },
        "jobs": validate_ci_jobs(evidence.get("jobs"), "pre-tag CI"),
    }


def decode_base64_field(value: object, label: str) -> bytes:
    if not isinstance(value, str) or not value:
        fail(f"Sigstore bundle omitted {label}")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as error:
        fail(f"Sigstore bundle has invalid {label}: {error}")
    if not decoded:
        fail(f"Sigstore bundle has empty {label}")
    return decoded


def validate_public_provenance_bundle(
    args: argparse.Namespace, directory: Path
) -> None:
    bundle = read_json(directory / PROVENANCE_BUNDLE)
    if not isinstance(bundle, dict) or bundle.get("mediaType") != (
        "application/vnd.dev.sigstore.bundle.v0.3+json"
    ):
        fail("Sigstore provenance bundle media type is invalid")
    material = require_mapping(bundle.get("verificationMaterial"), "Sigstore material")
    if "publicKey" in material:
        fail("public Sigstore provenance must be certificate-backed")
    certificate = require_mapping(
        material.get("certificate"), "Sigstore signing certificate"
    )
    certificate_der = decode_base64_field(
        certificate.get("rawBytes"), "Sigstore signing certificate"
    )
    if certificate_der[0] != 0x30:
        fail("Sigstore signing certificate is not DER")
    entries = material.get("tlogEntries")
    if not isinstance(entries, list) or not entries:
        fail("public Sigstore provenance omitted transparency-log evidence")

    envelope = require_mapping(bundle.get("dsseEnvelope"), "DSSE envelope")
    if envelope.get("payloadType") != "application/vnd.in-toto+json":
        fail("Sigstore provenance bundle omitted in-toto DSSE envelope")
    signatures = envelope.get("signatures")
    if not isinstance(signatures, list) or len(signatures) != 1:
        fail("Sigstore provenance bundle must contain exactly one DSSE signature")
    signature = require_mapping(signatures[0], "DSSE signature")
    decode_base64_field(signature.get("sig"), "DSSE signature")
    payload = decode_base64_field(envelope.get("payload"), "DSSE payload")
    try:
        statement = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"Sigstore provenance statement is invalid: {error}")
    statement = require_mapping(statement, "SLSA statement")
    if statement.get("_type") != IN_TOTO_STATEMENT_TYPE:
        fail("SLSA statement type is invalid")
    if statement.get("predicateType") != SLSA_PROVENANCE_TYPE:
        fail("SLSA predicate type is invalid")
    subjects = statement.get("subject")
    if not isinstance(subjects, list):
        fail("SLSA statement omitted subjects")
    actual: dict[str, str] = {}
    for value in subjects:
        subject = require_mapping(value, "SLSA subject")
        name = require_string(subject.get("name"), "SLSA subject name")
        basename = PurePosixPath(name).name
        digest = require_mapping(subject.get("digest"), "SLSA subject digest")
        sha256 = require_sha256(digest.get("sha256"), "SLSA subject SHA-256")
        if basename in actual:
            fail(f"SLSA statement duplicated subject {basename}")
        actual[basename] = sha256
    expected = {
        name: sha256_file(directory / name)
        for name in expected_unsigned_release_assets(args.version)
    }
    if actual != expected:
        fail(
            "SLSA subjects do not match the unsigned release closure: "
            f"actual={sorted(actual)} expected={sorted(expected)}"
        )


def verify_public_provenance(args: argparse.Namespace) -> None:
    validate_release_identity(args.version, args.source_sha)
    directory = Path(args.directory).resolve()
    actual = release_files(directory, "signed release asset directory")
    expected = expected_release_assets(args.version)
    if actual != expected:
        fail(
            "release provenance asset set mismatch: "
            f"actual={sorted(actual)} expected={sorted(expected)}"
        )
    validate_public_provenance_bundle(args, directory)


def validate_pretag(args: argparse.Namespace) -> None:
    validate_release_identity(args.version, args.source_sha)
    require_decimal(args.pretag_run_id, "annotated pre-tag run id")
    require_decimal(args.pretag_run_attempt, "annotated pre-tag run attempt")
    canonical = validate_pretag_evidence(
        read_json(Path(args.input)),
        args.source_sha,
        args.pretag_run_id,
        args.pretag_run_attempt,
    )
    write_json(Path(args.output), canonical)


def validate_tag(args: argparse.Namespace) -> None:
    validate_release_identity(args.version, args.source_sha)
    if args.tag_ref != f"refs/tags/v{args.version}":
        fail(f"release tag ref does not match version: {args.tag_ref}")
    tag_object_sha = require_git_object_sha(
        args.tag_object_sha, "annotated tag object SHA"
    )
    annotation_path = Path(args.annotation)
    require_regular_file(annotation_path, "annotated tag message")
    try:
        annotation = annotation_path.read_text(encoding="ascii")
    except UnicodeDecodeError as error:
        fail(f"annotated tag message is not ASCII: {error}")
    if annotation.endswith("\n"):
        annotation = annotation[:-1]
    fields = {}
    for line in annotation.split("\n"):
        if "=" in line:
            key, value = line.split("=", 1)
            if key in fields:
                fail(f"annotated tag duplicated {key}")
            fields[key] = value
    pretag_run_id = require_decimal(fields.get("pretag_run_id"), "annotated pre-tag run id")
    pretag_run_attempt = require_decimal(
        fields.get("pretag_run_attempt"), "annotated pre-tag run attempt"
    )
    expected = "\n".join(
        [
            "git-vws release",
            f"version=v{args.version}",
            f"source_commit={args.source_sha}",
            f"pretag_run_id={pretag_run_id}",
            f"pretag_run_attempt={pretag_run_attempt}",
        ]
    )
    if annotation != expected:
        fail("annotated tag message is not the exact release contract")
    workflow_path = Path(args.workflow_file)
    require_regular_file(workflow_path, "release workflow")
    workflow = workflow_path.read_text(encoding="utf-8")
    if workflow.count(SIGNER_PLACEHOLDER) != 0:
        if workflow.count(SIGNER_PLACEHOLDER) != 1:
            fail("release signer placeholder must occur exactly once")
        fail(
            "HOST_SETUP_REQUIRED: replace the release signer anchor placeholder "
            "with the first immutable signer commit SHA"
        )
    matches = re.findall(
        r"^\s*uses:\s*Fuxx-1/git-vws/\.github/workflows/release-sign\.yml@([^\s#]+)\s*$",
        workflow,
        flags=re.MULTILINE,
    )
    if len(matches) != 1 or GIT_OBJECT_SHA_PATTERN.fullmatch(matches[0]) is None:
        fail("release signer workflow must be pinned to one complete commit SHA")
    write_json(
        Path(args.output),
        {
            "version": args.version,
            "source_sha": args.source_sha,
            "tag_ref": args.tag_ref,
            "tag_object_sha": tag_object_sha,
            "pretag_run_id": pretag_run_id,
            "pretag_run_attempt": pretag_run_attempt,
            "signer_workflow_sha": matches[0],
        },
    )


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

    for target in sorted(TARGETS):
        archive = directory / archive_name(args.version, target)
        digest = sha256_file(archive)
        checksum = directory / f"{archive.name}.sha256"
        expected = f"{digest}  {archive.name}\n"
        if checksum.read_text(encoding="ascii") != expected:
            fail(f"per-archive checksum is invalid: {checksum.name}")
    for target in TARGETS:
        (directory / build_fragment_name(args.version, target)).unlink()
    actual = {path.name for path in directory.iterdir() if path.is_file()}
    checksum_assets = checksum_manifest_assets(args.version)
    if actual != checksum_assets:
        fail(
            "pre-checksum asset set mismatch: "
            f"actual={sorted(actual)} expected={sorted(checksum_assets)}"
        )
    lines = [
        f"{sha256_file(directory / name)}  {name}"
        for name in sorted(checksum_assets)
    ]
    (directory / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="ascii")
    actual = {path.name for path in directory.iterdir() if path.is_file()}
    expected = expected_unsigned_release_assets(args.version)
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
    actual = release_files(directory, "signed release asset directory")
    expected = expected_release_assets(args.version)
    if actual != expected:
        fail(f"release asset set mismatch: actual={sorted(actual)} expected={sorted(expected)}")
    validate_common(directory, args.version, args.source_sha)

    expected_sums = [
        f"{sha256_file(directory / name)}  {name}"
        for name in sorted(checksum_manifest_assets(args.version))
    ]
    if (directory / "SHA256SUMS").read_text(encoding="ascii") != (
        "\n".join(expected_sums) + "\n"
    ):
        fail("combined checksum manifest is invalid")

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

    validate_public_provenance_bundle(args, directory)

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

    provenance_verify = subcommands.add_parser("verify-provenance")
    provenance_verify.add_argument("--directory", required=True)
    provenance_verify.add_argument("--version", required=True)
    provenance_verify.add_argument("--source-sha", required=True)
    provenance_verify.set_defaults(function=verify_public_provenance)

    snapshot = subcommands.add_parser("snapshot-release")
    snapshot.add_argument("--release", required=True)
    snapshot.add_argument("--assets", required=True)
    snapshot.add_argument("--output", required=True)
    snapshot.add_argument("--repository", required=True)
    snapshot.add_argument("--repository-id", required=True)
    snapshot.add_argument("--run-id", required=True)
    snapshot.add_argument("--run-attempt", required=True)
    snapshot.add_argument("--version", required=True)
    snapshot.add_argument("--source-sha", required=True)
    snapshot.set_defaults(function=snapshot_release)

    snapshot_assets = subcommands.add_parser("release-assets")
    snapshot_assets.add_argument("--release", required=True)
    snapshot_assets.add_argument("--repository", required=True)
    snapshot_assets.add_argument("--repository-id", required=True)
    snapshot_assets.add_argument("--run-id", required=True)
    snapshot_assets.add_argument("--run-attempt", required=True)
    snapshot_assets.add_argument("--version", required=True)
    snapshot_assets.add_argument("--source-sha", required=True)
    snapshot_assets.set_defaults(function=emit_release_assets)

    snapshot_verify = subcommands.add_parser("verify-release-snapshot")
    snapshot_verify.add_argument("--manifest", required=True)
    snapshot_verify.add_argument("--assets", required=True)
    snapshot_verify.add_argument("--release")
    snapshot_verify.add_argument("--promoted", action="store_true")
    snapshot_verify.add_argument("--repository", required=True)
    snapshot_verify.add_argument("--repository-id", required=True)
    snapshot_verify.add_argument("--run-id", required=True)
    snapshot_verify.add_argument("--version", required=True)
    snapshot_verify.add_argument("--source-sha", required=True)
    snapshot_verify.set_defaults(function=verify_release_snapshot)

    pretag = subcommands.add_parser("validate-pretag")
    pretag.add_argument("--input", required=True)
    pretag.add_argument("--output", required=True)
    pretag.add_argument("--version", required=True)
    pretag.add_argument("--source-sha", required=True)
    pretag.add_argument("--pretag-run-id", required=True)
    pretag.add_argument("--pretag-run-attempt", required=True)
    pretag.set_defaults(function=validate_pretag)

    tag = subcommands.add_parser("validate-tag")
    tag.add_argument("--version", required=True)
    tag.add_argument("--source-sha", required=True)
    tag.add_argument("--tag-ref", required=True)
    tag.add_argument("--tag-object-sha", required=True)
    tag.add_argument("--annotation", required=True)
    tag.add_argument("--workflow-file", required=True)
    tag.add_argument("--output", required=True)
    tag.set_defaults(function=validate_tag)

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
