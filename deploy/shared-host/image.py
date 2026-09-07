#!/usr/bin/env python3
"""Build the existing image from a verified checkout and record immutable inputs."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
ASSETS = ROOT / "deploy/shared-host"
BASES = {
    "FFMPEG_IMAGE": "gtstef/ffmpeg:8.1-decode",
    "GO_IMAGE": "golang:alpine",
    "NODE_IMAGE": "node:jod-slim",
    "RUNTIME_IMAGE": "alpine:latest",
}
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


def checked_registry(registry: str) -> None:
    """Accept a Docker registry authority, never a URL or credential-bearing text."""
    host, separator, port = registry.partition(":")
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", host):
        raise ValueError("invalid registry authority")
    if any(not label or label.startswith("-") or label.endswith("-") for label in host.split(".")):
        raise ValueError("invalid registry authority")
    if separator and (not re.fullmatch(r"[0-9]{1,5}", port) or not 1 <= int(port) <= 65535):
        raise ValueError("invalid registry port")
    if "." not in host and not separator and host != "localhost":
        raise ValueError("registry must be an explicit hostname or host:port")


def checked_reference(reference: str, *, require_tag: bool = False,
                      allow_digest: bool = True) -> tuple[str, str]:
    """Validate before subprocesses can echo bad input in errors or logs."""
    if not isinstance(reference, str) or len(reference) > 512 or not re.fullmatch(r"[A-Za-z0-9_./:@-]+", reference):
        raise ValueError("invalid image reference")
    name, separator, digest = reference.partition("@")
    if separator and (not allow_digest or not DIGEST.fullmatch(digest)):
        raise ValueError("image reference contains an unsupported digest or credential syntax")
    last = name.rsplit("/", 1)[-1]
    if ":" in last:
        repository, _, tag = name.rpartition(":")
        if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}", tag):
            raise ValueError("invalid image tag")
    else:
        repository, tag = name, ""
    if require_tag and (not tag or separator):
        raise ValueError("publication target must have an explicit tag, without a digest")
    components = repository.split("/")
    registry = ""
    if len(components) > 1 and ("." in components[0] or ":" in components[0] or components[0] == "localhost"):
        registry = components.pop(0)
        checked_registry(registry)
    if not components or any(not re.fullmatch(r"[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*", part) for part in components):
        raise ValueError("invalid image repository")
    return registry, repository


def run(*args: str, capture: bool = True, env: dict | None = None) -> str:
    result = subprocess.run(args, cwd=ROOT, env=env, check=True, text=True,
                            stdout=subprocess.PIPE if capture else None)
    return (result.stdout or "").strip()


def checked_source(revision: str) -> None:
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("source SHA must be a full lowercase commit SHA")
    if run("git", "rev-parse", "HEAD") != revision:
        raise ValueError("checkout HEAD does not match the approved source SHA")
    if run("git", "status", "--porcelain=v1", "--untracked-files=all"):
        raise ValueError("build requires a clean fixed checkout")
    if run("git", "remote", "get-url", "origin").removesuffix(".git") != (
        "https://github.com/Tangbohu09527/CF_filebrowser-enterprise"
    ):
        raise ValueError("origin is not the approved product repository")


def evidence_directory(path: Path) -> None:
    path = path.absolute()
    if path == ROOT or ROOT in path.parents:
        raise ValueError("evidence must be outside the source checkout")
    for parent in (path, *path.parents):
        if parent.is_symlink():
            raise ValueError("evidence path must not contain symbolic links")
    path.mkdir(mode=0o700, parents=True, exist_ok=False)


def image_info(reference: str) -> dict:
    return json.loads(run("docker", "image", "inspect", reference))[0]


def write_record(directory: Path, record: dict) -> None:
    with (directory / "image.json").open("x", encoding="utf-8") as stream:
        json.dump(record, stream, indent=2)
        stream.write("\n")


def build(args: argparse.Namespace) -> None:
    checked_source(args.source_sha)
    checked_reference(args.image, allow_digest=False)
    base_references = {key: getattr(args, key.lower()) or default for key, default in BASES.items()}
    for reference in base_references.values():
        checked_reference(reference)
    evidence_directory(args.evidence)
    environment = os.environ.copy()
    # The approved example provides paths and resource limits, never host env.
    for line in (ASSETS / "compose.env.example").read_text().splitlines():
        if line and not line.startswith("#") and "=" in line:
            environment.pop(line.split("=", 1)[0], None)
    for key in ("COMPOSE_FILE", "COMPOSE_PROFILES", "COMPOSE_PROJECT_NAME"):
        environment.pop(key, None)
    record = {"schema": "cf-filebrowser-image/v1", "source_sha": args.source_sha,
              "platform": "linux/amd64", "bases": {}, "inputs": {}}
    for key, reference in base_references.items():
        run("docker", "pull", "--platform", "linux/amd64", reference, capture=False)
        info = image_info(reference)
        pinned = next((ref for ref in info.get("RepoDigests", [])
                       if DIGEST.fullmatch(ref.rsplit("@", 1)[-1])), None)
        if not pinned:
            raise ValueError(f"no registry digest resolved for {key}")
        environment[key] = pinned
        record["bases"][key] = {"requested": reference, "digest": pinned,
                                "image_id": info["Id"]}
    for name in ("backend/go.mod", "backend/go.sum", "frontend/package.json",
                 "frontend/package-lock.json", "_docker/Dockerfile",
                 "deploy/shared-host/compose.build.yaml"):
        record["inputs"][name] = hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
    environment.update(FILEBROWSER_BUILD_IMAGE=args.image,
                       BUILD_VERSION=args.version, BUILD_REVISION=args.source_sha)
    run("docker", "compose", "--env-file", str(ASSETS / "compose.env.example"),
        "-f", str(ASSETS / "compose.yaml"), "-f", str(ASSETS / "compose.build.yaml"),
        "--profile", "approved", "build", "--pull", "filebrowser-enterprise",
        capture=False, env=environment)
    info = image_info(args.image)
    if info.get("Config", {}).get("Labels", {}).get("org.opencontainers.image.revision") != args.source_sha:
        raise ValueError("built image revision label mismatch")
    if info.get("Architecture") != "amd64" or info.get("Os") != "linux":
        raise ValueError("built image must target linux/amd64")
    record.update(image_id=info["Id"], staging_reference=args.image,
                  docker_version=run("docker", "version", "--format", "{{json .}}"),
                  compose_version=run("docker", "compose", "version", "--short"))
    container = run("docker", "create", "--network", "none", "--entrypoint", "/bin/true", info["Id"])
    try:
        run("docker", "cp", f"{container}:/usr/share/filebrowser/build-inputs", str(args.evidence), capture=False)
    finally:
        run("docker", "rm", container)
    write_record(args.evidence, record)
    print(f"[shared-host-image] built {info['Id']}; evidence: {args.evidence}")


def publish(args: argparse.Namespace) -> None:
    if not DIGEST.fullmatch(args.image):
        raise ValueError("publish requires the actual sha256 Image ID")
    registry, repository = checked_reference(args.target, require_tag=True, allow_digest=False)
    checked_registry(args.approved_registry)
    if not registry or registry != args.approved_registry or registry in {"docker.io", "ghcr.io"}:
        raise ValueError("target must be the explicitly approved isolated test registry")
    info = image_info(args.image)
    revision = info.get("Config", {}).get("Labels", {}).get("org.opencontainers.image.revision")
    if revision != args.source_sha:
        raise ValueError("image revision does not match approved SHA")
    evidence_directory(args.evidence)
    run("docker", "tag", args.image, args.target)
    run("docker", "push", args.target, capture=False)
    digests = image_info(args.target).get("RepoDigests", [])
    pinned = next((ref for ref in digests if ref.startswith(repository + "@sha256:")), None)
    if not pinned:
        raise ValueError("publish did not yield a registry digest")
    write_record(args.evidence, {"schema": "cf-filebrowser-publish/v1", "source_sha": revision,
                                "image_id": args.image, "registry_reference": pinned})
    print(f"[shared-host-image] published {pinned}")


def main() -> None:
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    command = commands.add_parser("build")
    command.add_argument("--source-sha", required=True)
    command.add_argument("--image", required=True)
    command.add_argument("--version", required=True)
    command.add_argument("--evidence", type=Path, required=True)
    for key in BASES:
        command.add_argument("--" + key.lower().replace("_", "-"))
    command = commands.add_parser("publish")
    command.add_argument("--source-sha", required=True)
    command.add_argument("--image", required=True)
    command.add_argument("--target", required=True)
    command.add_argument("--approved-registry", required=True)
    command.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    try:
        (build if args.command == "build" else publish)(args)
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"[shared-host-image] {args.command} failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
