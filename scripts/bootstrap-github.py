#!/usr/bin/env python3
"""Download a checked, commit-bound operator bundle. Never activate a service."""
import argparse
from contextlib import contextmanager
import gzip
import hashlib
import json
import os
import platform
import re
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.parse
import urllib.request

REPOSITORY = "jegchi7/family-vpn"
VERSION = "0.29.0"
BASE = "https://api.github.com/repos/" + REPOSITORY
MAX_ARCHIVE = 128 * 1024 * 1024
MAX_EXPANDED = 160 * 1024 * 1024
HASH = re.compile(r"[a-f0-9]{64}\Z")
FRONTEND = re.compile(r"web/dist/(?:[A-Za-z0-9_-]+/)*[A-Za-z0-9_.-]+\.(?:html|js|css|svg|png|jpe?g|gif|webp|avif|ico|woff2?|ttf|otf|wasm)\Z")
FIXED = {
    "build/portal": 0o755, "build/admin": 0o755, "build/vpnctl": 0o755,
    "scripts/admin-credentials.py": 0o755, "scripts/bootstrap-foreign.sh": 0o755,
    "docs/stand-runbook.md": 0o644, "docs/profile-awg-session-runbook.md": 0o644,
    "docs/vpn-bootstrap-runbook.md": 0o644, "docs/protocol-status-runbook.md": 0o644,
    "docs/network-stand-runbook.md": 0o644,
    "release.json": 0o644, "SHA256SUMS": 0o644,
}


class BootstrapError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise BootstrapError(message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "Duplicate metadata field")
        result[key] = value
    return result


def parse_json(data):
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=unique_object)
    except BootstrapError:
        raise
    except (ValueError, UnicodeError, RecursionError):
        raise BootstrapError("Invalid bounded metadata") from None


def allowed_url(url):
    try:
        parsed = urllib.parse.urlsplit(url)
        host = parsed.hostname
        return (parsed.scheme == "https" and parsed.port in (None, 443) and
                parsed.username is None and parsed.password is None and not parsed.fragment and
                host in ("api.github.com", "raw.githubusercontent.com", "github.com",
                         "release-assets.githubusercontent.com", "objects.githubusercontent.com"))
    except ValueError:
        return False


class Redirects(urllib.request.HTTPRedirectHandler):
    max_redirections = 5
    max_repeats = 1

    def redirect_request(self, request, response, code, message, headers, new_url):
        require(urllib.parse.urlsplit(request.full_url).hostname not in ("api.github.com", "raw.githubusercontent.com") and
                allowed_url(new_url) and urllib.parse.urlsplit(new_url).hostname in
                ("github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"), "Unexpected release redirect")
        return super().redirect_request(request, response, code, message, headers, new_url)


@contextmanager
def network_deadline(seconds):
    # Apply is Linux-only and runs on the main thread. The alarm also bounds
    # TLS, response headers and redirects, before a response body is available.
    if sys.platform != "linux":
        yield
        return

    def expired(signum, frame):
        raise BootstrapError("Release download timed out")

    started = time.perf_counter()
    previous_handler = signal.signal(signal.SIGALRM, expired)
    previous_timer = signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)
        if previous_timer[0] > 0:
            remaining = max(0.000001, previous_timer[0] - (time.perf_counter() - started))
            signal.setitimer(signal.ITIMER_REAL, remaining, previous_timer[1])


class Transport:
    def __init__(self):
        # No inherited proxy settings or credentials; fixed public GitHub sources only.
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), Redirects())

    def copy(self, url, output, limit, expected_size=None, expected_hash=None):
        require(allowed_url(url), "Unexpected download source")
        request = urllib.request.Request(url, headers={
            "User-Agent": "family-vpn-operator-bootstrap", "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2026-03-10", "Accept-Encoding": "identity",
        })
        digest = hashlib.sha256()
        count = 0
        deadline = time.monotonic() + 180
        try:
            with network_deadline(180), self.opener.open(request, timeout=20) as response:
                require(response.status == 200, "Release download is unavailable")
                require(response.headers.get("Content-Encoding", "identity") == "identity", "Unexpected content encoding")
                length = response.headers.get("Content-Length")
                if length is not None:
                    require(length.isdigit() and int(length) <= limit, "Download exceeds bounds")
                while True:
                    require(time.monotonic() < deadline, "Release download timed out")
                    # read(size) can keep filling a chunk indefinitely under a
                    # slow sender. read1 returns after one receive, so the total
                    # deadline is checked even when bytes arrive continuously.
                    chunk = response.read1(64 * 1024)
                    if not chunk:
                        break
                    count += len(chunk)
                    require(count <= limit, "Download exceeds bounds")
                    digest.update(chunk)
                    output.write(chunk)
        except BootstrapError:
            raise
        except Exception:
            raise BootstrapError("GitHub download failed; check the Actions run and published release") from None
        require(expected_size is None or count == expected_size, "Release asset size mismatch")
        require(expected_hash is None or digest.hexdigest() == expected_hash, "Release asset checksum mismatch")

    def bytes(self, url, limit):
        import io
        output = io.BytesIO()
        self.copy(url, output, limit)
        return output.getvalue()

    def metadata(self, path):
        return parse_json(self.bytes(BASE + path, 1024 * 1024))


def main_commit(transport):
    reference = transport.metadata("/git/ref/heads/main")
    obj = reference.get("object", {})
    require(obj.get("type") == "commit" and re.fullmatch(r"[a-f0-9]{40}", obj.get("sha", "")), "Main commit is unavailable")
    return obj["sha"]


def checked_release(transport, commit):
    package = parse_json(transport.bytes("https://raw.githubusercontent.com/" + REPOSITORY + "/" + commit + "/package.json", 64 * 1024))
    require(package.get("version") == VERSION, "Main version differs from this bootstrap; use the matching new command")
    release = transport.metadata("/releases/tags/v" + VERSION)
    require(release.get("draft") is False and release.get("prerelease") is True and
            release.get("tag_name") == "v" + VERSION and release.get("target_commitish") == commit,
            "No published bootstrap release for the checked main commit; wait for successful Actions")
    tag = transport.metadata("/git/ref/tags/v" + VERSION).get("object", {})
    require(tag.get("type") == "commit" and tag.get("sha") == commit, "Release tag differs from main")
    names = set()
    for arch in ("amd64", "arm64"):
        name = "family-vpn-v" + VERSION + "-linux-" + arch + ".tar.gz"
        names.update((name, name + ".sha256"))
    assets = release.get("assets")
    require(isinstance(assets, list) and len(assets) == 4, "Release must contain both bundles and checksums")
    result = {}
    for asset in assets:
        name = asset.get("name")
        size = asset.get("size")
        digest = asset.get("digest", "")
        url = "https://github.com/" + REPOSITORY + "/releases/download/v" + VERSION + "/" + str(name)
        require(name in names and name not in result and asset.get("state") == "uploaded" and
                type(size) is int and 0 < size <= (512 if name.endswith(".sha256") else MAX_ARCHIVE) and
                isinstance(digest, str) and digest.startswith("sha256:") and HASH.fullmatch(digest[7:]) and
                asset.get("browser_download_url") == url, "Release asset provenance or checksum is invalid")
        result[name] = {"url": url, "size": size, "hash": digest[7:]}
    return result


def expected_mode(path):
    require(all(part and not part.startswith(".") for part in path.split("/")), "Unsafe bundle path")
    if path in FIXED:
        return FIXED[path]
    require(FRONTEND.fullmatch(path) is not None, "Unexpected bundle file")
    return 0o644


def validate_manifest(files, arch):
    manifest = parse_json(files["release.json"]["metadata"])
    require(type(manifest.get("format")) is int and manifest.get("format") == 1 and manifest.get("name") == "family-vpn-local-stand" and
            manifest.get("version") == VERSION and manifest.get("target") == {"os": "linux", "arch": arch, "cgo_enabled": False} and
            manifest.get("schemas") == {"portal": 6, "admin": 1}, "Bundle manifest target mismatch")
    require(type(manifest["target"].get("cgo_enabled")) is bool and
            all(type(v) is bool for v in manifest.get("scope", {}).values()) and
            all(type(v) is bool for v in manifest.get("acceptance", {}).values()) and
            manifest.get("scope") == {"numeric_loopback_https_only": True, "production": False,
                                      "vpn_ready": False, "profile_delivery_available": False} and
            manifest.get("acceptance") == {"linux_execution": False, "native_vpn": False,
                                           "client_round_trip": False, "uid_isolation": False}, "Bundle acceptance scope mismatch")
    records = manifest.get("files")
    require(isinstance(records, list) and len(records) <= 200, "Invalid manifest file list")
    expected = set(files) - {"release.json", "SHA256SUMS"}
    seen = set()
    for record in records:
        path = record.get("path")
        require(path in expected and path not in seen and record.get("sha256") == files[path]["hash"] and
                type(record.get("size")) is int and record["size"] == files[path]["size"] and
                record.get("mode") == format(expected_mode(path), "o"), "Manifest file mismatch")
        seen.add(path)
    require(seen == expected and set(FIXED).issubset(files) and "web/dist/index.html" in files, "Bundle files are incomplete")
    try:
        checksums = files["SHA256SUMS"]["metadata"].decode("ascii")
        lines = checksums.splitlines(keepends=True)
        expected_lines = {files[path]["hash"] + "  " + path + "\n" for path in files if path != "SHA256SUMS"}
        require(len(lines) == len(expected_lines) and set(lines) == expected_lines, "Bundle internal checksums mismatch")
    except UnicodeError:
        raise BootstrapError("Invalid internal checksum encoding") from None


def extract_checked(archive, destination, arch):
    prefix = "family-vpn-v" + VERSION + "-linux-" + arch
    files = {}
    seen = set()
    total = 0
    try:
        class BoundedExpansion:
            def __init__(self, source):
                self.source = source
                self.count = 0

            def read(self, size=-1):
                size = min(size if size >= 0 else MAX_EXPANDED + 1, MAX_EXPANDED + 1 - self.count)
                data = self.source.read(size)
                self.count += len(data)
                require(self.count <= MAX_EXPANDED, "Expanded archive exceeds bounds")
                return data

        with gzip.open(archive, "rb") as compressed, tarfile.open(fileobj=BoundedExpansion(compressed), mode="r|") as bundle:
            for member in bundle:
                require(len(seen) < 256 and member.name not in seen and not member.pax_headers and
                        member.uid == 0 and member.gid == 0 and not member.linkname,
                        "Unexpected archive metadata")
                seen.add(member.name)
                parts = member.name.split("/")
                require(parts[0] == prefix and all(re.fullmatch(r"[A-Za-z0-9_-][A-Za-z0-9_.-]*", p) for p in parts), "Unsafe archive path")
                relative = "/".join(parts[1:])
                path = os.path.join(destination, *parts)
                if member.isdir():
                    require(member.mode == 0o755 and member.size == 0, "Unsafe directory metadata")
                    os.makedirs(path, mode=0o700, exist_ok=True)
                    continue
                require(member.isreg() and not member.issparse() and member.mode == expected_mode(relative) and
                        0 < member.size <= 64 * 1024 * 1024, "Unsafe file metadata")
                total += member.size
                require(total <= MAX_EXPANDED, "Expanded archive exceeds bounds")
                if relative in ("release.json", "SHA256SUMS"):
                    require(member.size <= 64 * 1024, "Bundle metadata exceeds bounds")
                os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
                digest = hashlib.sha256()
                count = 0
                metadata = bytearray()
                header = bytearray()
                with bundle.extractfile(member) as source, os.fdopen(os.open(path, flags, 0o600), "wb") as output:
                    while True:
                        chunk = source.read(64 * 1024)
                        if not chunk:
                            break
                        count += len(chunk)
                        require(count <= member.size, "Archive file exceeds its declared size")
                        digest.update(chunk)
                        output.write(chunk)
                        if len(header) < 64:
                            header.extend(chunk[:64 - len(header)])
                        if relative in ("release.json", "SHA256SUMS"):
                            metadata.extend(chunk)
                require(count == member.size, "Truncated archive member")
                if relative.startswith("build/"):
                    require(len(header) == 64 and header[:5] == b"\x7fELF\x02" and header[5] == 1 and
                            int.from_bytes(header[18:20], "little") == (62 if arch == "amd64" else 183), "Wrong Linux ELF target")
                files[relative] = {"size": count, "hash": digest.hexdigest(), "metadata": bytes(metadata)}
        validate_manifest(files, arch)
        for relative in files:
            os.chmod(os.path.join(destination, prefix, *relative.split("/")), 0o700 if expected_mode(relative) == 0o755 else 0o600)
        return os.path.join(destination, prefix)
    except BootstrapError:
        raise
    except Exception:
        raise BootstrapError("Bundle extraction or validation failed; no executable was run") from None


def protected_directory(path):
    current = "/"
    for part in path.strip("/").split("/"):
        current = os.path.join(current, part)
        try:
            details = os.lstat(current)
        except FileNotFoundError:
            os.mkdir(current, 0o700)
            details = os.lstat(current)
        require(stat.S_ISDIR(details.st_mode) and details.st_uid == 0 and details.st_mode & 0o022 == 0,
                "Bootstrap directory must be protected and root-owned")


def invoke(bundle, arguments, interactive=False):
    environment = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
    command = [os.path.join(bundle, "build", "vpnctl")] + arguments
    try:
        if interactive:
            try:
                terminal = open("/dev/tty", "rb", buffering=0)
            except (OSError, ValueError):
                raise BootstrapError("An interactive terminal is required for new Foreign staging") from None
            with terminal:
                require(os.isatty(terminal.fileno()), "An interactive terminal is required for new Foreign staging")
                result = subprocess.run(["/bin/bash", os.path.join(bundle, "scripts", "bootstrap-foreign.sh"), "--apply"],
                                        cwd=bundle, env=environment, stdin=terminal)
        else:
            result = subprocess.run(command, cwd=bundle, env=environment, stdin=subprocess.DEVNULL)
        require(result.returncode == 0, "Operator preparation stopped; keep the existing binaries and private staging")
    except BootstrapError:
        raise
    except Exception:
        raise BootstrapError("Operator command could not be started; existing state was preserved") from None


def run(role, apply):
    if not apply:
        print(json.dumps({"version": VERSION, "role": role, "dry_run": True, "downloads": False,
                          "network_changed": False, "services_started": False, "vpn_ready": False}))
        return
    require(sys.platform == "linux" and os.geteuid() == 0, "Apply requires Linux root")
    arch = {"x86_64": "amd64", "aarch64": "arm64"}.get(platform.machine())
    require(arch is not None, "Only Linux amd64/arm64 are supported")
    transport = Transport()
    commit = main_commit(transport)
    assets = checked_release(transport, commit)
    name = "family-vpn-v" + VERSION + "-linux-" + arch + ".tar.gz"
    asset = assets[name]
    checksum_asset = assets[name + ".sha256"]
    checksum = transport.bytes(checksum_asset["url"], 512)
    require(len(checksum) == checksum_asset["size"] and hashlib.sha256(checksum).hexdigest() == checksum_asset["hash"] and
            checksum == (asset["hash"] + "  " + name + "\n").encode("ascii"), "Archive checksum sidecar mismatch")
    root = "/root/family-vpn-bundles"
    protected_directory(root)
    stage = tempfile.mkdtemp(prefix="v" + VERSION + "-", dir=root)
    archive = os.path.join(stage, name)
    with os.fdopen(os.open(archive, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "wb") as output:
        transport.copy(asset["url"], output, MAX_ARCHIVE, asset["size"], asset["hash"])
    bundle = extract_checked(archive, stage, arch)
    require(main_commit(transport) == commit, "Main changed during preparation; no installer was run")
    print("Checked bundle: " + bundle, flush=True)
    invoke(bundle, ["core-plan", "--role", role])
    if role == "ru":
        for core in ("xray", "sing-box"):
            invoke(bundle, ["core-install", "--core", core, "--apply"])
            invoke(bundle, ["core-status", "--core", core])
    elif os.path.lexists("/etc/family-vpn/foreign-staging"):
        for core in ("xray", "hysteria"):
            invoke(bundle, ["core-install", "--core", core, "--apply"])
        invoke(bundle, ["foreign-check", "--native-check"])
        invoke(bundle, ["foreign-status"])
    else:
        invoke(bundle, [], interactive=True)
    print("Preparation complete. No services started; kernel isolation, RU ingress and real Android testing remain required.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--role", choices=("ru", "foreign"), required=True)
    parser.add_argument("--apply", action="store_true")
    arguments = parser.parse_args()
    try:
        run(arguments.role, arguments.apply)
    except BootstrapError as error:
        print("Bootstrap: " + str(error), file=sys.stderr)
        return 1
    except Exception:
        print("Bootstrap failed; no automatic rollback, overwrite or cleanup was attempted", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
