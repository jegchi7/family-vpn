"""Synthetic bootstrap trust-boundary tests; no downloads or installers."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import signal
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("bootstrap", Path(__file__).with_name("bootstrap-github.py"))
bootstrap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bootstrap)


def bytes_json(value):
    return json.dumps(value).encode("utf-8")


def release_fixture():
    assets = []
    for arch in ("amd64", "arm64"):
        name = "family-vpn-v" + bootstrap.VERSION + "-linux-" + arch + ".tar.gz"
        for asset_name in (name, name + ".sha256"):
            assets.append({"name": asset_name, "size": 128, "state": "uploaded", "digest": "sha256:" + "a" * 64,
                           "browser_download_url": "https://github.com/" + bootstrap.REPOSITORY + "/releases/download/v" + bootstrap.VERSION + "/" + asset_name})
    return {"draft": False, "prerelease": True, "tag_name": "v" + bootstrap.VERSION,
            "target_commitish": "b" * 40, "assets": assets}


class MetadataTransport:
    def __init__(self, release=None, tag=None):
        self.release = release if release is not None else release_fixture()
        self.tag = tag or {"object": {"type": "commit", "sha": "b" * 40}}

    def bytes(self, url, limit):
        assert url == "https://raw.githubusercontent.com/" + bootstrap.REPOSITORY + "/" + "b" * 40 + "/package.json"
        return bytes_json({"version": bootstrap.VERSION})

    def metadata(self, path):
        if path == "/releases/tags/v" + bootstrap.VERSION:
            return self.release
        if path == "/git/ref/tags/v" + bootstrap.VERSION:
            return self.tag
        raise AssertionError(path)


def bundle_files(arch="amd64"):
    files = {}
    for path in bootstrap.FIXED:
        if path in ("release.json", "SHA256SUMS"):
            continue
        if path.startswith("build/"):
            data = bytearray(64)
            data[:6] = b"\x7fELF\x02\x01"
            data[18:20] = (62 if arch == "amd64" else 183).to_bytes(2, "little")
            files[path] = bytes(data)
        else:
            files[path] = b"non-secret synthetic content\n"
    files["web/dist/index.html"] = b"<html></html>"
    manifest = {"format": 1, "name": "family-vpn-local-stand", "version": bootstrap.VERSION,
                "target": {"os": "linux", "arch": arch, "cgo_enabled": False}, "schemas": {"portal": 6, "admin": 1},
                "scope": {"numeric_loopback_https_only": True, "production": False, "vpn_ready": False, "profile_delivery_available": False},
                "acceptance": {"linux_execution": False, "native_vpn": False, "client_round_trip": False, "uid_isolation": False},
                "files": [{"path": path, "mode": format(bootstrap.expected_mode(path), "o"), "size": len(data),
                           "sha256": hashlib.sha256(data).hexdigest()} for path, data in files.items()]}
    files["release.json"] = bytes_json(manifest)
    files["SHA256SUMS"] = "".join(hashlib.sha256(data).hexdigest() + "  " + path + "\n" for path, data in files.items()).encode("ascii")
    return files


def write_archive(path, files, special=None):
    prefix = "family-vpn-v" + bootstrap.VERSION + "-linux-amd64"
    with tarfile.open(path, "w:gz", format=tarfile.USTAR_FORMAT) as archive:
        for name, data in files.items():
            member = tarfile.TarInfo(prefix + "/" + name)
            member.mode = bootstrap.expected_mode(name)
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
        if special:
            archive.addfile(special[0], io.BytesIO(special[1]))


class BootstrapTests(unittest.TestCase):
    def test_interactive_terminal_failure_and_failed_operator_are_distinct(self):
        with patch("builtins.open", side_effect=OSError("private terminal detail")), patch.object(bootstrap.subprocess, "run") as run:
            with self.assertRaisesRegex(bootstrap.BootstrapError, "interactive terminal"):
                bootstrap.invoke("synthetic-bundle", [], interactive=True)
            run.assert_not_called()
        with patch.object(bootstrap.subprocess, "run", side_effect=OSError("private exec detail")):
            with self.assertRaisesRegex(bootstrap.BootstrapError, "could not be started") as result:
                bootstrap.invoke("synthetic-bundle", ["core-plan"])
            self.assertNotIn("private", str(result.exception))

    @unittest.skipUnless(sys.platform == "linux", "Real controlling terminal regression requires Linux")
    def test_interactive_foreign_reads_controlling_terminal_with_stdin_devnull(self):
        import pty
        master, slave = pty.openpty()
        try:
            terminal_path = os.ttyname(slave)
            with tempfile.TemporaryDirectory() as temporary:
                scripts = Path(temporary) / "scripts"
                scripts.mkdir()
                (scripts / "bootstrap-foreign.sh").write_text(
                    "#!/bin/bash\nset -euo pipefail\n"
                    "for expected in one two three four; do\n"
                    "  IFS= read -r actual\n  test \"$actual\" = \"$expected\"\ndone\n"
                    "printf 'synthetic-terminal-complete\\n'\n", encoding="utf-8")
                program = (
                    "import os,fcntl,termios,importlib.util,sys; "
                    "os.setsid(); fd=os.open(sys.argv[1],os.O_RDWR); "
                    "fcntl.ioctl(fd,termios.TIOCSCTTY,0); "
                    "s=importlib.util.spec_from_file_location('bootstrap',sys.argv[2]); "
                    "m=importlib.util.module_from_spec(s); s.loader.exec_module(m); "
                    "m.invoke(sys.argv[3],[],interactive=True); os.close(fd)"
                )
                child = subprocess.Popen([sys.executable, "-I", "-c", program, terminal_path,
                                          str(Path(bootstrap.__file__).resolve()), temporary],
                                         stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                try:
                    os.write(master, b"one\ntwo\nthree\nfour\n")
                    stdout, stderr = child.communicate(timeout=10)
                    self.assertEqual(child.returncode, 0, stderr.decode("utf-8", errors="replace"))
                    self.assertEqual(stdout, b"synthetic-terminal-complete\n")
                finally:
                    if child.poll() is None:
                        child.kill()
                        child.communicate(timeout=5)
        finally:
            os.close(master)
            os.close(slave)

    def test_published_commit_bound_assets(self):
        self.assertEqual(len(bootstrap.checked_release(MetadataTransport(), "b" * 40)), 4)

    def test_draft_stale_tag_and_commit_rejected(self):
        for field, value in (("draft", True), ("prerelease", False), ("target_commitish", "main"), ("tag_name", "v0.26.0")):
            with self.subTest(field=field):
                release = release_fixture()
                release[field] = value
                with self.assertRaises(bootstrap.BootstrapError):
                    bootstrap.checked_release(MetadataTransport(release), "b" * 40)
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.checked_release(MetadataTransport(tag={"object": {"type": "tag", "sha": "b" * 40}}), "b" * 40)

    def test_asset_alias_missing_duplicate_digest_and_size_rejected(self):
        mutations = [lambda r: r["assets"].pop(), lambda r: r["assets"].append(r["assets"][0]),
                     lambda r: r["assets"][0].update(digest="sha256:" + "A" * 64),
                     lambda r: r["assets"][0].update(browser_download_url="https://evil.example/bundle"),
                     lambda r: r["assets"][0].update(size=True),
                     lambda r: r["assets"][1].update(size=513)]
        for mutate in mutations:
            release = release_fixture()
            mutate(release)
            with self.assertRaises(bootstrap.BootstrapError):
                bootstrap.checked_release(MetadataTransport(release), "b" * 40)

    def test_closed_redirect_sources(self):
        self.assertTrue(bootstrap.allowed_url("https://release-assets.githubusercontent.com/file?opaque=value"))
        for url in ("http://github.com/file", "https://github.com.evil.example/file", "https://user@github.com/file", "https://github.com:444/file", "https://127.0.0.1/file", "https://github.com/file#fragment"):
            self.assertFalse(bootstrap.allowed_url(url), url)

    def test_total_deadline_on_fragmented_response(self):
        class Response:
            status = 200
            headers = {}
            receives = 0

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return None

            def read(self, size):
                raise AssertionError("Must not wait to fill an entire chunk")

            def read1(self, size):
                self.receives += 1
                return b"x"

        response = Response()

        class Opener:
            def open(self, request, timeout):
                return response

        transport = bootstrap.Transport()
        transport.opener = Opener()
        output = io.BytesIO()
        with patch.object(bootstrap.time, "monotonic", side_effect=(0, 0, 181)):
            with self.assertRaisesRegex(bootstrap.BootstrapError, "timed out"):
                transport.copy("https://github.com/checked", output, 1024)
        self.assertEqual(response.receives, 1)
        self.assertEqual(output.getvalue(), b"x")

    @unittest.skipUnless(sys.platform == "linux", "Linux request alarm execution requires Linux")
    def test_linux_whole_request_alarm_and_restoration(self):
        previous = signal.getsignal(signal.SIGALRM)
        with self.assertRaisesRegex(bootstrap.BootstrapError, "timed out"):
            with bootstrap.network_deadline(0.02):
                bootstrap.time.sleep(1)
        self.assertEqual(signal.getsignal(signal.SIGALRM), previous)
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))

    def test_duplicate_json_and_secret_file_rejected(self):
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.parse_json(b'{"version":1,"version":2}')
        for path in ("web/dist/../state.db", "web/dist/private.key", "web/dist/.env.js", "var/auth/state.db", "scripts/other.sh"):
            with self.assertRaises(bootstrap.BootstrapError):
                bootstrap.expected_mode(path)

    def extraction(self, files, special=None, succeeds=False):
        with tempfile.TemporaryDirectory() as temporary:
            archive = str(Path(temporary) / "bundle.tar.gz")
            output = str(Path(temporary) / "output")
            Path(output).mkdir()
            write_archive(archive, files, special)
            if succeeds:
                bundle = Path(bootstrap.extract_checked(archive, output, "amd64"))
                self.assertEqual((bundle / "build/vpnctl").read_bytes(), files["build/vpnctl"])
            else:
                with self.assertRaises(bootstrap.BootstrapError):
                    bootstrap.extract_checked(archive, output, "amd64")

    def test_streamed_bundle_manifest_and_elf(self):
        self.extraction(bundle_files(), succeeds=True)

    def test_file_tamper_wrong_arch_and_false_acceptance(self):
        files = bundle_files()
        files["web/dist/index.html"] += b"tampered"
        self.extraction(files)
        self.extraction(bundle_files("arm64"))
        files = bundle_files()
        manifest = json.loads(files["release.json"])
        manifest["acceptance"]["native_vpn"] = True
        files["release.json"] = bytes_json(manifest)
        self.extraction(files)

    def test_traversal_duplicate_and_links_rejected(self):
        prefix = "family-vpn-v" + bootstrap.VERSION + "-linux-amd64"
        for name, kind in ((prefix + "/../escaped", tarfile.REGTYPE), (prefix + "/build/vpnctl", tarfile.REGTYPE), (prefix + "/link", tarfile.SYMTYPE)):
            member = tarfile.TarInfo(name)
            member.type = kind
            member.mode = 0o755
            member.size = 1 if kind == tarfile.REGTYPE else 0
            member.linkname = "../../outside" if kind == tarfile.SYMTYPE else ""
            self.extraction(bundle_files(), (member, b"x"))

    def test_archive_expansion_bound_includes_metadata(self):
        old_limit = bootstrap.MAX_EXPANDED
        try:
            bootstrap.MAX_EXPANDED = 1024
            self.extraction(bundle_files())
        finally:
            bootstrap.MAX_EXPANDED = old_limit


if __name__ == "__main__":
    unittest.main()
