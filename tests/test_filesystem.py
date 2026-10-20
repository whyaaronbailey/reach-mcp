import codecs
import difflib
import hashlib
import os
from pathlib import Path

import pytest

from reach_mcp.filesystem import FileSystem, FileSystemError


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


@pytest.fixture
def fs(tmp_path):
    return FileSystem([tmp_path], tmp_path)


def test_create_read_compare_and_swap(fs, tmp_path):
    result = fs.write_text("code.py", "one\ntwo\nthree\n", create=True)
    assert result["created"]
    page = fs.read_text("code.py", 2, 2)
    assert page["content"] == "two\n"
    assert page["line_count"] == 3 and page["next_line"] == 3
    assert page["sha256"] == result["sha256"]
    with pytest.raises(FileSystemError, match="Creation requires"):
        fs.write_text("code.py", "overwritten", create=True)
    with pytest.raises(FileSystemError, match="current full SHA"):
        fs.write_text("code.py", "overwritten")
    (tmp_path / "code.py").write_text("changed")
    with pytest.raises(FileSystemError, match="changed"):
        fs.write_text("code.py", "overwritten", result["sha256"])
    assert (tmp_path / "code.py").read_text() == "changed"


@pytest.mark.parametrize("bom,encoding", [
    (codecs.BOM_UTF8, "utf-8"),
    (codecs.BOM_UTF16_LE, "utf-16-le"),
    (codecs.BOM_UTF16_BE, "utf-16-be"),
    (b"", "utf-8"),
])
def test_replace_preserves_encoding_bom_crlf(fs, tmp_path, bom, encoding):
    before = bom + "first\r\nsecond\r\n".encode(encoding)
    file = tmp_path / "text.txt"
    file.write_bytes(before)
    result = fs.replace_text("text.txt", "first\nsecond", "hello\nworld", sha(before))
    expected = bom + "hello\r\nworld\r\n".encode(encoding)
    assert file.read_bytes() == expected
    assert result["sha256"] == sha(expected)
    read = fs.read_text("text.txt")
    assert read["newline"] == "crlf" and read["bom"] == bool(bom)


def test_replacement_requires_exact_occurrence_count(fs, tmp_path):
    raw = b"same same"
    file = tmp_path / "text.txt"
    file.write_bytes(raw)
    with pytest.raises(FileSystemError, match="occurrence count"):
        fs.replace_text("text.txt", "same", "new", sha(raw))
    assert file.read_bytes() == raw
    fs.replace_text("text.txt", "same", "new", sha(raw), occurrences=2)
    assert file.read_bytes() == b"new new"


@pytest.mark.parametrize("path", [
    "../escape", r"..\escape", r"\\server\share\file", "//server/share/file",
    r"\\?\C:\Windows", r"\\.\NUL", "stream:secret", "NUL.txt", "file.", "file ",
])
def test_unsafe_paths_rejected(fs, path):
    with pytest.raises(FileSystemError):
        fs.read_text(path)


def test_outside_root_rejected(fs, tmp_path):
    with pytest.raises(FileSystemError, match="outside"):
        fs.read_text(tmp_path.parent / "elsewhere")


def test_symlink_escape_rejected(fs, tmp_path):
    outside = tmp_path.parent / (tmp_path.name + "-outside")
    outside.mkdir()
    (outside / "private").write_text("hidden")
    link = tmp_path / "link"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("Symlink creation unavailable")
    with pytest.raises(FileSystemError, match="Symlinks"):
        fs.read_text(link / "private")
    assert fs.list_directory()["entries"] == []


@pytest.mark.skipif(os.name != "nt", reason="Windows junction")
def test_windows_junction_escape_rejected(fs, tmp_path):
    import subprocess
    outside = tmp_path.parent / (tmp_path.name + "-junction-target")
    outside.mkdir()
    (outside / "private").write_text("hidden")
    link = tmp_path / "junction"
    completed = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(outside)],
                               capture_output=True)
    if completed.returncode:
        pytest.skip("Junction creation unavailable")
    try:
        with pytest.raises(FileSystemError, match="junction"):
            fs.read_text(link / "private")
        assert fs.list_directory()["entries"] == []
    finally:
        link.rmdir()


def test_binary_and_oversized_text_refused(fs, tmp_path):
    (tmp_path / "binary").write_bytes(b"abc\x00def")
    with pytest.raises(FileSystemError, match="Binary"):
        fs.read_text("binary")
    (tmp_path / "ansi").write_bytes(b"\xff")
    with pytest.raises(FileSystemError, match="UTF"):
        fs.read_text("ansi")
    small = FileSystem([tmp_path], tmp_path, max_file_bytes=1024)
    (tmp_path / "large").write_bytes(b"a" * 1025)
    with pytest.raises(FileSystemError, match="byte limit"):
        small.read_text("large")
    with pytest.raises(FileSystemError, match="byte limit"):
        small.write_text("new", "a" * 1025, create=True)


def test_listing_search_bounds_and_metadata_exclusions(fs, tmp_path):
    (tmp_path / "one.py").write_text("needle\nNEEDLE\nother")
    (tmp_path / "two.txt").write_text("needle")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "ignored.py").write_text("needle")
    listed = fs.list_directory(limit=1)
    assert len(listed["entries"]) == 1 and listed["truncated"]
    found = fs.search("needle", glob="*.py")
    assert [m["line"] for m in found["matches"]] == [1, 2]
    assert found["skipped"] == 1
    assert len(fs.search("needle", case_sensitive=True, glob="*.py")["matches"]) == 1
    assert fs.search("ONE", filenames=True)["matches"][0]["path"].endswith("one.py")
    found = fs.search("needle", limit=1)
    assert len(found["matches"]) == 1 and found["truncated"]


def test_read_bounds_and_huge_line(fs, tmp_path):
    (tmp_path / "many").write_text("a\n" * 2200)
    assert len(fs.read_text("many")["content"].splitlines()) == 400
    with pytest.raises(FileSystemError, match="range"):
        fs.read_text("many", 0, 2)
    with pytest.raises(FileSystemError, match="range"):
        fs.read_text("many", 1, 2001)
    (tmp_path / "huge").write_text("a" * 150000)
    result = fs.read_text("huge")
    assert len(result["content"]) == 60000 and result["partial_line"]


def test_move_remove_and_empty_directory_safety(fs, tmp_path):
    created = fs.write_text("a", "contents", create=True)
    fs.write_text("existing", "keep", create=True)
    with pytest.raises(FileSystemError, match="never overwrite"):
        fs.move("a", "existing", created["sha256"])
    moved = fs.move("a", "b", created["sha256"])
    assert not (tmp_path / "a").exists()
    assert (tmp_path / "b").read_text() == "contents"
    with pytest.raises(FileSystemError, match="SHA"):
        fs.remove("b")
    fs.remove("b", moved["sha256"])
    fs.make_directory("empty")
    fs.move("empty", "renamed")
    fs.remove("renamed")
    fs.make_directory("nonempty")
    fs.write_text("nonempty/a", "keep", create=True)
    with pytest.raises(FileSystemError, match="empty"):
        fs.remove("nonempty")
    with pytest.raises(FileSystemError, match="empty"):
        fs.move("nonempty", "moved")
    with pytest.raises(FileSystemError, match="root"):
        fs.remove(tmp_path)


def make_diff(old, new, name):
    return "".join(difflib.unified_diff(old.splitlines(keepends=True),
                                       new.splitlines(keepends=True),
                                       fromfile="a/" + name, tofile="b/" + name))


def test_unified_patch_multiple_files_preserves_crlf_bom(fs, tmp_path):
    old = "one\ntwo\nthree\n"
    (tmp_path / "one").write_bytes(codecs.BOM_UTF8 + old.replace("\n", "\r\n").encode())
    (tmp_path / "two").write_text("same\n")
    patch = make_diff(old, "one\nchanged\nthree\n", "one")
    patch += make_diff("same\n", "different\n", "two")
    expected = {name: sha((tmp_path / name).read_bytes()) for name in ["one", "two"]}
    result = fs.apply_patch(patch, expected)
    assert len(result["files"]) == 2
    assert (tmp_path / "one").read_bytes() == codecs.BOM_UTF8 + b"one\r\nchanged\r\nthree\r\n"
    assert (tmp_path / "two").read_text() == "different\n"


def test_patch_preflight_prevents_partial_changes(fs, tmp_path):
    (tmp_path / "one").write_bytes(b"one\n")
    (tmp_path / "two").write_bytes(b"two\n")
    patch = make_diff("one\n", "changed\n", "one") + make_diff("wrong\n", "changed\n", "two")
    expected = {name: sha((tmp_path / name).read_bytes()) for name in ["one", "two"]}
    with pytest.raises(FileSystemError, match="context"):
        fs.apply_patch(patch, expected)
    assert (tmp_path / "one").read_bytes() == b"one\n"
    assert (tmp_path / "two").read_bytes() == b"two\n"


def test_patch_create_delete_and_no_final_newline(fs, tmp_path):
    create = "--- /dev/null\n+++ b/new\n@@ -0,0 +1 @@\n+hello\n\\ No newline at end of file\n"
    fs.apply_patch(create, {"new": None})
    assert (tmp_path / "new").read_bytes() == b"hello"
    delete = "--- a/new\n+++ /dev/null\n@@ -1 +0,0 @@\n-hello\n\\ No newline at end of file\n"
    fs.apply_patch(delete, {"new": sha(b"hello")})
    assert not (tmp_path / "new").exists()


def test_patch_header_like_content_and_stale_hash(fs, tmp_path):
    old = "--- header\n+++ header\n"
    (tmp_path / "text").write_bytes(old.encode())
    patch = make_diff(old, "replacement\n", "text")
    with pytest.raises(FileSystemError, match="changed"):
        fs.apply_patch(patch, {"text": "0" * 64})
    fs.apply_patch(patch, {"text": sha(old.encode())})
    assert (tmp_path / "text").read_text() == "replacement\n"


def test_patch_rollback_on_second_commit_failure(fs, tmp_path, monkeypatch):
    for name in ("one", "two"):
        (tmp_path / name).write_bytes((name + "\n").encode())
    patch = make_diff("one\n", "changed\n", "one") + make_diff("two\n", "changed\n", "two")
    expected = {name: sha((tmp_path / name).read_bytes()) for name in ["one", "two"]}
    original = fs._store
    def fail_second(path, raw, **kwargs):
        if path.name == "two":
            raise OSError("simulated I/O failure")
        return original(path, raw, **kwargs)
    monkeypatch.setattr(fs, "_store", fail_second)
    with pytest.raises(OSError):
        fs.apply_patch(patch, expected)
    assert (tmp_path / "one").read_bytes() == b"one\n"
    assert (tmp_path / "two").read_bytes() == b"two\n"


def test_patch_rejects_rename_and_traversal(fs, tmp_path):
    fs.write_text("one", "one\n", create=True)
    for patch, expected in [
        ("--- a/one\n+++ b/two\n@@ -1 +1 @@\n-one\n+two\n", {"two": None}),
        ("--- /dev/null\n+++ b/../outside\n@@ -0,0 +1 @@\n+x\n", {"../outside": None}),
    ]:
        with pytest.raises(FileSystemError):
            fs.apply_patch(patch, expected)


def test_public_path_validation_reusable_for_terminal(fs, tmp_path):
    assert fs.resolve_path(".") == tmp_path
    assert fs.resolve_path("new", must_exist=False) == tmp_path / "new"
    with pytest.raises(FileSystemError, match="exist"):
        fs.resolve_path("new")
    fs.write_text("file", "content", create=True)
    with pytest.raises(FileSystemError, match="directory"):
        fs.resolve_path("file", directory=True)
