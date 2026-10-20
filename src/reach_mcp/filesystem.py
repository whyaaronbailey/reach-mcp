"""Bounded local file operations for Reach MCP.

Every existing-file mutation uses an optimistic SHA-256 precondition. Paths must
stay inside configured local roots; links, junctions, shares and device paths are
not traversed. Multi-file patches validate completely before commit and roll
back committed files on failure, but are not an OS-level multi-file transaction.
"""
from __future__ import annotations

import codecs
import ctypes
import errno
import fnmatch
import hashlib
import os
import re
import stat
import tempfile
import threading
import time
from pathlib import Path


class FileSystemError(RuntimeError):
    """An expected, safe-to-display file operation failure."""


class FileSystem:
    def __init__(self, allowed_roots, cwd, max_file_bytes=2_000_000, max_results=200):
        self.max_file_bytes = max(1024, min(int(max_file_bytes), 20_000_000))
        self.max_results = max(1, min(int(max_results), 1000))
        self._lock = threading.RLock()
        self.roots = tuple(self._local_absolute(Path(p)) for p in allowed_roots)
        if not self.roots:
            raise FileSystemError("Configure at least one allowed local file root.")
        for root in self.roots:
            self._no_links(root)
            if not root.is_dir():
                raise FileSystemError("Every allowed file root must be an existing directory.")
        self.cwd = self._path(cwd)
        if not self.cwd.is_dir():
            raise FileSystemError("The file working directory must exist.")

    @staticmethod
    def _local_absolute(path):
        text = str(path)
        if not text or "\x00" in text or text.startswith(("\\\\", "//", "\\?\\", "\\.\\")):
            raise FileSystemError("Use a local filesystem path, not a share or device path.")
        if not path.is_absolute():
            raise FileSystemError("Configured file roots must be absolute local paths.")
        for part in path.parts[1:]:
            if part in (".", "..") or ":" in part or part.endswith((" ", ".")):
                raise FileSystemError("Unsafe path component.")
            if re.fullmatch(r"(?i)(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?", part):
                raise FileSystemError("Windows device filenames are not allowed.")
        if os.name == "nt":
            anchor = path.anchor
            if ctypes.windll.kernel32.GetDriveTypeW(anchor) in (0, 1, 4):
                raise FileSystemError("The path must be on a local available drive.")
        return path

    @staticmethod
    def _no_links(path):
        for item in (path, *path.parents):
            try:
                info = item.lstat()
            except FileNotFoundError:
                continue
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                raise FileSystemError("Symlinks and junctions are not allowed in file paths.")

    def _path(self, path):
        value = str(path)
        if value.startswith(("\\", "//")) or "\x00" in value:
            raise FileSystemError("Use a path inside an allowed local root.")
        candidate = Path(value)
        if any(part == ".." for part in candidate.parts):
            raise FileSystemError("Parent traversal is not allowed.")
        if not candidate.is_absolute():
            # A drive-relative Windows path (C:foo) must not inherit process state.
            if candidate.drive:
                raise FileSystemError("Drive-relative paths are not allowed.")
            candidate = getattr(self, "cwd", self.roots[0]) / candidate
        candidate = self._local_absolute(candidate)
        self._no_links(candidate)
        normalized = candidate.resolve(strict=False)
        if not any(normalized.is_relative_to(root.resolve()) for root in self.roots):
            raise FileSystemError("The path is outside the configured file roots.")
        return normalized

    def resolve_path(self, path, *, must_exist=True, directory=False):
        """Validate a local path for another tool (for example a process cwd)."""
        resolved = self._path(path)
        if must_exist and not resolved.exists():
            raise FileSystemError("The requested path does not exist.")
        if directory and not resolved.is_dir():
            raise FileSystemError("The requested working directory is not a directory.")
        return resolved

    def _not_root(self, path):
        if path in self.roots:
            raise FileSystemError("An allowed root itself cannot be moved or removed.")

    def _raw(self, path):
        self._no_links(path)
        if not path.is_file():
            raise FileSystemError("The requested path is not an existing regular file.")
        if path.stat().st_size > self.max_file_bytes:
            raise FileSystemError("The file exceeds the configured byte limit.")
        with path.open("rb") as stream:
            raw = stream.read(self.max_file_bytes + 1)
        if len(raw) > self.max_file_bytes:
            raise FileSystemError("The file exceeds the configured byte limit.")
        return raw

    @staticmethod
    def _sha(raw):
        return hashlib.sha256(raw).hexdigest()

    @staticmethod
    def _decode(raw):
        if raw.startswith(codecs.BOM_UTF8):
            encoding, bom = "utf-8", codecs.BOM_UTF8
        elif raw.startswith(codecs.BOM_UTF16_LE):
            encoding, bom = "utf-16-le", codecs.BOM_UTF16_LE
        elif raw.startswith(codecs.BOM_UTF16_BE):
            encoding, bom = "utf-16-be", codecs.BOM_UTF16_BE
        else:
            encoding, bom = "utf-8", b""
        try:
            text = raw[len(bom):].decode(encoding)
        except UnicodeError:
            raise FileSystemError("The file is not supported UTF-8 or BOM-marked UTF-16 text.") from None
        if "\x00" in text:
            raise FileSystemError("Binary files are not supported by text tools.")
        crlf = text.count("\r\n")
        bare_lf = text.count("\n") - crlf
        bare_cr = text.count("\r") - crlf
        newline = "crlf" if crlf and not bare_lf and not bare_cr else "lf"
        if bare_cr or (crlf and bare_lf):
            newline = "mixed"
        return text, encoding, bom, newline

    def _encode(self, text, original=None):
        if "\x00" in text:
            raise FileSystemError("Text must not contain NUL characters.")
        encoding, bom, newline = "utf-8", b"", "lf"
        if original is not None:
            _, encoding, bom, newline = self._decode(original)
        if newline == "crlf":
            text = text.replace("\r\n", "\n").replace("\n", "\r\n")
        try:
            raw = bom + text.encode(encoding)
        except UnicodeError:
            raise FileSystemError("Text contains an invalid Unicode sequence.") from None
        if len(raw) > self.max_file_bytes:
            raise FileSystemError("The resulting file exceeds the configured byte limit.")
        return raw

    def _check(self, path, expected):
        raw = self._raw(path)
        if not expected or not re.fullmatch(r"[0-9a-fA-F]{64}", expected):
            raise FileSystemError("Supply the current full SHA-256 before changing an existing file.")
        if self._sha(raw) != expected.lower():
            raise FileSystemError("The file changed. Read it again before editing.")
        return raw

    def _store(self, path, raw, *, create=False):
        self._path(path)
        if not path.parent.is_dir():
            raise FileSystemError("The destination directory does not exist.")
        descriptor, temporary = tempfile.mkstemp(prefix=".reach-", dir=path.parent)
        stage = Path(temporary)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            self._path(path)
            if create:
                # Linking the complete temporary file gives atomic no-clobber creation.
                try:
                    os.link(stage, path)
                except FileExistsError:
                    raise FileSystemError("The destination already exists; creation never overwrites.") from None
            else:
                if os.name == "nt":
                    # ReplaceFile retains the target's ACL and file attributes.
                    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
                    replace = kernel.ReplaceFileW
                    replace.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_wchar_p,
                                        ctypes.c_uint32, ctypes.c_void_p, ctypes.c_void_p]
                    replace.restype = ctypes.c_int
                    if not replace(str(path), str(stage), None, 0, None, None):
                        raise ctypes.WinError(ctypes.get_last_error())
                else:
                    os.chmod(stage, stat.S_IMODE(path.stat().st_mode))
                    os.replace(stage, path)
        finally:
            stage.unlink(missing_ok=True)

    def list_directory(self, path=".", recursive=False, limit=200):
        root = self._path(path)
        if not root.is_dir():
            raise FileSystemError("The requested path is not a directory.")
        limit = max(1, min(int(limit), self.max_results))
        entries, scanned, truncated = [], 0, False
        deadline = time.monotonic() + 3
        stack = [(root, 0)]
        while stack:
            directory, depth = stack.pop()
            try:
                children = os.scandir(directory)
                with children:
                    for item in children:
                        scanned += 1
                        if scanned > 20_000 or time.monotonic() > deadline or len(entries) >= limit:
                            truncated = True
                            break
                        child = Path(item.path)
                        try:
                            self._path(child)
                            info = item.stat(follow_symlinks=False)
                            kind = "directory" if item.is_dir(follow_symlinks=False) else "file"
                            entries.append({"path": str(child), "kind": kind, "bytes": info.st_size,
                                            "modified_ns": info.st_mtime_ns})
                            if recursive and kind == "directory" and depth < 32:
                                stack.append((child, depth + 1))
                        except (FileSystemError, OSError):
                            continue
            except OSError:
                continue
            if truncated:
                break
        return {"path": str(root), "entries": entries, "truncated": truncated}

    def read_text(self, path, start_line=1, end_line=None):
        file = self._path(path)
        raw = self._raw(file)
        text, encoding, bom, newline = self._decode(raw)
        lines = text.splitlines(keepends=True)
        start = int(start_line)
        end = min(len(lines), start + 399 if end_line is None else int(end_line))
        if start < 1 or end < start - 1 or end - start >= 2000:
            raise FileSystemError("Use a positive line range of at most 2000 lines.")
        selected = "".join(lines[start - 1:end])
        shortened = len(selected) > 60_000
        if shortened:
            # Keep complete lines so next_line always identifies unread content.
            used, kept = 0, []
            for line in lines[start - 1:end]:
                if used + len(line) > 60_000:
                    break
                kept.append(line)
                used += len(line)
            if not kept and start <= len(lines):
                selected = lines[start - 1][:60_000]
                return {"path": str(file), "sha256": self._sha(raw), "bytes": len(raw),
                        "encoding": encoding, "bom": bool(bom), "newline": newline,
                        "line_count": len(lines), "start_line": start, "end_line": start,
                        "content": selected, "truncated": True, "partial_line": True,
                        "next_line": start + 1 if start < len(lines) else None}
            selected = "".join(kept)
            end = start + len(kept) - 1
        return {"path": str(file), "sha256": self._sha(raw), "bytes": len(raw),
                "encoding": encoding, "bom": bool(bom), "newline": newline,
                "line_count": len(lines), "start_line": start, "end_line": end,
                "content": selected, "truncated": shortened or end < len(lines),
                "next_line": end + 1 if end < len(lines) else None}

    def write_text(self, path, content, expected_sha256=None, create=False):
        with self._lock:
            file = self._path(path)
            if create:
                if expected_sha256 is not None or file.exists():
                    raise FileSystemError("Creation requires a missing file and no expected SHA-256.")
                raw = self._encode(content)
            else:
                original = self._check(file, expected_sha256)
                raw = self._encode(content, original)
                self._check(file, expected_sha256)
            self._store(file, raw, create=create)
            return {"path": str(file), "sha256": self._sha(raw), "bytes": len(raw), "created": create}

    def replace_text(self, path, old, new, expected_sha256, occurrences=1):
        with self._lock:
            file = self._path(path)
            original = self._check(file, expected_sha256)
            text, _, _, newline = self._decode(original)
            if not old or int(occurrences) < 1:
                raise FileSystemError("Provide nonempty old text and a positive exact occurrence count.")
            if newline == "crlf":
                old = old.replace("\r\n", "\n").replace("\n", "\r\n")
                new = new.replace("\r\n", "\n").replace("\n", "\r\n")
            count = text.count(old)
            if count != int(occurrences):
                raise FileSystemError("The old text occurrence count does not match; no change was made.")
            raw = self._encode(text.replace(old, new), original)
            self._check(file, expected_sha256)
            self._store(file, raw)
            return {"path": str(file), "sha256": self._sha(raw), "bytes": len(raw), "replacements": count}

    def make_directory(self, path):
        with self._lock:
            directory = self._path(path)
            directory.mkdir(parents=False, exist_ok=False)
            return {"path": str(directory), "created": True}

    def move(self, source, destination, expected_sha256=None):
        with self._lock:
            old, new = self._path(source), self._path(destination)
            self._not_root(old)
            if new.exists():
                raise FileSystemError("The destination already exists; moves never overwrite.")
            if old.is_dir():
                if any(old.iterdir()):
                    raise FileSystemError("Only empty directories can be moved with this tool.")
                old.rename(new)
                return {"source": str(old), "path": str(new), "kind": "directory"}
            raw = self._check(old, expected_sha256)
            try:
                # Same-volume moves keep the original inode, ACL and attributes.
                # A hard-link destination is atomic and cannot overwrite a file.
                os.link(old, new)
            except OSError as error:
                if error.errno != errno.EXDEV and getattr(error, "winerror", None) != 17:
                    raise
                self._store(new, raw, create=True)
            try:
                self._check(old, expected_sha256)
                old.unlink()
            except BaseException:
                new.unlink(missing_ok=True)
                raise
            return {"source": str(old), "path": str(new), "sha256": self._sha(raw), "bytes": len(raw)}

    def remove(self, path, expected_sha256=None):
        with self._lock:
            file = self._path(path)
            self._not_root(file)
            if file.is_dir():
                if any(file.iterdir()):
                    raise FileSystemError("Only empty directories can be removed; recursive deletion is unavailable.")
                file.rmdir()
                return {"path": str(file), "removed": True, "kind": "directory"}
            raw = self._check(file, expected_sha256)
            file.unlink()
            return {"path": str(file), "removed": True, "sha256": self._sha(raw), "bytes": len(raw)}

    def search(self, query, path=".", glob="*", case_sensitive=False, filenames=False, limit=100):
        root = self._path(path)
        if not query or len(query) > 4000:
            raise FileSystemError("Search text must contain 1 to 4000 characters.")
        limit = max(1, min(int(limit), self.max_results))
        matches, scanned, skipped = [], 0, 0
        deadline = time.monotonic() + 3
        needle = query if case_sensitive else query.casefold()
        candidates = [root] if root.is_file() else []
        stack = [(root, 0)] if root.is_dir() else []
        truncated = False
        while candidates or stack:
            if time.monotonic() > deadline or scanned >= 20_000 or len(matches) >= limit:
                truncated = True
                break
            if not candidates:
                directory, depth = stack.pop()
                try:
                    with os.scandir(directory) as children:
                        for item in children:
                            scanned += 1
                            if scanned >= 20_000 or time.monotonic() > deadline:
                                truncated = True
                                break
                            child = Path(item.path)
                            try:
                                self._path(child)
                                if item.is_dir(follow_symlinks=False):
                                    if depth < 32 and item.name not in {".git", ".venv", "node_modules", "__pycache__"}:
                                        stack.append((child, depth + 1))
                                    else:
                                        skipped += 1
                                elif item.is_file(follow_symlinks=False):
                                    candidates.append(child)
                            except (OSError, FileSystemError):
                                skipped += 1
                except OSError:
                    skipped += 1
                continue
            file = candidates.pop()
            if not fnmatch.fnmatchcase(file.name.casefold(), glob.casefold()):
                continue
            if filenames:
                name = file.name if case_sensitive else file.name.casefold()
                if needle in name:
                    matches.append({"path": str(file)})
                continue
            try:
                text, _, _, _ = self._decode(self._raw(file))
            except (OSError, FileSystemError):
                skipped += 1
                continue
            for number, line in enumerate(text.splitlines(), 1):
                candidate = line if case_sensitive else line.casefold()
                if needle in candidate:
                    matches.append({"path": str(file), "line": number, "text": line[:2000],
                                    "line_truncated": len(line) > 2000})
                    if len(matches) >= limit:
                        truncated = True
                        break
        return {"path": str(root), "matches": matches, "truncated": truncated,
                "scanned_entries": scanned, "skipped": skipped,
                "excluded_directories": [".git", ".venv", "node_modules", "__pycache__"]}

    def apply_patch(self, patch, expected_sha256):
        """Apply a standard unified diff after validating every file and hunk."""
        with self._lock:
            plans = self._parse_patch(patch, expected_sha256)
            committed = []
            try:
                for file, before, after in plans:
                    if before is None:
                        if file.exists():
                            raise FileSystemError("A patch creation target now exists.")
                    else:
                        self._check(file, self._sha(before))
                    if after is None:
                        file.unlink()
                    else:
                        self._store(file, after, create=before is None)
                    committed.append((file, before, after))
            except BaseException:
                rollback_failed = False
                for file, before, after in reversed(committed):
                    try:
                        if before is None:
                            if file.exists() and self._raw(file) == after:
                                file.unlink()
                            else:
                                rollback_failed = True
                        elif after is None:
                            self._store(file, before, create=True)
                        elif self._raw(file) == after:
                            self._store(file, before)
                        else:
                            rollback_failed = True
                    except (OSError, FileSystemError):
                        rollback_failed = True
                if rollback_failed:
                    raise FileSystemError("Patch commit failed and rollback was incomplete; inspect the affected files.") from None
                raise
            return {"files": [{"path": str(file), "sha256": self._sha(after) if after is not None else None,
                               "created": before is None, "deleted": after is None}
                              for file, before, after in plans]}

    def _parse_patch(self, patch, expected):
        if len(patch.encode("utf-8")) > self.max_file_bytes:
            raise FileSystemError("The patch exceeds the configured byte limit.")
        lines = patch.replace("\r\n", "\n").splitlines(keepends=True)
        plans, seen, index = [], set(), 0
        while index < len(lines):
            if lines[index].startswith("diff --git "):
                index += 1
                continue
            if not lines[index].startswith("--- ") or index + 1 >= len(lines) or not lines[index + 1].startswith("+++ "):
                raise FileSystemError("Use a standard unified diff with ---/+++ headers and @@ hunks.")
            old_name = lines[index][4:].rstrip("\n").split("\t", 1)[0]
            new_name = lines[index + 1][4:].rstrip("\n").split("\t", 1)[0]
            old_name = old_name[2:] if old_name.startswith("a/") else old_name
            new_name = new_name[2:] if new_name.startswith("b/") else new_name
            if old_name != "/dev/null" and new_name != "/dev/null" and old_name != new_name:
                raise FileSystemError("Patch renames are unsupported; use the move tool separately.")
            name = new_name if new_name != "/dev/null" else old_name
            if name == "/dev/null" or name not in expected:
                raise FileSystemError("Every patch path needs an expected SHA-256 entry (null for a new file).")
            file = self._path(name)
            if file in seen or len(plans) >= 100:
                raise FileSystemError("Patch paths must be unique, with at most 100 files.")
            seen.add(file)
            creating = old_name == "/dev/null"
            if creating:
                if expected[name] is not None or file.exists():
                    raise FileSystemError("Patch creation requires a missing file and a null expected SHA-256.")
                before, text, newline = None, "", "lf"
            else:
                before = self._check(file, expected[name])
                text, _, _, newline = self._decode(before)
                if newline == "mixed":
                    raise FileSystemError("Unified patches require consistent LF or CRLF newlines.")
            original = text.replace("\r\n", "\n").splitlines(keepends=True)
            result, cursor, hunks = [], 0, 0
            index += 2
            while index < len(lines) and lines[index].startswith("@@ "):
                match = re.match(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(?:.*)\n?$", lines[index])
                if not match:
                    raise FileSystemError("A unified diff hunk header is invalid.")
                old_start, old_count, new_start, new_count = [int(v) if v is not None else 1 for v in match.groups()]
                start = old_start - 1 if old_count else old_start
                if start < cursor or start > len(original):
                    raise FileSystemError("Patch hunks overlap or refer outside the original file.")
                result.extend(original[cursor:start])
                cursor = start
                if (new_start - 1 if new_count else new_start) != len(result):
                    raise FileSystemError("Patch new-file line positions do not match.")
                index += 1
                body, body_old, body_new = [], 0, 0
                while index < len(lines) and lines[index][:1] in (" ", "+", "-"):
                    if body_old >= old_count and body_new >= new_count:
                        break
                    marker = lines[index][0]
                    body.append([marker, lines[index][1:]])
                    body_old += marker in (" ", "-")
                    body_new += marker in (" ", "+")
                    index += 1
                    if index < len(lines) and lines[index].startswith("\\ No newline at end of file"):
                        body[-1][1] = body[-1][1].removesuffix("\n")
                        index += 1
                removed = added = 0
                for marker, content in body:
                    if marker in (" ", "-"):
                        if cursor >= len(original) or original[cursor] != content:
                            raise FileSystemError("Patch context does not match; no files were changed.")
                        cursor += 1
                        removed += 1
                    if marker in (" ", "+"):
                        result.append(content)
                        added += 1
                if removed != old_count or added != new_count:
                    raise FileSystemError("Patch hunk line counts do not match.")
                hunks += 1
            if not hunks:
                raise FileSystemError("Each patched file needs at least one hunk.")
            result.extend(original[cursor:])
            after = None if new_name == "/dev/null" else self._encode("".join(result), before)
            if after is None and result:
                raise FileSystemError("A deletion patch must remove the entire file.")
            if not file.parent.is_dir():
                raise FileSystemError("Create patch parent directories before applying the patch.")
            plans.append((file, before, after))
        if not plans:
            raise FileSystemError("The patch contains no file changes.")
        return plans
