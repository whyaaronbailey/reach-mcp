"""Direct developer tools, sharing native approval, audit and pause policy."""
from __future__ import annotations

from typing import Annotated, Literal
from pydantic import Field

from . import config as config_module
from .filesystem import FileSystem, FileSystemError
from .processes import ProcessManager

PathArg = Annotated[str, Field(max_length=4096)]
Payload = Annotated[str, Field(max_length=60000)]
Digest = Annotated[str, Field(pattern=r"^[0-9a-fA-F]{64}$")]


def register_development_tools(tool, cfg, check_allowed):
    # Installed first run must work even when no audit log has created state yet.
    # Only the application's default state workspace is created automatically.
    if cfg.filesystem.workspace == config_module.PROJECT_ROOT:
        cfg.filesystem.workspace.mkdir(parents=True, exist_ok=True)
    fs = FileSystem(cfg.filesystem.allowed_roots, cfg.filesystem.workspace,
                    max_file_bytes=cfg.filesystem.max_file_bytes,
                    max_results=cfg.filesystem.max_results)
    manager = ProcessManager(
        max_jobs=cfg.execution.max_jobs, max_history=cfg.execution.max_history,
        max_output_bytes=cfg.execution.max_output_bytes,
        max_runtime_seconds=cfg.execution.max_runtime_seconds,
        max_stdin_chars=cfg.execution.max_stdin_chars,
        safety_check=check_allowed,
    ) if cfg.execution.enabled else None

    @tool(read_only=True, serialized=False, title="Capabilities and workspace")
    def reach_get_capabilities() -> dict:
        """Discover enabled capabilities, file roots, command limits and safety behavior."""
        return {
            "filesystem": {
                "enabled": cfg.filesystem.enabled,
                "workspace": str(cfg.filesystem.workspace),
                "allowed_roots": [str(p) for p in cfg.filesystem.allowed_roots],
                "max_file_bytes": cfg.filesystem.max_file_bytes,
                "max_results": cfg.filesystem.max_results,
                "patch_format": "standard unified diff; expected_sha256 maps paths to hashes (null for new files)",
                "requires_hash_before_overwrite": True,
            },
            "execution": {
                "enabled": cfg.execution.enabled,
                "max_jobs": cfg.execution.max_jobs,
                "max_runtime_seconds": cfg.execution.max_runtime_seconds,
                "max_output_bytes": cfg.execution.max_output_bytes,
                "identity": "same normal Windows user as Reach",
                "sandbox": False,
            },
            "disabled_tools": cfg.disabled_tools,
            "safety": "PAUSED or the mouse corner blocks mutations and stops managed commands. Reads/cancellation remain available.",
            "usage": "Reach does not call a model. Running an AI CLI through terminal uses that client's normal allowance.",
        }

    if cfg.filesystem.enabled:
        @tool(read_only=True, serialized=False, title="List directory")
        def reach_list_directory(path: PathArg = ".", recursive: bool = False,
                                 limit: Annotated[int, Field(ge=1, le=1000)] = 200) -> dict:
            """List bounded entries inside configured local roots; no symlinks or network shares."""
            return fs.list_directory(path, recursive=recursive, limit=limit)

        @tool(read_only=True, serialized=False, title="Read text file")
        def reach_read_file(path: PathArg, start_line: Annotated[int, Field(ge=1)] = 1,
                            end_line: Annotated[int | None, Field(ge=1)] = None) -> dict:
            """Read text and full-file SHA256. Use the hash for subsequent edits."""
            return fs.read_text(path, start_line=start_line, end_line=end_line)

        @tool(read_only=True, serialized=False, title="Search files and text")
        def reach_search_files(query: Annotated[str, Field(max_length=1000)],
                               path: PathArg = ".", glob: str = "*",
                               case_sensitive: bool = False, filenames: bool = False,
                               limit: Annotated[int, Field(ge=1, le=1000)] = 100) -> dict:
            """Bounded literal text search, or filename search. Use glob to filter files."""
            return fs.search(query, path, glob=glob, case_sensitive=case_sensitive,
                             filenames=filenames, limit=limit)

        @tool(destructive=True, serialized=False, mutates_workspace=True, title="Write text file")
        def reach_write_file(path: PathArg, content: Payload, expected_sha256: Digest | None = None,
                             create: bool = False) -> dict:
            """Create a file with create=true, or replace existing text using its current SHA256."""
            return fs.write_text(path, content, expected_sha256=expected_sha256, create=create)

        @tool(destructive=True, serialized=False, mutates_workspace=True, title="Replace exact text")
        def reach_replace_text(path: PathArg, old: Payload, new: Payload,
                               expected_sha256: Digest,
                               occurrences: Annotated[int, Field(ge=1, le=10000)] = 1) -> dict:
            """Replace exact text only when hash and occurrence count match; preserve encoding/newlines."""
            return fs.replace_text(path, old, new, expected_sha256, occurrences=occurrences)

        @tool(destructive=True, serialized=False, mutates_workspace=True, title="Apply unified patch")
        def reach_apply_patch(patch: Payload, expected_sha256: dict[str, str | None]) -> dict:
            """Apply standard unified diff with exact context. Supply current hashes; null for creation."""
            return fs.apply_patch(patch, expected_sha256)

        @tool(serialized=False, mutates_workspace=True, title="Create directory")
        def reach_make_directory(path: PathArg) -> dict:
            """Create a local directory inside a configured file root."""
            return fs.make_directory(path)

        @tool(destructive=True, serialized=False, mutates_workspace=True, title="Move file or empty directory")
        def reach_move_file(source: PathArg, destination: PathArg,
                            expected_sha256: Digest | None = None) -> dict:
            """Move without overwriting. Supply current hash for files; directories must be empty."""
            return fs.move(source, destination, expected_sha256=expected_sha256)

        @tool(destructive=True, serialized=False, mutates_workspace=True, title="Remove file or empty directory")
        def reach_remove_file(path: PathArg, expected_sha256: Digest | None = None) -> dict:
            """Delete one file using its current hash, or one empty directory. No recursive delete."""
            return fs.remove(path, expected_sha256=expected_sha256)

    if manager is not None:
        @tool(destructive=True, serialized=False, mutates_workspace=True,
              open_world=True, title="Run terminal command")
        def reach_run_command(
            command: Annotated[str | list[str], Field(description="PowerShell/cmd script, or argv array for shell=program.")],
            cwd: PathArg = ".",
            shell: Literal["powershell", "cmd", "program"] = "powershell",
            timeout_seconds: Annotated[float, Field(ge=1, le=86400)] = 300,
            wait_seconds: Annotated[float, Field(ge=0, le=10)] = 1,
        ) -> dict:
            """Run as the normal VM user; returns job id, bounded stdout/stderr and exit status.
            Use shell=program with an argv array for exact executable arguments. Poll long jobs.
            Commands may access files/network beyond file-tool roots; this is not a sandbox."""
            directory = fs.resolve_path(cwd, directory=True)
            return manager.start(command, directory, shell=shell,
                                 timeout_seconds=timeout_seconds, wait_seconds=wait_seconds)

        @tool(read_only=True, serialized=False, title="Read terminal output")
        def reach_read_process(job_id: str, cursor: Annotated[int, Field(ge=0)] = 0,
                               max_chars: Annotated[int, Field(ge=1, le=60000)] = 20000,
                               wait_seconds: Annotated[float, Field(ge=0, le=10)] = 0) -> dict:
            """Read output/status since cursor; keep next_cursor. Truncated output cannot be recovered."""
            return manager.read(job_id, cursor=cursor, max_chars=max_chars, wait_seconds=wait_seconds)

        @tool(destructive=True, serialized=False, mutates_workspace=True,
              open_world=True, title="Send terminal input")
        def reach_write_process(job_id: str, text: Payload = "", close: bool = False) -> dict:
            """Send UTF-8 text to stdin (include newline when needed); optionally close stdin."""
            return manager.write_stdin(job_id, text, close=close)

        @tool(destructive=True, serialized=False, title="Cancel terminal job")
        def reach_cancel_process(job_id: str) -> dict:
            """Stop the managed process tree. Prior side effects remain; inspect before retrying."""
            return manager.cancel(job_id)

        @tool(read_only=True, serialized=False, title="List terminal jobs")
        def reach_list_processes() -> dict:
            """List this Reach process manager's jobs and status; does not enumerate unrelated processes."""
            return {"jobs": manager.list_jobs()}

    return manager
