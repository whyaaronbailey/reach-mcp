"""MCP tool surface. Any MCP client (Claude Code, Codex, OpenCode/OpenChamber,
ChatGPT desktop, ...) sees the same tools; nothing here is client-specific."""

from __future__ import annotations

import ctypes
import functools
import inspect
import json
import os
import time
from typing import Annotated, Literal

import anyio
from mcp.server.mcpserver import Image, MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import Field

from . import __version__
from .audit import AuditLog
from .approval import ApprovalError, ApprovalGate
from .capture import CaptureHistory, draw_cursor, encode, fit_scale, scale_image
from .config import Config
from .win import clipboard, screen, windows
from .win import input as winput
from .win.dpi import dpi_mode
from .win.keys import parse_combo

INSTRUCTIONS = """\
Desktop control for the user's Windows PC (screenshots, mouse, keyboard, windows, clipboard).
The server starts in Ask for approval. Every desktop read and action needs an owner decision
unless the owner temporarily chooses Approve for me (a fixed observation-only allowlist) or
Full access in the separate local control panel. Approval waits expire after 60 seconds.
Never attempt to approve your own requests or change the owner's approval settings.

Work in a loop: observe -> act -> verify.
1. Call `reach_screenshot` (or `reach_list_windows`) to see the current state before acting.
2. Act with one small step (reach_click / reach_type_text / reach_press_keys / reach_scroll / reach_drag).
3. Verify with a fresh screenshot (or pass screenshot=true to the action) before the next step.

Coordinates: by default x/y are pixels in the MOST RECENT screenshot image, exactly as you see it;
the server maps them to the real screen. Pass coordinate_space="screen" only for raw physical
screen pixels (e.g. from reach_list_windows). Take a new screenshot after anything moves.

Prefer keyboard shortcuts and `reach_focus_window` over hunting for small targets. Use `reach_type_text` for
text (any Unicode) and `reach_press_keys` for shortcuts like "ctrl+s", "alt+tab", "enter".
Ask the user before irreversible actions (sending, deleting, purchasing, submitting forms,
changing system settings). Never enter passwords or payment details.
If a tool reports the failsafe or pause is active, stop and tell the user.
Elevated (administrator) windows and UAC prompts cannot be controlled; ask the user.
"""

Space = Literal["screenshot", "screen"]
Button = Literal["left", "right", "middle"]
ScreenshotFlag = Annotated[bool, Field(description="Also return a fresh screenshot after the action.")]
XCoord = Annotated[float, Field(description="X in the coordinate space (default: last screenshot image).")]
YCoord = Annotated[float, Field(description="Y in the coordinate space (default: last screenshot image).")]


class PolicyError(RuntimeError):
    pass


def _approval_message(error: ApprovalError) -> str:
    """Only reviewed, static approval outcomes may cross the MCP boundary."""
    reason = str(error)
    if reason == "The owner denied this tool call.":
        return (
            "Reach MCP approval denied; the tool was not executed. "
            "Stop and ask the user before making another request."
        )
    if reason == "Approval timed out; the tool was not executed.":
        return (
            "Reach MCP approval timed out; the tool was not executed. "
            "Ask the user to open the local Reach MCP approval controls, then retry "
            "only when they are ready to approve the new request. "
            "Chat client approval does not replace the local approval."
        )
    safe_reasons = {
        "Approval queue is full; retry after an existing request completes.",
        "Approval controller is closed.",
        "Approval controller closed; the tool was not executed.",
        "Approval mode expired; request approval again.",
        "Approval mode changed; request approval again.",
        "Approval changed; request approval again.",
        "Approval is missing, expired, changed, or already used.",
        "The screenshot changed while approval was pending; take a fresh screenshot and retry.",
        "No screenshot exists; approve a screenshot first or use screen coordinates.",
        "Invalid approval request.",
        "Approval arguments must be finite JSON values.",
        "Approval request is too large.",
    }
    safe_reason = reason if reason in safe_reasons else "Approval was not granted."
    return (
        f"Reach MCP approval blocked; the tool was not executed. {safe_reason} "
        "Ask the user before retrying; never approve your own requests."
    )


def _is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except OSError:
        return False


def build_server(cfg: Config, client_label: str = "", approval_gate: ApprovalGate | None = None) -> MCPServer:
    server = MCPServer(
        name="reach-mcp",
        title="Reach MCP",
        description="Agent-independent Windows desktop control: screenshots, mouse, keyboard, windows.",
        instructions=INSTRUCTIONS,
        version=__version__,
    )
    audit = AuditLog(cfg.audit.path, cfg.audit.enabled, cfg.audit.log_typed_text, client_label)
    approval = approval_gate if approval_gate is not None else ApprovalGate()
    history = CaptureHistory()
    execution_lock = anyio.Lock()

    # ------------------------------------------------------------ helpers

    def check_input_allowed() -> None:
        if cfg.safety.pause_file.exists():
            raise PolicyError(
                f"Paused: {cfg.safety.pause_file} exists. The user has paused desktop control; "
                "stop and ask them before continuing."
            )
        if cfg.safety.failsafe_corner:
            x, y = winput.cursor_pos()
            if x <= 2 and y <= 2:
                raise PolicyError(
                    "Failsafe: the mouse is in the top-left screen corner, which means the user wants "
                    "control back. Stop and ask the user before continuing."
                )

    def settle() -> None:
        if cfg.safety.action_delay_ms:
            time.sleep(cfg.safety.action_delay_ms / 1000)

    def resolve_point(x: float, y: float, space: Space) -> tuple[int, int]:
        if space == "screen":
            return int(x), int(y)
        cap = history.last
        if cap is None:
            raise ValueError("no screenshot yet: call reach_screenshot first, or pass coordinate_space='screen'")
        return cap.to_screen(x, y)

    def take_screenshot(monitor: int | None = None, hwnd: int | None = None,
                        region: list[int] | None = None, max_long_edge: int | None = None):
        if hwnd is not None:
            if not windows.exists(hwnd):
                raise ValueError(f"no window with hwnd {hwnd}")
            left, top, width, height = windows.window_rect(hwnd)
            vl, vt, vw, vh = screen.virtual_screen()  # clip to the desktop
            r, b = min(left + width, vl + vw), min(top + height, vt + vh)
            left, top = max(left, vl), max(top, vt)
            width, height = r - left, b - top
            if width <= 0 or height <= 0:
                raise ValueError("window is off-screen or minimized; call reach_focus_window first")
            source = f"window {hwnd} ({windows.info(hwnd).title[:60]})"
        elif region is not None:
            if len(region) != 4 or region[2] <= 0 or region[3] <= 0:
                raise ValueError("region must be [left, top, width, height] in screen pixels")
            left, top, width, height = (int(v) for v in region)
            source = "region"
        else:
            if monitor is None:
                last = history.last
                mon = None
                if last is not None and last.source.startswith("monitor "):
                    idx = int(last.source.split()[1])
                    mon = next((m for m in screen.monitors() if m.index == idx), None)
                mon = mon or screen.primary()
                left, top, width, height, source = mon.left, mon.top, mon.width, mon.height, f"monitor {mon.index}"
            elif monitor == 0:
                left, top, width, height = screen.virtual_screen()
                source = "monitor 0"
            else:
                mon = next((m for m in screen.monitors() if m.index == monitor), None)
                if mon is None:
                    raise ValueError(f"no monitor {monitor}; see reach_get_screen_info")
                left, top, width, height, source = mon.left, mon.top, mon.width, mon.height, f"monitor {mon.index}"

        img = screen.grab(left, top, width, height)
        scale = fit_scale(width, height, max_long_edge or cfg.screenshot.max_long_edge)
        img = scale_image(img, scale)
        cap = history.new(left=left, top=top, width=width, height=height,
                          image_width=img.width, image_height=img.height, scale=round(scale, 6), source=source)
        cursor = cap.to_image(*winput.cursor_pos())
        if cfg.screenshot.draw_cursor and cursor:
            draw_cursor(img, cursor)
        data = encode(img, cfg.screenshot.format, cfg.screenshot.jpeg_quality)
        meta = (f"Screenshot #{cap.id} of {source}: image {cap.image_width}x{cap.image_height}, "
                f"screen region {width}x{height} at ({left},{top}), scale {cap.scale}. "
                f"Mouse cursor (crosshair) at image {cursor if cursor else 'off-image'}. "
                "x/y for actions are read in this image's pixel space.")
        return [Image(data=data, format=cfg.screenshot.format), meta]

    def with_screenshot(message: str, want: bool):
        if not want:
            return message
        settle()
        return [message, *take_screenshot()]

    def tool(*, read_only: bool = False, destructive: bool = False, title: str | None = None,
             touches_input: bool = False):
        """Register a sync function as an async MCP tool with policy checks and auditing.

        The blocking body runs in a worker thread so slow actions (drag, wait) never stall
        the transport, and desktop operations are serialized by an asynchronous lock.
        """

        def deco(fn):
            name = fn.__name__
            if name in cfg.disabled_tools:
                return fn
            sig = inspect.signature(fn)

            @functools.wraps(fn)
            async def wrapper(*args, **kwargs):
                bound = sig.bind(*args, **kwargs)
                bound.apply_defaults()
                started = time.monotonic()

                approval_args = dict(bound.arguments)
                grant = None
                approved_capture = None

                def run():
                    if approved_capture is not None and history.last is not approved_capture:
                        raise ApprovalError("The screenshot changed while approval was pending; take a fresh screenshot and retry.")
                    approval.consume(grant, name, approval_args, client_label)
                    if touches_input:
                        check_input_allowed()
                    result = fn(*bound.args, **bound.kwargs)
                    if touches_input:
                        settle()
                    return result

                try:
                    # Cached screenshot metadata only: this does not observe the desktop.
                    if touches_input and approval_args.get("coordinate_space") == "screenshot":
                        pairs = []
                        if approval_args.get("x") is not None and approval_args.get("y") is not None:
                            pairs.append((approval_args["x"], approval_args["y"]))
                        if "start_x" in approval_args:
                            pairs.extend([
                                (approval_args["start_x"], approval_args["start_y"]),
                                (approval_args["end_x"], approval_args["end_y"]),
                            ])
                        if pairs:
                            approved_capture = history.last
                            if approved_capture is None:
                                raise ApprovalError("No screenshot exists; approve a screenshot first or use screen coordinates.")
                            approval_args["_screenshot_id"] = approved_capture.id
                            approval_args["_screen_points"] = [list(approved_capture.to_screen(x, y)) for x, y in pairs]
                    grant = await approval.authorize(name, approval_args, client_label)
                    # Wait asynchronously; no cancelled call can be left in a worker
                    # blocked on another desktop operation. Screenshot history cannot
                    # change between its stale check and coordinate dispatch.
                    async with execution_lock:
                        result = await anyio.to_thread.run_sync(run)
                except BaseException as e:  # include cancellation; record each failed call once
                    approval_failure = isinstance(e, (ApprovalError, anyio.get_cancelled_exc_class()))
                    audit_args = {} if approval_failure else dict(bound.arguments)
                    detail = type(e).__name__ if isinstance(e, anyio.get_cancelled_exc_class()) else f"{type(e).__name__}: {e}"
                    audit.record(name, audit_args, False, started, detail)
                    if isinstance(e, ApprovalError):
                        # The SDK masks unanticipated exceptions. Approval outcomes
                        # are expected and safe to explain, without exposing raw errors.
                        raise ToolError(_approval_message(e)) from e
                    raise
                finally:
                    approval.revoke(grant)
                audit.record(name, dict(bound.arguments), True, started)
                return result

            server.tool(
                name=name,
                title=title,
                annotations=ToolAnnotations(
                    title=title,
                    readOnlyHint=read_only,
                    destructiveHint=destructive if not read_only else False,
                    idempotentHint=read_only,
                    openWorldHint=False,
                ),
            )(wrapper)
            return fn

        return deco

    # ------------------------------------------------------------ observe

    @tool(read_only=True, title="Screen info")
    def reach_get_screen_info() -> str:
        """Monitors, virtual desktop bounds, cursor position, foreground window, last screenshot and safety state."""
        fg = windows.foreground()
        return json.dumps({
            "monitors": [m.to_dict() for m in screen.monitors()],
            "virtual_screen": dict(zip(("left", "top", "width", "height"), screen.virtual_screen())),
            "cursor": winput.cursor_pos(),
            "foreground_window": fg.to_dict() if fg else None,
            "last_screenshot": history.last.describe() if history.last else None,
            "dpi_awareness": dpi_mode(),
            "server_elevated": _is_admin(),
            "paused": cfg.safety.pause_file.exists(),
            "pause_file": str(cfg.safety.pause_file),
        }, indent=1)

    @tool(read_only=True, title="Screenshot")
    def reach_screenshot(
        monitor: Annotated[int | None, Field(description="Monitor index from reach_get_screen_info; 0 = all monitors. Default: primary (or the last one captured).")] = None,
        hwnd: Annotated[int | None, Field(description="Capture just this window (from reach_list_windows). It should be in front: call reach_focus_window first.")] = None,
        region: Annotated[list[int] | None, Field(description="[left, top, width, height] in physical screen pixels.")] = None,
        max_long_edge: Annotated[int | None, Field(description="Downscale so the longer side is at most this many pixels.", ge=200, le=4096)] = None,
    ):
        """Capture the screen (or a monitor, window or region). Subsequent x/y arguments refer to this image."""
        return take_screenshot(monitor, hwnd, region, max_long_edge)

    @tool(read_only=True, title="List windows")
    def reach_list_windows(
        title_contains: Annotated[str | None, Field(description="Case-insensitive title filter.")] = None,
        process: Annotated[str | None, Field(description="Process name filter, e.g. 'notepad.exe'.")] = None,
    ) -> str:
        """Visible top-level windows in Z-order (front first), with hwnd, title, process and screen rect."""
        wins = windows.list_windows()
        if title_contains:
            wins = [w for w in wins if title_contains.lower() in w.title.lower()]
        if process:
            wins = [w for w in wins if w.process.lower() == process.lower()]
        return json.dumps([w.to_dict() for w in wins], indent=1, ensure_ascii=False)

    @tool(read_only=True, title="Cursor position")
    def reach_get_cursor_position() -> str:
        """Current mouse position in screen pixels and, if inside it, in the last screenshot's space."""
        sx, sy = winput.cursor_pos()
        img = history.last.to_image(sx, sy) if history.last else None
        return json.dumps({"screen": [sx, sy], "screenshot": img})

    @tool(read_only=True, title="Read clipboard")
    def reach_get_clipboard() -> str:
        """Text currently on the clipboard (empty string if none)."""
        return clipboard.get_text() or ""

    # ------------------------------------------------------------ act

    @tool(title="Focus window", touches_input=True)
    def reach_focus_window(
        hwnd: Annotated[int | None, Field(description="Window handle from reach_list_windows.")] = None,
        title_contains: Annotated[str | None, Field(description="Or: first window whose title contains this.")] = None,
        screenshot: ScreenshotFlag = False,
    ):
        """Restore (if minimized) and bring a window to the foreground."""
        if hwnd is None:
            if not title_contains:
                raise ValueError("pass hwnd or title_contains")
            match = next((w for w in windows.list_windows() if title_contains.lower() in w.title.lower()), None)
            if match is None:
                raise ValueError(f"no visible window title contains {title_contains!r}")
            hwnd = match.hwnd
        ok = windows.activate(hwnd)
        w = windows.info(hwnd)
        msg = (f"Focused {w.title!r} ({w.process})." if ok else
               f"Could not bring {w.title!r} to the foreground (Windows refused focus change).")
        return with_screenshot(msg, screenshot)

    @tool(title="Move mouse", touches_input=True)
    def reach_move_mouse(x: XCoord, y: YCoord, coordinate_space: Space = "screenshot", screenshot: ScreenshotFlag = False):
        """Move the mouse pointer (hover) without clicking."""
        sx, sy = resolve_point(x, y, coordinate_space)
        winput.move_to(sx, sy)
        return with_screenshot(f"Moved to screen ({sx},{sy}).", screenshot)

    @tool(destructive=True, title="Click", touches_input=True)
    def reach_click(
        x: Annotated[float | None, Field(description="X (omit to click at the current pointer position).")] = None,
        y: Annotated[float | None, Field(description="Y (omit to click at the current pointer position).")] = None,
        button: Button = "left",
        clicks: Annotated[int, Field(ge=1, le=3, description="2 = double-click, 3 = triple-click.")] = 1,
        modifiers: Annotated[str | None, Field(description="Keys held during the click, e.g. 'ctrl' or 'ctrl+shift'.")] = None,
        coordinate_space: Space = "screenshot",
        screenshot: ScreenshotFlag = False,
    ):
        """Click a mouse button, optionally at a position and with modifier keys held."""
        if (x is None) != (y is None):
            raise ValueError("pass both x and y, or neither")
        if x is not None:
            sx, sy = resolve_point(x, y, coordinate_space)
            winput.move_to(sx, sy)
            time.sleep(0.03)
        else:
            sx, sy = winput.cursor_pos()
        mods = parse_combo(modifiers) if modifiers else []
        pressed = []
        try:
            for k in mods:
                winput.key_down(k)
                pressed.append(k)
            winput.click(button, clicks)
        finally:
            for k in reversed(pressed):
                winput.key_up(k)
        what = {1: "Clicked", 2: "Double-clicked", 3: "Triple-clicked"}[clicks]
        return with_screenshot(f"{what} {button} at screen ({sx},{sy}).", screenshot)

    @tool(destructive=True, title="Drag", touches_input=True)
    def reach_drag(
        start_x: XCoord, start_y: YCoord, end_x: XCoord, end_y: YCoord,
        button: Button = "left",
        duration_ms: Annotated[int, Field(ge=50, le=5000)] = 400,
        coordinate_space: Space = "screenshot",
        screenshot: ScreenshotFlag = False,
    ):
        """Press at the start point, move smoothly to the end point and release."""
        a = resolve_point(start_x, start_y, coordinate_space)
        b = resolve_point(end_x, end_y, coordinate_space)
        winput.drag([a, b], button, duration_ms / 1000)
        return with_screenshot(f"Dragged {button} from screen {a} to {b}.", screenshot)

    @tool(title="Scroll", touches_input=True)
    def reach_scroll(
        direction: Literal["up", "down", "left", "right"],
        amount: Annotated[int, Field(ge=1, le=50, description="Wheel notches (about 3 lines each).")] = 3,
        x: Annotated[float | None, Field(description="Point to scroll over (omit = current pointer).")] = None,
        y: Annotated[float | None, Field(description="Point to scroll over (omit = current pointer).")] = None,
        coordinate_space: Space = "screenshot",
        screenshot: ScreenshotFlag = False,
    ):
        """Scroll the mouse wheel over a point."""
        if (x is None) != (y is None):
            raise ValueError("pass both x and y, or neither")
        if x is not None:
            winput.move_to(*resolve_point(x, y, coordinate_space))
            time.sleep(0.03)
        winput.scroll(direction, amount)
        return with_screenshot(f"Scrolled {direction} {amount}.", screenshot)

    @tool(destructive=True, title="Type text", touches_input=True)
    def reach_type_text(
        text: Annotated[str, Field(description="Text to type into the focused control. Any Unicode; \\n presses Enter.")],
        screenshot: ScreenshotFlag = False,
    ):
        """Type text into whatever has keyboard focus (click the field first)."""
        if len(text) > cfg.safety.max_type_chars:
            raise ValueError(f"text longer than {cfg.safety.max_type_chars} chars; use reach_set_clipboard + ctrl+v")
        winput.type_unicode(text, check_allowed=check_input_allowed)
        return with_screenshot(f"Typed {len(text)} characters.", screenshot)

    @tool(destructive=True, title="Press keys", touches_input=True)
    def reach_press_keys(
        keys: Annotated[str, Field(description="Key or chord, e.g. 'enter', 'ctrl+s', 'alt+f4', 'win+r', 'shift+tab', 'f5'.")],
        repeat: Annotated[int, Field(ge=1, le=50)] = 1,
        screenshot: ScreenshotFlag = False,
    ):
        """Press a key or a key combination (modifiers are released afterwards)."""
        combo = parse_combo(keys)
        for i in range(repeat):
            winput.press_combo(combo)
            if i + 1 < repeat:
                time.sleep(0.03)
        return with_screenshot(f"Pressed {keys}" + (f" x{repeat}." if repeat > 1 else "."), screenshot)

    @tool(destructive=True, title="Write clipboard", touches_input=True)
    def reach_set_clipboard(text: Annotated[str, Field(description="Text to place on the clipboard.")]) -> str:
        """Replace the clipboard text (paste it with reach_press_keys 'ctrl+v')."""
        clipboard.set_text(text)
        return f"Clipboard set ({len(text)} characters)."

    @tool(destructive=True, title="Launch application", touches_input=True)
    def reach_launch_application(
        target: Annotated[str, Field(description="Program name/path, document path or URL, e.g. 'notepad.exe'.")],
        arguments: Annotated[str, Field(description="Command-line arguments for a program.")] = "",
        screenshot: ScreenshotFlag = False,
    ):
        """Open a program, document or URL the same way Run/double-click would (as the current user)."""
        if not cfg.launch.enabled:
            raise PolicyError("reach_launch_application is disabled in config")
        allowed = [a.lower() for a in cfg.launch.allowed]
        if allowed and target.lower() not in allowed and os.path.basename(target).lower() not in allowed:
            raise PolicyError(f"{target!r} is not in [launch].allowed")
        os.startfile(target, arguments=arguments) if arguments else os.startfile(target)
        if screenshot:
            time.sleep(1.0)  # give the window a moment to appear
        return with_screenshot(f"Launched {target}.", screenshot)

    @tool(read_only=True, title="Wait")
    def reach_wait(
        seconds: Annotated[float, Field(ge=0, le=60)] = 1.0,
        screenshot: ScreenshotFlag = False,
    ):
        """Pause (e.g. for a page or app to load), optionally then take a screenshot."""
        time.sleep(min(seconds, cfg.safety.max_wait_seconds))
        return with_screenshot(f"Waited {seconds}s.", screenshot)

    return server
