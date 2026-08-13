"""RouterSploit integration for FR-10 (authorized exploit verification).

RouterSploit isn't designed to be driven programmatically — its own
interactive console (rsf.py) is the only "supported" entry point — so
this module reverse-engineers the two seams that matter:

1. Module discovery: `index_modules()`/`import_exploit()` give us every
   `Exploit` class, each with an `__info__` dict (Python name-mangled to
   `_Exploit__info__` since every module names its class literally
   `Exploit`). There's no CVE-indexed search built in, so
   `find_modules_for_cve` does a literal substring match — RouterSploit's
   own coverage of any given CVE is inherently partial (verified: only
   24 of 358 modules reference an explicit CVE ID at all), so an empty
   result here is the common case, not a bug.

2. Output capture: RouterSploit prints via its own async PrinterThread
   (a queue drained on a background thread, never auto-started outside
   rsf.py) rather than returning structured results from check()/run().
   _capture_output reuses RouterSploit's own thread_output_stream
   mechanism (the same one their `mute` decorator uses) to redirect a
   single call's output into a buffer, then drains the queue with
   printer_queue.join() before reading it back.

Phase 7 additions (concrete issues identified in earlier audits, fixed
here rather than in a rewrite):

3. Tri-state check() result. RouterSploit's check() can return True,
   False, or None ("could not verify" — e.g. misfortune_cookie.py).
   `bool(None) == False`, so a naive `bool(check_result)` silently turns
   "inconclusive" into "confirmed not vulnerable." _classify_check_result
   preserves all three states explicitly; run_exploit() returns both the
   detailed state and a backward-compatible `success` bool derived from
   it (never the other way around).

4. Interactive shell() detection. Confirmed via direct inspection of the
   installed package: 53 of its exploit modules call `shell()`
   (routersploit/core/exploit/shell.py), an interactive `input()`-loop
   console meant for rsf.py's own TTY — calling it through this adapter
   with no attached terminal blocks forever. _uses_interactive_shell
   detects this statically (the name `shell` appearing in run()'s own
   bytecode co_names — confirmed empirically to correctly flag a known
   interactive module and clear two verified-safe ones) so run_exploit()
   can refuse mode="run" on such a module instead of hanging.

5. Bounded timeout. check()/run() now execute inside a single-worker
   thread pool with .result(timeout=...) — the caller is guaranteed
   control back within config.EXPLOIT_TIMEOUT regardless of what
   RouterSploit's own call is doing. This is a real, documented
   limitation, not true process isolation: CPython cannot forcibly kill
   a thread, so a call that ignores the timeout keeps running in the
   background (leaked, not orphaned as a separate OS process) — see
   .scratch/pisa-phase7-exploitation.md.
"""
import io
import re
import threading
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError

from routersploit.core.exploit.printer import PrinterThread, printer_queue, thread_output_stream
from routersploit.core.exploit.utils import import_exploit, index_modules

import config

_MODULE_INDEX: dict[str, type] | None = None
_PRINTER_STARTED = False
_PRINTER_LOCK = threading.Lock()
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

CHECK_CONFIRMED_VULNERABLE = "CONFIRMED_VULNERABLE"
CHECK_CONFIRMED_NOT_VULNERABLE = "CONFIRMED_NOT_VULNERABLE"
CHECK_INCONCLUSIVE = "INCONCLUSIVE"

# Single-worker pool: exploit attempts are already serialized by the
# calling route's synchronous request handling, and a shared pool with
# .result(timeout=) is simpler and safer than spawning a bare Thread per
# call (no thread-object bookkeeping, no manual daemon flag to remember).
_EXPLOIT_EXECUTOR = ThreadPoolExecutor(max_workers=4, thread_name_prefix="routersploit-exploit")


def _classify_check_result(raw) -> str:
    """True/False/None -> the tri-state PISA actually persists. Anything
    else RouterSploit might theoretically return (a module bug) also
    falls through to INCONCLUSIVE rather than being coerced — the same
    "don't guess" stance as every other tri-state decision in this
    project."""
    if raw is True:
        return CHECK_CONFIRMED_VULNERABLE
    if raw is False:
        return CHECK_CONFIRMED_NOT_VULNERABLE
    return CHECK_INCONCLUSIVE


def _uses_interactive_shell(exploit_cls: type) -> bool:
    """Static detection: does this module's run() method reference the
    global name `shell` (routersploit.core.exploit.shell.shell, called as
    `shell(self, ...)`) anywhere in its bytecode? Confirmed empirically
    against the installed package: True for a known interactive module
    (routers.netgear.dgn2200_ping_cgi_rce), False for both modules this
    project actually registers as supported (see pisa/m3/exploitation.py)."""
    run = getattr(exploit_cls, "run", None)
    code = getattr(run, "__code__", None)
    if code is None:
        return False
    return "shell" in code.co_names


def _ensure_printer_started() -> None:
    global _PRINTER_STARTED
    with _PRINTER_LOCK:
        if not _PRINTER_STARTED:
            PrinterThread().start()
            _PRINTER_STARTED = True


def _load_module_index() -> dict[str, type]:
    global _MODULE_INDEX
    if _MODULE_INDEX is not None:
        return _MODULE_INDEX

    index: dict[str, type] = {}
    for relative_path in index_modules():
        full_path = "routersploit.modules." + relative_path
        try:
            index[relative_path] = import_exploit(full_path)
        except Exception as e:
            print(f"[RouterSploit] Skipping unloadable module {relative_path}: {e}")
    _MODULE_INDEX = index
    return index


def _module_info(exploit_cls: type) -> dict:
    return getattr(exploit_cls, "_Exploit__info__", {}) or {}


def find_modules_for_cve(cve_id: str) -> list[dict]:
    """Search the module index for exploits referencing this CVE by
    literal ID match. Returns [] — not an error — when nothing matches,
    which is the common case (RouterSploit only explicitly cites a CVE
    in a minority of its modules)."""
    needle = cve_id.strip().lower()
    if not needle:
        return []

    matches = []
    for module_path, exploit_cls in _load_module_index().items():
        info = _module_info(exploit_cls)
        haystack = " ".join([
            str(info.get("name", "")),
            str(info.get("description", "")),
            " ".join(info.get("references", ()) or ()),
        ]).lower()
        if needle in haystack:
            matches.append({
                "module_path": module_path,
                "name": info.get("name"),
                "description": info.get("description"),
                "references": list(info.get("references", ()) or ()),
                "devices": list(info.get("devices", ()) or ()),
            })
    return matches


def _capture_output(fn) -> tuple:
    """Run fn() with RouterSploit's print output redirected into a
    buffer for the calling thread. Returns (fn's return value, captured
    text with ANSI color codes stripped)."""
    _ensure_printer_started()
    thread = threading.current_thread()
    buffer = io.StringIO()
    thread_output_stream.setdefault(thread, []).append(buffer)
    try:
        result = fn()
    finally:
        printer_queue.join()
        thread_output_stream[thread].pop()
    return result, _ANSI_RE.sub("", buffer.getvalue())


def _run_with_timeout(fn, timeout: float) -> tuple:
    """Runs _capture_output(fn) inside the shared executor. Returns
    (state, raw_result, output_text) where state is "ok"/"timeout"/
    "error" — never raises. This is what actually bounds a call to
    RouterSploit's check()/run(): the caller gets control back within
    `timeout` regardless of what fn() is doing, even though (CPython
    limitation, documented in the module docstring) the underlying
    thread cannot be forcibly killed if it doesn't return on its own."""
    future = _EXPLOIT_EXECUTOR.submit(_capture_output, fn)
    try:
        raw_result, output = future.result(timeout=timeout)
        return "ok", raw_result, output
    except FutureTimeoutError:
        return "timeout", None, ""
    except Exception as e:
        return "error", None, f"error: {e}"


def run_exploit(device_ip: str, module_path: str, mode: str, port: int | None = None) -> dict:
    """Instantiate the module at module_path, point it at device_ip, and
    run either the safe check() (mode="check") or check()+run() (mode
    ="run", only actually exploits if check() confirmed vulnerable).
    Never raises — any failure (bad module path, connection error,
    module bug, timeout, unsupported interactive module) is caught and
    reported as {"success": False, ...}, matching every other network-
    facing module's fail-soft convention in this codebase.

    Returns, in addition to the original `success`/`result` keys (kept
    for backward compatibility — every existing caller/test that reads
    only those two keys is unaffected):
      check_state:  CONFIRMED_VULNERABLE / CONFIRMED_NOT_VULNERABLE /
                    INCONCLUSIVE — the tri-state check() actually
                    produced, never collapsed via bare bool().
      timeout:      True if this attempt hit config.EXPLOIT_TIMEOUT.
      unsupported:  True if mode="run" was requested on a module that
                    uses RouterSploit's interactive shell() console —
                    refused outright rather than attempted and hung.
    """
    try:
        index = _load_module_index()
        exploit_cls = index.get(module_path)
        if exploit_cls is None:
            return {
                "success": False, "check_state": CHECK_INCONCLUSIVE,
                "result": f"error: unknown module '{module_path}'",
            }

        if mode == "run" and _uses_interactive_shell(exploit_cls):
            return {
                "success": False, "check_state": CHECK_INCONCLUSIVE, "unsupported": True,
                "result": (
                    "error: this module requires RouterSploit's interactive shell() console "
                    "(input()-based) and is not supported by PISA's automated adapter."
                ),
            }

        instance = exploit_cls()
        instance.target = device_ip
        if port is not None:
            instance.port = port

        state, raw_check, check_output = _run_with_timeout(instance.check, config.EXPLOIT_TIMEOUT)
        if state == "timeout":
            return {
                "success": False, "check_state": CHECK_INCONCLUSIVE, "timeout": True,
                "result": f"error: check() did not complete within {config.EXPLOIT_TIMEOUT}s",
            }
        if state == "error":
            return {"success": False, "check_state": CHECK_INCONCLUSIVE, "result": check_output}

        check_state = _classify_check_result(raw_check)
        output_parts = [check_output] if check_output else []

        if mode == "run" and check_state == CHECK_CONFIRMED_VULNERABLE:
            run_state, _, run_output = _run_with_timeout(instance.run, config.EXPLOIT_TIMEOUT)
            if run_state == "timeout":
                output_parts.append(f"error: run() did not complete within {config.EXPLOIT_TIMEOUT}s")
                return {
                    "success": False, "check_state": check_state, "timeout": True,
                    "result": "\n".join(output_parts).strip(),
                }
            if run_state == "error":
                return {"success": False, "check_state": check_state, "result": run_output}
            if run_output:
                output_parts.append(run_output)

        result_text = "\n".join(output_parts).strip() or (
            "Target appears vulnerable." if check_state == CHECK_CONFIRMED_VULNERABLE
            else "Target does not appear vulnerable."
        )
        return {"success": check_state == CHECK_CONFIRMED_VULNERABLE, "check_state": check_state, "result": result_text}
    except Exception as e:
        return {"success": False, "check_state": CHECK_INCONCLUSIVE, "result": f"error: {e}"}
