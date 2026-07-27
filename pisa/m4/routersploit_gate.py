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
"""
import io
import re
import threading

from routersploit.core.exploit.printer import PrinterThread, printer_queue, thread_output_stream
from routersploit.core.exploit.utils import import_exploit, index_modules

_MODULE_INDEX: dict[str, type] | None = None
_PRINTER_STARTED = False
_PRINTER_LOCK = threading.Lock()
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


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


def run_exploit(device_ip: str, module_path: str, mode: str, port: int | None = None) -> dict:
    """Instantiate the module at module_path, point it at device_ip, and
    run either the safe check() (mode="check") or check()+run() (mode
    ="run", only actually exploits if check() reports vulnerable).
    Never raises — any failure (bad module path, connection error,
    module bug) is caught and reported as {"success": False, "result":
    "error: ..."}, matching every other network-facing module's fail-
    soft convention in this codebase."""
    try:
        index = _load_module_index()
        exploit_cls = index.get(module_path)
        if exploit_cls is None:
            return {"success": False, "result": f"error: unknown module '{module_path}'"}

        instance = exploit_cls()
        instance.target = device_ip
        if port is not None:
            instance.port = port

        success, check_output = _capture_output(instance.check)
        output_parts = [check_output] if check_output else []

        if mode == "run" and success:
            _, run_output = _capture_output(instance.run)
            if run_output:
                output_parts.append(run_output)

        result_text = "\n".join(output_parts).strip() or (
            "Target appears vulnerable." if success else "Target does not appear vulnerable."
        )
        return {"success": bool(success), "result": result_text}
    except Exception as e:
        return {"success": False, "result": f"error: {e}"}
