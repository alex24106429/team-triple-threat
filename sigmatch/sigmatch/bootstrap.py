"""Automatically provision sigmatch's runtime dependencies.

Live event reading needs ``pyetwkit`` (Sysmon ETW provider) and a running
Sysmon service.  Instead of failing immediately when either is missing, this
module installs/starts them on demand and only raises :class:`BootstrapError`
when that is not possible.
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
import zipfile
from pathlib import Path

from .events import SYSMON_CHANNEL


class BootstrapError(RuntimeError):
    """Raised when a required dependency cannot be provisioned automatically."""


def _log(message: str) -> None:
    stream = sys.stderr
    if stream is not None:
        try:
            print(f"[sigmatch] {message}", file=stream, flush=True)
        except Exception:
            pass


def _command_output(completed: subprocess.CompletedProcess[str]) -> str:
    output = "\n".join(
        part.strip() for part in (completed.stdout, completed.stderr) if part and part.strip()
    )
    if len(output) > 4000:
        output = "..." + output[-4000:]
    return output


def _refresh_import_paths() -> None:
    """Apply newly installed site-packages entries without restarting Python."""

    try:
        import importlib
        import site
    except ImportError:  # pragma: no cover - always available
        return

    directories: list[str] = []
    try:
        directories.extend(site.getsitepackages())
    except (AttributeError, TypeError):
        pass
    try:
        directories.append(site.getusersitepackages())
    except (AttributeError, TypeError):
        pass

    for directory in directories:
        if not directory:
            continue
        try:
            site.addsitedir(directory)
        except Exception:
            pass
    importlib.invalidate_caches()


# ---------------------------------------------------------------------------
# pyetwkit (Sysmon ETW provider)
# ---------------------------------------------------------------------------


_pyetwkit_lock = threading.Lock()
_pyetwkit_modules: tuple[object, object] | None = None
_pyetwkit_install_attempted = False

PYETWKIT_HELP = "Install it manually with: python -m pip install pyetwkit"

PYETWKIT_REQUIREMENT = (
    "pyetwkit is required to consume Sysmon ETW events. Prebuilt wheels exist "
    "for 64-bit CPython 3.10-3.14; on older interpreters pip must build it from "
    "source (Rust toolchain required)."
)


def _import_pyetwkit() -> tuple[object, object]:
    from pyetwkit._core import EtwProvider, EtwSession  # type: ignore

    return EtwSession, EtwProvider


def _install_pyetwkit() -> None:
    _log("pyetwkit is missing; installing it automatically...")
    command = [sys.executable, "-m", "pip", "install", "pyetwkit"]
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=900)
    except (OSError, subprocess.SubprocessError) as exc:
        raise BootstrapError(
            f"pyetwkit is required for live Sysmon events and could not be "
            f"installed automatically ({type(exc).__name__}: {exc}). "
            f"{PYETWKIT_REQUIREMENT} {PYETWKIT_HELP}"
        ) from exc

    if completed.returncode != 0:
        output = _command_output(completed)
        details = f": {output}" if output else ""
        raise BootstrapError(
            "pyetwkit is required for live Sysmon events and its automatic "
            f"installation failed (pip exited with {completed.returncode}){details}. "
            f"{PYETWKIT_REQUIREMENT} {PYETWKIT_HELP}"
        )


def ensure_pyetwkit() -> tuple[object, object]:
    """Return ``(EtwSession, EtwProvider)``, installing pyetwkit if needed."""

    global _pyetwkit_modules, _pyetwkit_install_attempted

    if _pyetwkit_modules is not None:
        return _pyetwkit_modules

    try:
        modules = _import_pyetwkit()
    except ImportError as first_error:
        with _pyetwkit_lock:
            if _pyetwkit_modules is not None:
                return _pyetwkit_modules
            if not _pyetwkit_install_attempted:
                _install_pyetwkit()
                _pyetwkit_install_attempted = True
                _refresh_import_paths()
            try:
                modules = _import_pyetwkit()
            except ImportError as exc:
                raise BootstrapError(
                    "pyetwkit is required for live Sysmon events but is still not "
                    f"usable after installation ({type(exc).__name__}: {exc}). "
                    f"{PYETWKIT_REQUIREMENT} {PYETWKIT_HELP}"
                ) from first_error

    _pyetwkit_modules = modules
    return modules


# ---------------------------------------------------------------------------
# Sysmon
# ---------------------------------------------------------------------------


_SYSMON_DOWNLOAD_URL = "https://download.sysinternals.com/files/Sysmon.zip"
_SYSMON_SERVICE_NAMES = ("Sysmon64", "Sysmon")
_SYSMON_PATH_ENV = "SIGMATCH_SYSMON_PATH"
_SYSMON_CONFIG_ENV = "SIGMATCH_SYSMON_CONFIG"

_SC_MANAGER_CONNECT = 0x0001
_SERVICE_QUERY_STATUS = 0x0004
_SERVICE_START = 0x0010
_SC_STATUS_PROCESS_INFO = 0
_SERVICE_STOPPED = 1
_SERVICE_START_PENDING = 2
_SERVICE_STOP_PENDING = 3
_SERVICE_RUNNING = 4
_SERVICE_CONTINUE_PENDING = 5
_SERVICE_PAUSE_PENDING = 6
_SERVICE_PAUSED = 7
_ERROR_SERVICE_DOES_NOT_EXIST = 1060
_ERROR_SERVICE_ALREADY_RUNNING = 1056
_ERROR_ACCESS_DENIED = 5


def _service_module():
    import ctypes
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    advapi32.OpenSCManagerW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.DWORD,
    ]
    advapi32.OpenSCManagerW.restype = wintypes.HANDLE
    advapi32.OpenServiceW.argtypes = [
        wintypes.HANDLE,
        wintypes.LPCWSTR,
        wintypes.DWORD,
    ]
    advapi32.OpenServiceW.restype = wintypes.HANDLE
    advapi32.CloseServiceHandle.argtypes = [wintypes.HANDLE]
    advapi32.CloseServiceHandle.restype = wintypes.BOOL
    advapi32.StartServiceW.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPCWSTR),
    ]
    advapi32.StartServiceW.restype = wintypes.BOOL
    advapi32.QueryServiceStatusEx.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.QueryServiceStatusEx.restype = wintypes.BOOL

    class SERVICE_STATUS_PROCESS(ctypes.Structure):
        _fields_ = [
            ("dwServiceType", wintypes.DWORD),
            ("dwCurrentState", wintypes.DWORD),
            ("dwControlsAccepted", wintypes.DWORD),
            ("dwWin32ExitCode", wintypes.DWORD),
            ("dwServiceSpecificExitCode", wintypes.DWORD),
            ("dwCheckPoint", wintypes.DWORD),
            ("dwWaitHint", wintypes.DWORD),
            ("dwProcessId", wintypes.DWORD),
            ("dwServiceFlags", wintypes.DWORD),
        ]

    return ctypes, wintypes, advapi32, SERVICE_STATUS_PROCESS


def _open_service_manager(advapi32, ctypes):
    scm = advapi32.OpenSCManagerW(None, None, _SC_MANAGER_CONNECT)
    if not scm:
        error = ctypes.get_last_error()
        hint = (
            " Run sigmatch as administrator."
            if error == _ERROR_ACCESS_DENIED
            else ""
        )
        raise BootstrapError(
            "could not automatically install or start Sysmon: could not open the "
            f"Windows service manager (error {error}).{hint}"
        )
    return scm


def _open_service(advapi32, ctypes, wintypes, scm, name: str, access: int):
    service = advapi32.OpenServiceW(scm, name, access)
    if service:
        return service
    error = ctypes.get_last_error()
    if error == _ERROR_SERVICE_DOES_NOT_EXIST:
        return None
    hint = (
        " Run sigmatch as administrator."
        if error == _ERROR_ACCESS_DENIED
        else ""
    )
    raise BootstrapError(
        "could not automatically install or start Sysmon: could not open the "
        f"{name} service (Windows error {error}).{hint}"
    )


def _query_service_state(name: str) -> int | None:
    ctypes, wintypes, advapi32, status_type = _service_module()
    scm = _open_service_manager(advapi32, ctypes)
    try:
        service = _open_service(
            advapi32, ctypes, wintypes, scm, name, _SERVICE_QUERY_STATUS
        )
        if service is None:
            return None
        try:
            status = status_type()
            needed = wintypes.DWORD()
            ok = advapi32.QueryServiceStatusEx(
                service,
                _SC_STATUS_PROCESS_INFO,
                ctypes.byref(status),
                ctypes.sizeof(status),
                ctypes.byref(needed),
            )
            if not ok:
                error = ctypes.get_last_error()
                raise BootstrapError(
                    "could not automatically install or start Sysmon: could not "
                    f"query the {name} service state (Windows error {error})."
                )
            return int(status.dwCurrentState)
        finally:
            advapi32.CloseServiceHandle(service)
    finally:
        advapi32.CloseServiceHandle(scm)


def _find_sysmon_service() -> tuple[str | None, int | None]:
    for name in _SYSMON_SERVICE_NAMES:
        state = _query_service_state(name)
        if state is not None:
            return name, state
    return None, None


def _start_service(name: str) -> None:
    ctypes, wintypes, advapi32, _ = _service_module()
    scm = _open_service_manager(advapi32, ctypes)
    try:
        service = _open_service(
            advapi32,
            ctypes,
            wintypes,
            scm,
            name,
            _SERVICE_QUERY_STATUS | _SERVICE_START,
        )
        if service is None:
            raise BootstrapError(
                "could not automatically start Sysmon: the "
                f"{name} service disappeared before it could be started."
            )
        try:
            if not advapi32.StartServiceW(service, 0, None):
                error = ctypes.get_last_error()
                if error != _ERROR_SERVICE_ALREADY_RUNNING:
                    hint = (
                        " Run sigmatch as administrator."
                        if error == _ERROR_ACCESS_DENIED
                        else ""
                    )
                    raise BootstrapError(
                        "could not automatically start Sysmon: could not start "
                        f"the {name} service (Windows error {error}).{hint}"
                    )
        finally:
            advapi32.CloseServiceHandle(service)
    finally:
        advapi32.CloseServiceHandle(scm)

    _wait_for_service(name, _SERVICE_RUNNING, timeout=30.0)


def _wait_for_service(name: str, expected: int, *, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    last_state: int | None = None
    while time.monotonic() < deadline:
        last_state = _query_service_state(name)
        if last_state == expected:
            return
        time.sleep(0.5)
    raise BootstrapError(
        "could not automatically start Sysmon: the "
        f"{name} service did not reach the expected state {expected} "
        f"(last state: {last_state})."
    )


def _is_64_bit() -> bool:
    machine = platform.machine().casefold()
    return (
        sys.maxsize > 2**32
        or machine in {"amd64", "x86_64", "arm64", "aarch64"}
    )


def _sysmon_executable_name() -> str:
    return "Sysmon64.exe" if _is_64_bit() else "Sysmon.exe"


def _project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _cache_directory() -> Path:
    base = os.environ.get("LOCALAPPDATA") or os.environ.get("TEMP")
    if not base:
        base = tempfile.gettempdir()
    return Path(base) / "sigmatch" / "sysmon"


def _candidate_sysmon_paths() -> list[Path]:
    name = _sysmon_executable_name()
    candidates: list[Path] = []

    configured = os.environ.get(_SYSMON_PATH_ENV)
    if configured:
        candidates.append(Path(configured))

    for found in (shutil.which(name), shutil.which("Sysmon64.exe"), shutil.which("Sysmon.exe")):
        if found:
            candidates.append(Path(found))

    candidates.extend(
        [
            _project_root() / name,
            Path.cwd() / name,
            _cache_directory() / name,
        ]
    )

    windows_dir = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    candidates.extend(
        [
            windows_dir / "System32" / name,
            windows_dir / "Sysmon" / name,
            Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Sysmon" / name,
        ]
    )
    return candidates


def _locate_sysmon_executable() -> Path | None:
    for candidate in _candidate_sysmon_paths():
        try:
            if candidate.is_file():
                return candidate
        except OSError:
            continue
    return None


def _download_sysmon() -> Path:
    target = _cache_directory()
    executable = target / _sysmon_executable_name()
    if executable.is_file():
        return executable

    target.mkdir(parents=True, exist_ok=True)
    _log("downloading Sysmon from Microsoft Sysinternals...")
    try:
        with urllib.request.urlopen(_SYSMON_DOWNLOAD_URL, timeout=60) as response:
            payload = response.read(64 * 1024 * 1024)
    except Exception as exc:
        raise BootstrapError(
            "Sysmon is not installed and could not be downloaded automatically "
            f"from {_SYSMON_DOWNLOAD_URL} ({type(exc).__name__}: {exc}). "
            "Install Sysmon manually and make sure its service is running."
        ) from exc

    archive = target / "Sysmon.zip"
    try:
        archive.write_bytes(payload)
        with zipfile.ZipFile(archive) as bundle:
            for member in ("Sysmon.exe", "Sysmon64.exe", "Eula.txt"):
                if member in bundle.namelist():
                    bundle.extract(member, target)
    except Exception as exc:
        raise BootstrapError(
            "Sysmon was downloaded but the distribution archive could not be "
            f"unpacked ({type(exc).__name__}: {exc}). "
            "Install Sysmon manually and make sure its service is running."
        ) from exc

    if not executable.is_file():
        raise BootstrapError(
            f"the downloaded Sysmon archive did not contain {executable.name}. "
            "Install Sysmon manually and make sure its service is running."
        )
    return executable


def _sysmon_config_path() -> Path | None:
    configured = os.environ.get(_SYSMON_CONFIG_ENV)
    candidates = [Path(configured)] if configured else []
    candidates.extend(
        [
            Path.cwd() / "config" / "sysmon-sigmatch.xml",
            _project_root() / "config" / "sysmon-sigmatch.xml",
        ]
    )
    for candidate in candidates:
        try:
            if candidate.is_file():
                return candidate
        except OSError:
            continue
    return None


def _install_sysmon() -> None:
    executable = _locate_sysmon_executable()
    if executable is None:
        executable = _download_sysmon()

    config = _sysmon_config_path()
    command = [str(executable), "-accepteula", "-i"]
    if config is not None:
        command.append(str(config))

    _log("Sysmon is not installed; installing it automatically...")
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=180,
            creationflags=creationflags,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise BootstrapError(
            "Sysmon is not installed and could not be installed automatically "
            f"({type(exc).__name__}: {exc}). "
            "Install Sysmon manually and make sure its service is running."
        ) from exc

    if completed.returncode != 0:
        output = _command_output(completed)
        details = f": {output}" if output else ""
        raise BootstrapError(
            "Sysmon is not installed and its automatic installation failed "
            f"(installer exited with {completed.returncode}){details}. "
            "Install Sysmon manually and make sure its service is running."
        )


def ensure_sysmon(channel: str = SYSMON_CHANNEL) -> None:
    """Ensure the Sysmon service for *channel* exists and is running.

    Installs Sysmon (downloading it from Microsoft Sysinternals if necessary)
    when it is missing, and starts an existing but stopped service.
    """

    if sys.platform != "win32":
        return
    if channel.casefold() != SYSMON_CHANNEL.casefold():
        return

    name, state = _find_sysmon_service()
    if name is not None:
        if state == _SERVICE_RUNNING:
            return
        if state == _SERVICE_STOP_PENDING:
            _wait_for_service(name, _SERVICE_STOPPED, timeout=30.0)
        elif state in {
            _SERVICE_START_PENDING,
            _SERVICE_CONTINUE_PENDING,
            _SERVICE_PAUSE_PENDING,
        }:
            _wait_for_service(name, _SERVICE_RUNNING, timeout=30.0)
            return
        _log(f"the {name} service is not running; starting it automatically...")
        _start_service(name)
        return

    _install_sysmon()
    name, state = _find_sysmon_service()
    if name is None:
        raise BootstrapError(
            "could not automatically install Sysmon: the installer completed but "
            "Windows did not create a Sysmon service. Install Sysmon manually "
            "and make sure its service is running."
        )
    if state != _SERVICE_RUNNING:
        _log(f"the {name} service is not running; starting it automatically...")
        _start_service(name)
