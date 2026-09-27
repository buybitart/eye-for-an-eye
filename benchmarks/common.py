"""Benchmark-only environment, measurements and finite process watchdog."""
import ctypes
from ctypes import wintypes
from dataclasses import asdict
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time
from benchmarks.p3_deception import resources
from eye_for_an_eye.config import Config
from eye_for_an_eye.deception.profiles import CATALOGUE_VERSION

SEED = 20260908


def source_hash():
    digest = hashlib.sha256()
    for path in sorted(Path('eye_for_an_eye').rglob('*.py')):
        digest.update(path.as_posix().encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()


def _kernel_settings():
    """What was tuned, said about the machine the run actually happened on."""
    if sys.platform.startswith('linux'):
        return 'Linux: stock distribution sysctl, no tuning applied by this harness'
    if sys.platform == 'win32':
        return 'Windows defaults; no tuning'
    return f'{sys.platform}: defaults; no tuning'


def environment():
    ram = None
    cpu = platform.processor()
    if sys.platform.startswith('linux'):
        # Both of these were previously wrong on Linux: RAM came back null
        # because only the Windows branch filled it, and every benchmark report
        # produced on Linux carried the sentence "Windows defaults". A
        # performance baseline whose environment block describes a different
        # operating system is not a baseline anybody can compare against.
        try:
            for line in Path('/proc/meminfo').read_text(encoding='utf-8').splitlines():
                if line.startswith('MemTotal:'):
                    ram = int(line.split()[1]) * 1024
                    break
        except (OSError, ValueError, IndexError):
            ram = None
        try:
            for line in Path('/proc/cpuinfo').read_text(encoding='utf-8').splitlines():
                if line.startswith('model name'):
                    cpu = line.split(':', 1)[1].strip()
                    break
        except (OSError, IndexError):
            pass
    if sys.platform == 'win32':
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'HARDWARE\DESCRIPTION\System\CentralProcessor\0') as key:
            cpu = winreg.QueryValueEx(key, 'ProcessorNameString')[0].strip()
        class Memory(ctypes.Structure):
            _fields_ = [('length', wintypes.DWORD), ('load', wintypes.DWORD)] + [
                (name, ctypes.c_ulonglong) for name in ('total', 'available', 'page_total', 'page_available',
                                                       'virtual_total', 'virtual_available', 'extended')]
        memory = Memory()
        memory.length = ctypes.sizeof(memory)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(memory)):
            ram = memory.total
    return {'python': sys.version, 'os': platform.platform(), 'cpu': cpu, 'logical_cpus': os.cpu_count(),
        'physical_ram_bytes': ram, 'kernel_settings': _kernel_settings(),
        'dependencies': sorted((item.metadata['Name'], item.version) for item in importlib.metadata.distributions()),
        'source_sha256': source_hash(), 'git': 'absent; pre-P5 SHA256/text snapshot retained',
        'seed': SEED, 'catalogue_version': CATALOGUE_VERSION}


def percentiles(values):
    ordered = sorted(values)
    return {name: ordered[int((len(ordered) - 1) * fraction)] if ordered else None
            for name, fraction in (('p50_ms', .5), ('p95_ms', .95), ('p99_ms', .99), ('max_ms', 1))}


def measure(count, callback):
    latencies = []
    before = resources()
    started, cpu = time.perf_counter(), time.process_time()
    for index in range(count):
        stamp = time.perf_counter()
        callback(index)
        latencies.append((time.perf_counter() - stamp) * 1000)
    elapsed = time.perf_counter() - started
    return {'operations': count, 'seconds': elapsed, 'operations_per_second': count / elapsed,
            'cpu_seconds': time.process_time() - cpu, **percentiles(latencies),
            'resources_before': before, 'resources_after': resources()}


def config():
    settings = Config()
    settings.correlation.max_events_per_source = 64
    return settings


def configuration(settings):
    return asdict(settings)


def child_usage(process):
    """Parent-side RSS/CPU monitor; includes root worker, not provider descendants."""
    if sys.platform == 'win32':
        class Memory(ctypes.Structure):
            _fields_ = [('cb', wintypes.DWORD), ('faults', wintypes.DWORD)] + [
                (key, ctypes.c_size_t) for key in ('peak_ws', 'ws', 'peak_pool', 'pool', 'peak_nonpool',
                                                   'nonpool', 'page', 'peak_page')]
        memory = Memory()
        memory.cb = ctypes.sizeof(memory)
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        query = ctypes.WinDLL('psapi', use_last_error=True).GetProcessMemoryInfo
        query.argtypes = [wintypes.HANDLE, ctypes.POINTER(Memory), wintypes.DWORD]
        handle = wintypes.HANDLE(int(process._handle))
        if not query(handle, ctypes.byref(memory), memory.cb):
            return None
        times = [wintypes.FILETIME() for _ in range(4)]
        get_times = kernel.GetProcessTimes
        get_times.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
        get_times(handle, *(ctypes.byref(value) for value in times))
        cpu = sum((value.dwHighDateTime << 32) | value.dwLowDateTime for value in times[2:]) / 10_000_000
        return memory.ws, cpu
    status = Path(f'/proc/{process.pid}/status')
    if status.exists():
        values = status.read_text()
        rss = next((line for line in values.splitlines() if line.startswith('VmRSS:')), '')
        return (int(rss.split()[1]) * 1024 if rss else 0), None
    return None


def guarded(argv, *, wall=120, cpu=90, memory=536870912):
    """Fixed local child argv only; watchdog never accepts a target host."""
    if not 1 <= wall <= 3600 or not 1 <= cpu <= 3600 or not 33_554_432 <= memory <= 1_073_741_824:
        raise ValueError('watchdog budget')
    import tempfile
    root = Path('.p5-check/tmp').resolve()
    if not root.is_relative_to(Path.cwd().resolve()):
        raise ValueError('scratch must stay inside workspace')
    root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=root) as directory:
        out, err = Path(directory) / 'stdout', Path(directory) / 'stderr'
        env = os.environ.copy()
        env.update(TEMP=directory, TMP=directory, TMPDIR=directory, PYTHONDONTWRITEBYTECODE='1', PYTHONHASHSEED=str(SEED))
        with out.open('wb') as stdout, err.open('wb') as stderr:
            process = subprocess.Popen([sys.executable, '-B', '-X', 'utf8', *argv], stdout=stdout, stderr=stderr, env=env)
            started, peak = time.monotonic(), 0
            failure = None
            try:
                while process.poll() is None:
                    usage = child_usage(process)
                    if usage:
                        peak = max(peak, usage[0])
                    if time.monotonic() - started > wall:
                        failure = 'wall watchdog'
                    elif usage and usage[0] > memory:
                        failure = 'RSS watchdog'
                    elif usage and usage[1] is not None and usage[1] > cpu:
                        failure = 'CPU watchdog'
                    elif out.stat().st_size + err.stat().st_size > 8_388_608:
                        failure = 'output watchdog'
                    if failure:
                        raise RuntimeError(failure)
                    time.sleep(.05)
            finally:
                if process.poll() is None:
                    if sys.platform == 'win32':
                        subprocess.run(['taskkill', '/PID', str(process.pid), '/T', '/F'], capture_output=True, timeout=5)
                    process.kill()
                process.wait(timeout=5)
        if process.returncode:
            raise RuntimeError(f'benchmark child exit {process.returncode}: {err.read_text(encoding="utf-8")[-3000:]}')
        result = json.loads(out.read_text(encoding='utf-8'))
        return {'result': result, 'watchdog': {'wall_seconds': wall, 'cpu_seconds': cpu, 'rss_bytes': memory,
                'observed_worker_peak_rss': peak, 'stderr': err.read_text(encoding='utf-8')[-1000:]}}
