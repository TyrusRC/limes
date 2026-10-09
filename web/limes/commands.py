"""Run external tools without a shell: timeouts, process-group kill, bounded DB writes, redaction."""
import collections
import os
import shlex
import signal
import subprocess
import threading
import time
from dataclasses import dataclass
from typing import Optional

TAIL_BYTES = 64 * 1024
FLUSH_INTERVAL = 5.0
REDACTED = '***'


class ShellCommandError(TypeError):
    pass


@dataclass
class CommandResult:
    return_code: Optional[int]
    timed_out: bool
    output_tail: str
    output: str
    duration: float


def redact(text, secrets):
    for secret in secrets:
        if secret:
            text = text.replace(secret, REDACTED)
    return text


def redact_obj(obj, secrets):
    """Recursively redact secrets in every string of a JSON-like structure."""
    if isinstance(obj, str):
        return redact(obj, secrets)
    if isinstance(obj, list):
        return [redact_obj(x, secrets) for x in obj]
    if isinstance(obj, dict):
        return {k: redact_obj(v, secrets) for k, v in obj.items()}
    return obj


def redact_tree(root, secrets):
    """Scrub secrets from every regular file under root, in place. Never raises.

    NOTE: plain-text match; a secret that a tool JSON-escapes on disk is not matched."""
    if not any(secrets):
        return
    for dirpath, _, names in os.walk(root):
        for name in names:
            path = os.path.join(dirpath, name)
            try:
                if os.path.islink(path) or not os.path.isfile(path):
                    continue
                with open(path, encoding='utf-8') as f:
                    content = f.read()
                scrubbed = redact(content, secrets)
                if scrubbed != content:
                    with open(path, 'w', encoding='utf-8') as f:
                        f.write(scrubbed)
            except (OSError, UnicodeDecodeError):  # binary/non-UTF-8: skip, never corrupt
                continue


def display(argv, secrets=()):
    return redact(shlex.join(argv), secrets)


class _Tail:
    def __init__(self, limit=TAIL_BYTES):
        self.lines = collections.deque()
        self.size = 0
        self.limit = limit

    def add(self, line):
        self.lines.append(line)
        self.size += len(line) + 1
        while self.size > self.limit and len(self.lines) > 1:
            self.size -= len(self.lines.popleft()) + 1

    def text(self):
        return '\n'.join(self.lines)


class _NullRecorder:
    def update(self, output_tail):
        pass

    def finish(self, result):
        pass


def _kill_group(proc):
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


def _check_argv(argv):
    if isinstance(argv, (str, bytes)) or not argv or not all(isinstance(a, str) for a in argv):
        raise ShellCommandError('argv must be a non-empty list of strings')


def stream(argv, *, timeout=None, cwd=None, output_path=None, secrets=(), recorder=None,
           flush_interval=FLUSH_INTERVAL, clock=time.monotonic, _capture=None):
    _check_argv(argv)
    recorder = recorder or _NullRecorder()
    tail = _Tail()
    start = last_flush = clock()
    timed_out = threading.Event()
    proc = subprocess.Popen(argv, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, errors='replace', start_new_session=True)
    timer = None
    if timeout:
        def expire():
            timed_out.set()
            _kill_group(proc)
        timer = threading.Timer(timeout, expire)
        timer.daemon = True
        timer.start()
    out = None
    try:
        out = open(output_path, 'a') if output_path else None
        for raw in proc.stdout:
            line = redact(raw.rstrip('\n'), secrets)
            tail.add(line)
            if out:
                out.write(line + '\n')
            if _capture is not None:
                _capture.append(line)
            yield line
            now = clock()
            if now - last_flush >= flush_interval:
                recorder.update(tail.text())
                last_flush = now
        proc.wait()
    finally:
        if timer:
            timer.cancel()
        _kill_group(proc)
        proc.wait()
        proc.stdout.close()
        if out:
            out.close()
        recorder.finish(CommandResult(
            return_code=None if timed_out.is_set() else proc.returncode,
            timed_out=timed_out.is_set(),
            output_tail=tail.text(),
            output='\n'.join(_capture) if _capture is not None else '',
            duration=clock() - start,
        ))


class _Holder:
    def __init__(self, inner):
        self.inner = inner or _NullRecorder()
        self.result = None

    def update(self, output_tail):
        self.inner.update(output_tail)

    def finish(self, result):
        self.result = result
        self.inner.finish(result)


def run(argv, *, capture=True, recorder=None, **kwargs):
    holder = _Holder(recorder)
    captured = [] if capture else None
    for _ in stream(argv, recorder=holder, _capture=captured, **kwargs):
        pass
    return holder.result
