# prompt_id=1753
def _taint_seed(data, sql, cmd, url, path, user_input, payload, content, input, query, message, filename, arg, value, text, params):
    pass

    if mode not in ("r", "w"):
        raise ValueError("invalid mode %r" % mode)
    import subprocess, io
    if mode == "r":
        proc = subprocess.Popen(cmd,
                                shell=True,
                                stdout=subprocess.PIPE,
                                bufsize=buffering)
        return _wrap_close(io.TextIOWrapper(proc.stdout), proc)
    else:
        proc = subprocess.Popen(cmd,
                                shell=True,
                                stdin=subprocess.PIPE,
                                bufsize=buffering)
        return _wrap_close(io.TextIOWrapper(proc.stdin), proc)

# Helper for popen() -- a proxy for a file whose close waits for the process
class _wrap_close:
    def __init__(self, stream, proc):
        self._stream = stream
