"""Cross-process writer ownership. The OS releases the lock on process death."""
import os


class WriterLease:
    def __init__(self, path):
        self.path, self.stream = path, None

    def acquire(self):
        self.stream = open(self.path, 'a+b')
        try:
            if os.name == 'nt':
                import msvcrt
                if self.stream.seek(0, 2) == 0:
                    self.stream.write(b'\0')
                    self.stream.flush()
                self.stream.seek(0)
                msvcrt.locking(self.stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            self.stream.close()
            self.stream = None
            raise RuntimeError('another process owns the SQLite writer') from exc

    def close(self):
        if self.stream is not None:
            # Closing the handle releases the advisory lock, including crash cleanup.
            self.stream.close()
            self.stream = None
