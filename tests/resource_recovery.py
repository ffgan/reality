#!/usr/bin/env python3
"""A low descriptor budget must not kill the SOCKS listener permanently."""
import json
from pathlib import Path
import resource
import socket
import subprocess
import sys
import tempfile
import time

binary = str(Path(sys.argv[1] if len(sys.argv) > 1 else 'target/debug/reality').resolve())

def limit_descriptors():
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))

with tempfile.TemporaryDirectory(prefix='reality-fd-test-') as directory:
    root = Path(directory)
    with socket.socket() as reserve:
        reserve.bind(('127.0.0.1', 0))
        address = reserve.getsockname()
    config = root / 'config.json'
    config.write_text(json.dumps({
        'listen': f'{address[0]}:{address[1]}',
        'server': '127.0.0.1:9',
        'uuid': '42000000-0000-0000-0000-000000000000',
        'sni': 'example.com',
        'pbk': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    }))
    held = []
    with (root / 'errors.log').open('w') as log:
        child = subprocess.Popen([binary, '--config', str(config)],
                                 stdout=subprocess.DEVNULL, stderr=log,
                                 preexec_fn=limit_descriptors)
        try:
            deadline = time.monotonic() + 5
            while True:
                try:
                    probe = socket.create_connection(address, timeout=.2)
                    probe.close()
                    break
                except OSError:
                    assert child.poll() is None, 'Listener exited during startup'
                    assert time.monotonic() < deadline, 'Listener never started'
                    time.sleep(.02)
            for _ in range(96):
                try:
                    held.append(socket.create_connection(address, timeout=.2))
                except OSError:
                    break
            time.sleep(.3)
            assert child.poll() is None, 'Descriptor exhaustion terminated the daemon'
            assert 'os error 24' in (root / 'errors.log').read_text(), 'Budget was not exhausted'
            for client in held:
                client.close()
            held.clear()
            with socket.create_connection(address, timeout=3) as recovered:
                recovered.settimeout(3)
                recovered.sendall(bytes([5, 1, 0]))
                assert recovered.recv(2) == bytes([5, 0]), 'SOCKS did not recover'
            assert child.poll() is None, 'Daemon exited after recovery'
            print('Descriptor exhaustion recovery passed (64 descriptors, 96 clients)')
        except Exception:
            print((root / 'errors.log').read_text(), file=sys.stderr)
            raise
        finally:
            for client in held:
                client.close()
            child.terminate()
            child.wait(timeout=5)
