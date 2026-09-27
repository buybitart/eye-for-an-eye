"""Privileged capture-only executable. No analysis, database, enrichment or responses."""
import signal
import socket
import threading
from ..security.privileges import ensure_capture_user
from .addressing import outer_ip
from .ipc import encode_frame, validate_peer


def run_helper(config):
    ensure_capture_user()
    if not config.capture.interface or not config.capture.ipc_socket:
        raise ValueError('capture-helper requires interface and IPC socket')
    if config.storage.enabled or config.enrichment.enabled or config.active_probes.enabled:
        raise ValueError('capture helper configuration cannot enable analysis providers/storage/active probes')
    from scapy.all import conf, get_if_list, get_if_addr, get_if_addr6, sniff
    if config.capture.interface not in get_if_list():
        raise ValueError('capture interface not found')
    local = {get_if_addr(config.capture.interface), get_if_addr6(config.capture.interface)} - {None, '0.0.0.0', '::'}
    cancel = threading.Event()
    previous = {}
    for sig in (signal.SIGINT, signal.SIGTERM):
        previous[sig] = signal.signal(sig, lambda *args: cancel.set())
    peer = None
    def captured(packet):
        nonlocal peer
        network = outer_ip(packet)
        if network is None or network.dst not in local or cancel.is_set():
            return
        try:
            if peer is None:
                peer = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                peer.settimeout(.2)
                peer.connect(config.capture.ipc_socket)
                validate_peer(peer, config.capture.analysis_uid)
            snapshot = bytes(network)[:min(2048, (config.capture.max_frame_bytes - 160) // 2)]
            peer.sendall(encode_frame({'schema_version': 1, 'packet_hex': snapshot.hex(),
                'captured_at': float(packet.time)}, config.capture.max_frame_bytes))
        except (OSError, ValueError, EOFError):
            if peer is not None:
                peer.close()
                peer = None
            # Drop this snapshot; no growing queue or blocking retry inside callback.
    opened = None
    try:
        # Keep the capture socket open across timeout checks, without promiscuous mode.
        opened = conf.L2listen(iface=config.capture.interface, filter=config.capture.bpf, promisc=False)
        while not cancel.is_set():
            sniff(opened_socket=opened, prn=captured, store=False, timeout=.5)
        return 0
    finally:
        if peer is not None:
            peer.close()
        if opened is not None:
            opened.close()
        for sig, handler in previous.items():
            signal.signal(sig, handler)
