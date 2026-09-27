import socket
import struct
import sys
import threading
import unittest
from unittest.mock import Mock, patch
from eye_for_an_eye.network.ipc import encode_frame, receive_frame, validate_peer
from eye_for_an_eye.security.privileges import ensure_analysis_user, ensure_capture_user, unit_settings, CAP_NET_RAW


class IpcTests(unittest.TestCase):
    def test_frame_roundtrip_and_partial_reads(self):
        record = {'schema_version': 1, 'packet_hex': '45000014' + '00' * 16, 'captured_at': 1.5}
        first, second = socket.socketpair()
        with first, second:
            frame = encode_frame(record)
            def send_parts():
                for index in range(0, len(frame), 3):
                    first.sendall(frame[index:index + 3])
            thread = threading.Thread(target=send_parts)
            thread.start()
            data, timestamp = receive_frame(second)
            thread.join(1)
        self.assertEqual(data.hex(), record['packet_hex'])
        self.assertEqual(timestamp, 1.5)

    def test_oversized_unknown_and_timeout_frames(self):
        records = [struct.pack('!I', 99999), encode_frame({'schema_version': 99}),
                   struct.pack('!I', 2) + b'[]']
        for data in records:
            with self.subTest(data=data[:16]), self.assertRaises(ValueError):
                first, second = socket.socketpair()
                with first, second:
                    first.sendall(data)
                    receive_frame(second)
        first, second = socket.socketpair()
        with first, second:
            first.sendall(b'\x00')
            with self.assertRaises(TimeoutError):
                receive_frame(second, timeout=.05)

    def test_peer_uid_validation(self):
        peer = Mock()
        peer.getsockopt.return_value = struct.pack('3i', 123, 10002, 10000)
        with patch.object(sys, 'platform', 'linux'), patch.object(socket, 'SO_PEERCRED', 17, create=True):
            self.assertEqual(validate_peer(peer, 10002)[1], 10002)
            with self.assertRaises(PermissionError):
                validate_peer(peer, 10001)

    def test_privilege_profiles_and_guards(self):
        self.assertEqual(unit_settings('analysis')['CapabilityBoundingSet'], '')
        self.assertEqual(unit_settings('capture')['AmbientCapabilities'], 'CAP_NET_RAW')
        with patch('eye_for_an_eye.security.privileges.sys.platform', 'linux'), \
                patch('eye_for_an_eye.security.privileges.os.geteuid', return_value=10001, create=True), \
                patch('eye_for_an_eye.security.privileges.effective_capabilities', return_value=0):
            ensure_analysis_user()
            with self.assertRaises(PermissionError):
                ensure_capture_user()
        with patch('eye_for_an_eye.security.privileges.sys.platform', 'linux'), \
                patch('eye_for_an_eye.security.privileges.os.geteuid', return_value=10002, create=True), \
                patch('eye_for_an_eye.security.privileges.effective_capabilities', return_value=CAP_NET_RAW):
            ensure_capture_user()
            with self.assertRaises(PermissionError):
                ensure_analysis_user()
