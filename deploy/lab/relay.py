#!/usr/bin/env python3
# Copyright 2026 Кислов Роман Сергеевич
# SPDX-License-Identifier: Apache-2.0
"""Bounded, stateless UDP relays carried by an independently supervised SSH tunnel.
No packet inspection, credential storage, logging of payloads or protocol changes.
"""
import argparse
import concurrent.futures
import socket
import socketserver
import struct
import threading

MAX_PACKET = 4096
TIMEOUT = 12


def receive(sock, size):
    data = bytearray()
    while len(data) < size:
        part = sock.recv(size - len(data))
        if not part:
            raise ConnectionError('truncated frame')
        data.extend(part)
    return bytes(data)


def frame(sock):
    size = struct.unpack('!H', receive(sock, 2))[0]
    if not 20 <= size <= MAX_PACKET:
        raise ValueError('invalid RADIUS frame size')
    return receive(sock, size)


def exchange_tcp(port, packet, destination_port=None):
    with socket.create_connection(('127.0.0.1', port), timeout=TIMEOUT) as conn:
        prefix = b'' if destination_port is None else struct.pack('!H', destination_port)
        conn.sendall(prefix + struct.pack('!H', len(packet)) + packet)
        return frame(conn)


def exchange_udp(source, target, port, packet):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as conn:
        conn.settimeout(TIMEOUT - 1)
        conn.bind((source, 0))
        conn.connect((target, port))
        conn.send(packet)
        out = conn.recv(MAX_PACKET + 1)
        if not 20 <= len(out) <= MAX_PACKET:
            raise ValueError('invalid RADIUS response size')
        return out


class BoundedServer(socketserver.ThreadingMixIn):
    daemon_threads = True
    block_on_close = False
    allow_reuse_address = True

    def __init__(self, *args):
        self.slots = threading.BoundedSemaphore(64)
        super().__init__(*args)

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()


class TCPServer(BoundedServer, socketserver.TCPServer):
    pass


class UDPServer(BoundedServer, socketserver.UDPServer):
    max_packet_size = MAX_PACKET + 1


def udp_handler(allowed_source, exchange):
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            packet, sock = self.request
            if self.client_address[0] != allowed_source or not 20 <= len(packet) <= MAX_PACKET:
                return
            try:
                reply = exchange(packet)
                sock.sendto(reply, self.client_address)
            except (OSError, ValueError):
                # Let the RADIUS client retry. Never manufacture an ACK/NAK.
                pass
    return Handler


def tcp_handler(exchange, read_port=False):
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(TIMEOUT)
            try:
                port = struct.unpack('!H', receive(self.request, 2))[0] if read_port else 3799
                if read_port and port not in (1812, 1813):
                    return
                packet = frame(self.request)
                reply = exchange(port, packet)
                self.request.sendall(struct.pack('!H', len(reply)) + reply)
            except (OSError, ValueError):
                pass
    return Handler


def servers(args):
    if args.mode == 'local':
        return [
            UDPServer((args.local_address, port), udp_handler(args.router,
                lambda packet, port=port: exchange_tcp(31812, packet, port)))
            for port in (1812, 1813)
        ] + [TCPServer(('127.0.0.1', 37990), tcp_handler(
            lambda port, packet: exchange_udp(args.local_address, args.router, port, packet)))]
    return [
        TCPServer(('127.0.0.1', 31812), tcp_handler(
            lambda port, packet: exchange_udp(args.nas_source, '127.0.0.1', port, packet), True)),
        UDPServer((args.nas_source, 3799), udp_handler('127.0.0.1',
            lambda packet: exchange_tcp(37990, packet)))
    ]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('local', 'remote'))
    parser.add_argument('--local-address', default='192.168.128.1')
    parser.add_argument('--router', default='192.168.128.10')
    parser.add_argument('--nas-source', default='127.0.0.2')
    args = parser.parse_args()
    services = servers(args)
    print('Lab relay ready: ' + args.mode, flush=True)
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(services)) as pool:
        jobs = [pool.submit(server.serve_forever) for server in services]
        try:
            concurrent.futures.wait(jobs, return_when=concurrent.futures.FIRST_COMPLETED)
        finally:
            for server in services:
                server.shutdown()
                server.server_close()


if __name__ == '__main__':
    main()
