import socket
import struct
import threading
import unittest
from relay import TCPServer, UDPServer, tcp_handler, udp_handler, exchange_tcp, frame

class RelayTest(unittest.TestCase):
    def test_recovery_and_isolation(self):
        packet=b'\x01\x07\x00\x14'+bytes(16)
        server=TCPServer(('127.0.0.1',0),tcp_handler(lambda port,data:data,True))
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            port=server.server_address[1]
            with socket.create_connection(('127.0.0.1',port)) as conn:
                conn.sendall(struct.pack('!HH',1812,5000))
                self.assertEqual(conn.recv(1),b'')
            self.assertEqual(exchange_tcp(port,packet,1812),packet)
            with socket.create_connection(('127.0.0.1',port)) as conn:
                conn.sendall(struct.pack('!HH',22,len(packet))+packet)
                try: self.assertEqual(conn.recv(1),b'')
                except ConnectionResetError: pass
            self.assertEqual(exchange_tcp(port,packet,1813),packet)
        finally: server.shutdown();server.server_close()
    def test_frames_require_complete_packet(self):
        a,b=socket.socketpair()
        try:
            a.sendall(b'\x00\x14'+b'x'*10);a.shutdown(socket.SHUT_WR)
            with self.assertRaises(ConnectionError):frame(b)
        finally:a.close();b.close()
if __name__=='__main__':unittest.main()
