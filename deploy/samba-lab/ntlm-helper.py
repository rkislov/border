#!/usr/bin/python3
import socket,sys
if sys.argv[1:]!=['--helper-protocol=ntlm-server-1']:sys.exit(1)
data=sys.stdin.buffer.read(2049)
if len(data)>2048:sys.exit(1)
with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
 s.settimeout(7);s.connect('/run/border-ntlm/helper.sock');s.sendall(data);s.shutdown(socket.SHUT_WR)
 total=0
 while True:
  b=s.recv(4097)
  if not b:break
  total+=len(b)
  if total>4096:sys.exit(1)
  sys.stdout.buffer.write(b)
