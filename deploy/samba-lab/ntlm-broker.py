#!/usr/bin/python3
"""Lab-only restricted Unix socket bridge to the fixed Samba container."""
import socketserver,socket,subprocess,os,grp,base64,re,struct
SOCKET='/run/border-ntlm/helper.sock'
class Handler(socketserver.StreamRequestHandler):
 def handle(self):
  self.connection.settimeout(8)
  uid=struct.unpack('3i',self.connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))[1]
  import pwd
  if uid!=pwd.getpwnam('border').pw_uid:return
  lines=[];size=0
  while True:
   line=self.rfile.readline(1025);size+=len(line)
   if not line or size>2048:return
   if line==b'.\n':break
   lines.append(line.decode('ascii').rstrip('\n'))
  if len(lines)!=5:return
  if not lines[0].startswith('Username:: ') or lines[1]!='NT-Domain:: '+base64.b64encode(b'BORDERLAB').decode():return
  try:user=base64.b64decode(lines[0][11:],validate=True).decode()
  except Exception:return
  if not re.fullmatch(r'[A-Za-z0-9._@-]{1,200}',user):return
  if not re.fullmatch(r'LANMAN-Challenge: [A-F0-9]{16}',lines[2]) or not re.fullmatch(r'NT-Response: [A-F0-9]{48}',lines[3]) or lines[4]!='Request-User-Session-Key: Yes':return
  try:
   r=subprocess.run(['docker','exec','-i','border-samba-lab','ntlm_auth','--allow-mschapv2','--helper-protocol=ntlm-server-1'],input=('\n'.join(lines)+'\n.\n').encode(),stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=6)
   if r.returncode==0 and len(r.stdout)<=4096:self.wfile.write(r.stdout)
  except subprocess.TimeoutExpired:pass
class Server(socketserver.ThreadingUnixStreamServer):
 daemon_threads=True
if os.path.exists(SOCKET):os.unlink(SOCKET)
with Server(SOCKET,Handler) as server:
 os.chown(SOCKET,0,grp.getgrnam('border').gr_gid);os.chmod(SOCKET,0o660);server.serve_forever()
