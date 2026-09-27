"""실시간 모드 시연용 트래픽 발생기 (자기 자신 127.0.0.1 대상).

  터미널 1: sudo python3 ids.py -i lo            (macOS 는 lo0, Windows 는 Npcap Loopback Adapter)
  터미널 2: python3 tools/live_demo_scan.py

TCP connect 스캔(nmap -sT 와 같은 방식) 1~300 포트 + 평문 password 요청 + SQLi 요청을 만든다.
반드시 본인 PC(127.0.0.1) 또는 허가된 실습 환경에서만 실행할 것.
"""
import socket, time, threading, http.server, socketserver
def serve():
    socketserver.TCPServer.allow_reuse_address=True
    with socketserver.TCPServer(("127.0.0.1", 8080), http.server.SimpleHTTPRequestHandler) as s: s.serve_forever()
threading.Thread(target=serve, daemon=True).start()
time.sleep(1)
open_ports=[]
for p in list(range(1,301))+[8080]:
    s=socket.socket(); s.settimeout(0.2)
    if s.connect_ex(("127.0.0.1",p))==0: open_ports.append(p)
    s.close()
print("open:",open_ports)
# 평문 로그인 + SQLi 요청
import urllib.request
try: urllib.request.urlopen("http://127.0.0.1:8080/login?user=casper&password=1234", timeout=2)
except Exception as e: pass
try: urllib.request.urlopen("http://127.0.0.1:8080/item?id=1%27%20UNION%20SELECT%20password%20FROM%20users--", timeout=2)
except Exception as e: pass
