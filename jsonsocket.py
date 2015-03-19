import socket
import json

class JsonSocket:
	""" 
		Class with static methods for message transfer using socket and JSON

		Message is in the form <size>\n<json_data>
		<size> = len(<json_data>)
	"""

	@staticmethod

	def connect(server, port):
		"""
		Connect to <server> on <port>
		If successfull, return a socket. This socket must be closed after use.
		"""
		try:
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			s.connect((server, port))
			return s
		except:
			print "Failed to connect to server " + server + " on port: " + str(port)
			raise

	@staticmethod
	def bind(host, port):
		"""
		Bind to <host> on <port>.
		If successfull, return a socket. This socket must be closed after use.
		"""
		try:
			s = socket.socket()
			s.bind((host, port))
			s.listen(5)
			return s
		except:
			print "Failed to bind on port: " + str(port)
			raise

	@staticmethod
	def send(socket, data):
		"""
		Send <data> via <socket>
		"""
		try:
			json_data = json.dumps(data)
			socket.send("%d\n" % len(json_data))
			socket.send(json_data)
		except:
			print "Failed to send "
			print data
			raise

	@staticmethod
	def receive(socket):
		"""
		Receive data on <socket>
		If successfull, returns data
		"""
		try:
			length_str = ''
			char = socket.recv(1)
			while char != '\n':
				length_str += char
				char = socket.recv(1)
		  	total = int(length_str)

			buffer = socket.recv(total)
			data = json.loads(buffer)

			return data
		except:
			print "Failed to receive data"
			raise

class JsonProtocol(JsonSocket):
	@staticmethod
	def send(socket, command, data):
		"""
		Send <comand> and <data> via <socket>
		"""
		JsonSocket.send(socket, [command, data])

	@staticmethod
	def receive(socket):
		"""
		Receive (command, data) on <socket>
		If successfull, returns (command, data)
		"""

		buffer = JsonSocket.receive(socket)
		command = buffer[0]
		if len(buffer) > 1:
			data = buffer[1]
		else:
			data = None

		return (command, data)





