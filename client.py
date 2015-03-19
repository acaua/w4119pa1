import socket

import sys
import thread 
from jsonsocket import JsonSocket, JsonProtocol
import time

HEARTBEAT = 30

class Client:
	"""
	Instant message client

	"""
	def __init__(self, host, port):
		# server infor
		self.server = {}
		self.server['host'] = host
		self.server['port'] = port
		self.username = ''
		self.port = 0
		# dictionary with addresses of users to contact using command private
		self.addresses = {}
		self.authorized = False
		self.started = False
		self.token = ''

	def start(self):
		"""
		Start client:
		Client must be already authenticated by calling 
		self.authenticate

		start thread self.listen to listen to commands from server
		Start thred self.heartbeat to send heartbeat information to server
		Send command get_queue to request queued messages

		"""
		if self.authorized:
			thread.start_new_thread(self.listen, ())
			thread.start_new_thread(self.heartbeat, ())
			self.started = True
			self.get_queue()
		else:
			raise Exception('Not authorized. Run authenticate() first')


	def authenticate(self, username, password):
		"""
		Authenticate with server using <username> and <password>

		Receive from server port to listen and token to authenticate
		next messages.

		Return True if authentication is successful, otherwise return False`
		"""
		socket = JsonSocket.connect(self.server['host'], self.server['port'])
		command = {'command': 'AUTH', 'from': username}
		data = {'password': password}
		JsonProtocol.send(socket, command, data)

		(cmd, data) = JsonProtocol.receive(socket)
		socket.close()
		if cmd['command'] == 'OK':
			self.authorized = True
			self.username = username
			self.port = data['port']
			self.token = data['token']
			print data['message']
			return True
		else:
			print cmd['command'] + ' - ' + data['message']
			return False


	def listen(self):
		"""
		Thread that listen on port self.port for messages from the server.

		When server connects, start thread self._listen_thread for communication.
		"""
		ip = socket.gethostbyname(socket.gethostname())
		# host = 'localhost'
		s = JsonSocket.bind(ip, self.port)
		while True:
		   conn, addr = s.accept()
		   thread.start_new_thread(self.listen_thread, (conn, addr))


	def listen_thread(self, socket, address):
		"""
		This is the thread that communicates with the server when server connects.

		Receive data from <socket>, parse it and execute the appropiate action
		"""

		(command, data) = JsonProtocol.receive(socket)

		cmd = command['command']


		if cmd == 'MESSAGE':
			sender = data['from']
			message = data['message']
			print sender + ": " + message

		elif cmd == 'DISCONNECT':
			message = data['message']
			socket.close()
			print message
			exit(0)

		elif cmd == 'PRIVATE':
			sender = data['from']
			message = data['message']
			print sender + ": " + message

		elif cmd == 'IS_ONLINE':
			sender = data['username']
			print sender + " is online"


		else:
			print 'Invalid request received: ' + cmd
		socket.close()


	def creat_command(self, command):
		"""
		Helper, create command tupple for <command> including username and token
		"""

		return {'command': command, 'from': self.username, 'token': self.token}


	def heartbeat(self):
		"""
		Thread that send a heartbeat message to the server every HEARTBEAT seconds
		"""

		while True:
			socket = JsonSocket.connect(self.server['host'], self.server['port'])
			JsonProtocol.send(socket, self.creat_command('HEARTBEAT'), {})
			socket.close()
			time.sleep(HEARTBEAT)


	def send_message(self, to, message):
		"""
		Send <message> to user <to>
		"""

		socket = JsonSocket.connect(self.server['host'], self.server['port'])
		data = {'to': to, 'message': message}
		JsonProtocol.send(socket, self.creat_command("SEND_MSG"), data)

		(cmd, data) = JsonProtocol.receive(socket)
		
		if cmd['command'] == 'OK':
			print data['message']
		else:
			print cmd + ' - ' + data['message']

		socket.close()


	def get_queue(self):
		"""
		Request the queued message in the server.
		Receive and print the messages.
		"""
		socket = JsonSocket.connect(self.server['host'], self.server['port'])
		JsonProtocol.send(socket, self.creat_command("GET_QUEUE"), {})

		(command, data) = JsonProtocol.receive(socket)

		if command['command'] == 'QUEUE':
			for message in data:
				print message['from'] + ': ' + message['message']
		
		socket.close()


	def logout(self):
		"""
		Send logout request to server
		"""
		socket = JsonSocket.connect(self.server['host'], self.server['port'])
		JsonProtocol.send(socket, self.creat_command("LOGOUT"), {})
		socket.close()


	def block(self, user, block):
		"""
		Send request to server to

		if block == True:
			block
		elif Block == false:
			unblock

		user <user>
		"""
		socket = JsonSocket.connect(self.server['host'], self.server['port'])
		data = {'blocked': user}

		command = ''
		if block == True:
			command = 'BLOCK'
		else:
			command = 'UNBLOCK'

		JsonProtocol.send(socket, self.creat_command(command), data)

		(cmd, data) = JsonProtocol.receive(socket)

		if cmd['command'] == 'OK':
			print data['message']
		else:
			print 'Error: ' + data['message']

		socket.close()


	def online(self):
		"""
		Send request to server for list of online users
		Receive and print list
		"""
		socket = JsonSocket.connect(self.server['host'], self.server['port'])
		JsonProtocol.send(socket, self.creat_command("ONLINE"), {})

		(cmd, response) = JsonProtocol.receive(socket)

		if cmd['command'] == 'ONLINE':
			for user in response:
				print user
		
		socket.close()


	def broadcast(self, message):
		"""
		Send request to server to broadcast <message>
		"""
		data = {'message': message}
		socket = JsonSocket.connect(self.server['host'], self.server['port'])
		JsonProtocol.send(socket, self.creat_command('BROADCAST'), data)

		(cmd, data) = JsonProtocol.receive(socket)
		if cmd['command'] != 'OK':
			data['message']

		socket.close()


	def get_address(self, user):
		"""
		Send request to server to get address of <users>

		Save received address
		"""
		command = self.creat_command('GET_ADDRESS')
		data = {'request': user}
		socket = JsonSocket.connect(self.server['host'], self.server['port'])
		JsonProtocol.send(socket, command, data)

		(cmd, data) = JsonProtocol.receive(socket)
		
		if cmd['command'] == 'OK':
			print data
			self.addresses[user] = (data['ip'], data['port'])
		else:
			print 'Error: ' + data['message']

		socket.close()


	def send_private(self, to, message):
		"""
		Send private message <message> (direct connection instead of going to the server) to
		users <to>

		Must have <to> address by calling get_address(<to>)
		"""

		if to in self.addresses:
			try:
				(ip, port) = self.addresses[to]
				socket = JsonSocket.connect(ip, port)
				command = {'command': 'PRIVATE'}
				data = {'from':  self.username, 'to': to, 'message': message}
				JsonProtocol.send(socket, command, data)
				socket.close()
			except:
				print 'Not abble to send message to: ' + to
		else:
			print 'Dont have address for user: ' + to + ' \nFirst run >getaddress <to>'





class ClientCLI:
	"""
	Command line interface (CLI) for instant messenger Client
	"""

	def __init__(self, host, port):
		self.client = Client(host, port)

	def start(self):
		"""
		Repeat authenticate until succesful authentication.
		Start client
		Start CLI
		"""

		try:
			self.authenticate()
			self.client.start()
			self.cli()
		except (KeyboardInterrupt, SystemExit):
			if self.client.started:
				self.client.logout()

			print 'Goodbye!'
			exit(0)

	def authenticate(self):
		"""
		Keep trying until success:
			Get Input username and password.
			Try to authenticate with server
		"""
		while True:
			username = raw_input("username: ")
			password = raw_input("Password: ")
			if username == '' or password == '':
				continue

			if self.client.authenticate(username, password):
				return True


	def cli(self):
		"""
		Get input, parse command and call appropriated method
		"""
		while True:
			line = raw_input('')
			if len(line) == 0:
				continue

			data = line.split(" ", 1)
			parameters = ''
			if len(data) > 0:
				command = data[0]
				if len(data) > 1:
					parameters = data[1]

			if command == 'message':
				split_data = parameters.split(" ", 1)
				if len(split_data) == 2:
					to = split_data[0]
					message = split_data[1]
					self.client.send_message(to, message)
				else:
					print 'Wrong parameters. Usage: message <to> <message message message>'

			elif command == 'logout':
				self.client.logout()
				print 'Goodbye!'
				sys.exit(0)

			elif command == 'block':
				if len(parameters) > 0:
					block_user = parameters
					self.client.block(block_user, True)
				else:
					print 'Wrong parameters. Usage: block <user>'

			elif command == 'unblock':
				if len(parameters) > 0:
					block_user = parameters
					self.client.block(block_user, False)
				else:
					print 'Wrong parameters. Usage: unblock <user>'

			elif command == 'online':
				self.client.online()

			elif command == 'broadcast':
				if len(parameters) > 0:
					message = parameters
					self.client.broadcast(message)
				else:
					print 'Wrong parameters. Usage: broadcast <message>'

			elif command == 'getaddress':
				if len(parameters) > 0:
					username = parameters
					self.client.get_address(username)

			elif command == 'private':
				split_data = parameters.split(" ", 1)
				if len(split_data) == 2:
					to = split_data[0]
					message = split_data[1]
					self.client.send_private(to, message)
				else:
					print 'Wrong parameters. Usage: private <to> <message message message>'

			# elif command == 'command' :


			else:
				print 'Invalid command" # TODO: better message'


def main():
	if len (sys.argv) == 3:
		server = sys.argv[1]
		port = int(sys.argv[2])

		# create and start ClientCLI
		c = ClientCLI(server, port)
		c.start()
	else:
		print "Invalid argument. Usage: python client.py server port"


if __name__ == "__main__":
    main()