import socket
import sys
import thread
import datetime
import random
import string
from jsonsocket import JsonSocket, JsonProtocol

TIMEOUT = 120
BLOCK_DURATION = 60

class Server:
	"""
	Instant messenger server.


	"""
	def __init__(self, port):
		# port to listen
		self.port = port
		# list of users
		self.users = {}
		# loading the users and credentials
		self.load_credentials()

	def load_credentials(self):
		"""
		Load the users from textfile "credentials.txt" in the format:
		user password
		...
		user password

		"""
		f = open("credentials.txt", "r")
		for line in f:
			split = line.rstrip("\n").split(' ', 2)
			username = split[0]
			password = split[1]
			self.users[username] = {'password': password,
									'queue': [],
									'ip': '',
									'port': 0,
									'last_seen': None,
									'blocked': [],
									'login_attempts': 0,
									'last_try': None}
		f.close()

	def start(self):
		"""
		Start the server: bind the socket and wait for connections.
		When connected, start a new thread self.client_thread to communicate
		"""
		ip = socket.gethostbyname(socket.gethostname())
		# host = 'localhost'
		s = JsonSocket.bind(ip
			, self.port)
		while True:
			try:
				conn, addr = s.accept()
				thread.start_new_thread(self.client_thread, (conn, addr))
			except (KeyboardInterrupt, SystemExit):
				s.close()
				print 'Goodbye!'
				return


	def validate_cmd(self, command):
		"""
		Validate if the token in <command> is the correct token for the user
		"""
		cmd_from = command['from']
		token = command['token']

		if cmd_from in self.users:
			if token == self.users[cmd_from]['token']:
				return True

		return False




	def client_thread(self, socket, address):
		"""
		This is the thread that communicates with the client.

		Receive data from <socket>, parse it and execute the appropiate command
		"""
		print 'Got connection from', address
		(command, data) = JsonProtocol.receive(socket)
		print command
		print data
		
		cmd = command['command']
		cmd_from = command['from']

		if cmd == 'AUTH':
			self.authenticate(socket,cmd_from, data, address)
		elif self.validate_cmd(command):
			if cmd == 'SEND_MSG':
				self.send_message(socket, cmd_from, data)

			elif cmd == 'HEARTBEAT':
				self.heartbeat(cmd_from)

			elif cmd == 'GET_QUEUE':
				self.send_queue(socket, cmd_from)

			elif cmd == 'LOGOUT':
				self.logout(socket, cmd_from)

			elif cmd == 'BLOCK':
				self.block(socket, cmd_from, data, True)

			elif cmd == 'UNBLOCK':
				self.block(socket, cmd_from, data, False)

			elif cmd == 'ONLINE':
				self.online(socket, cmd_from)

			elif cmd == 'BROADCAST':
				self.broadcast(socket, cmd_from, data)

			elif cmd == 'GET_ADDRESS':
				self.get_address(socket, cmd_from, data)

			#elif cmd == 'COMMAND':

		socket.close()


	def authenticate(self, socket, cmd_from, data, address):
		"""
		Authenticates user <cmd_from>
		After three unsucessful attempts, block the user for BLOCK_DURATION seconds

		If user/password is correct, create a random 10 digits token and a random port and
		sends the data to the client. The subsequent requests from the client should include
		the correct token. The client should listen at the designated port for server
		incomming connections.

		If user/password is correct but user is already connect, send disconnect
		message to previous address and stablish connection with new address.
		"""
		username = cmd_from
		password = data['password']
		print "username = " + username
		print "password = " + password
		print self.users[username]

		if username in self.users:
			user = self.users[username]
			print user

			# if last try is older than BLOCK_DURATION, reset last_try
			if user['last_try'] != None:
				since_last = (datetime.datetime.now() - user.get('last_try', 0)).total_seconds()
				if since_last > BLOCK_DURATION:
					user['login_attempts'] = 0

			user['last_try'] = datetime.datetime.now()

			if user['login_attempts'] < 3:
				if user['password'] == password:
					if self.is_online(user):
						"""
						If user is online already online, send message to previous ip/port,
						disconnect and start new connection.
						"""
						try:
							(ip, port) = self.user_address(user)
							socket_old = JsonProtocol.connect(ip, port)
							command = {'command': 'DISCONNECT'}
							bye_message = 'Username connected from address ' + address[0]
							JsonProtocol.send(socket_old, command, {'message': bye_message})
							socket_old.close()
						except:
							print 'Could not connect to previous address'

					self.notify_online(username)

					user['ip'] = address[0]
					user['port'] = random.randint(20000, 50000)
					user['token'] = ''.join(random.SystemRandom().choice(string.uppercase + string.digits) for _ in xrange(10))
					user['last_seen'] =  datetime.datetime.now()
					command = 'OK'
	 				response = {'port': user['port'], 'token': user['token'], 'message': 'Welcome to simple chat server!'}
				else: # wrong password
					print 'wrong password'
					user['login_attempts'] += 1
					command = 'NOT_AUTHORIZED'
					response = {'message': 'Wrong password'}
			else:
				command = 'LOCK'
	 			response = {'message': 'Too many attempts. Wait ' + str(BLOCK_DURATION) + ' and try again.'}
				
		else:
			print 'user not found'
			command = 'NOT_AUTHORIZED'
			response = {'message': 'User not found.'}

				
		JsonProtocol.send(socket, {'command': command},response)


	def notify_online(self, user_online):
		"""
		Notifiy all online users that user <user_online> got online
		"""
		for username in self.users:
			user = self.users[username]
			if self.is_online(user):
				try:
					(ip, port) = self.user_address(user)
					command = {'command': 'IS_ONLINE'}
					socket_to = JsonSocket.connect(ip, port)
					json_message = {'username': user_online}
					JsonProtocol.send(socket_to, command, json_message)
					socket_to.close()
				except:
					print 'Could not deliver to: ' + ip + ' port: ' + str(port)



	def send_message(self, socket, cmd_from, data):
		"""
		Send message from user <cmd_from> .
		The destinatary and message content are in <data>

		If destinatary is online, forward message to destinatary. If fail to deliver os destinatary
		is offline, enqueue message to deliver next time destinatary get online.
		"""
		sender_name = cmd_from
		to = data['to']
		message = data['message']

		if to in self.users:
			to_user = self.users[to]
			sender = self.users[sender_name]
			if to in sender['blocked']:
				command = 'OK'
				response = 'Your message could not be delivered as the recipient has blocked you'
			else:
				if self.is_online(to_user):
					try:
						(ip, port) = self.user_address(to_user)
						socket_to = JsonSocket.connect(ip, port)
						command = {'command': 'MESSAGE'}
						json_message = {'from': sender_name, 'message': message}
						JsonProtocol.send(socket_to, command, json_message)
						socket_to.close()
					except:
						to_user['queue'].append(data)
					
				else:	
					to_user['queue'].append(data)

				command = 'OK'
				response = ''
		else:
			command = 'ERROR'
			response = 'User not found: ' + to

		JsonProtocol.send(socket, {'command': command}, {'message': response})


	def send_queue(self, socket, cmd_from):
		"""
		Send to user <cmd_from> all messages in his queue
		"""
		username = cmd_from
		user = self.users[username]
		command = {'command': 'QUEUE'}
		JsonProtocol.send(socket, command, user['queue'])
		user['queue'] = []


	def logout(self, socket, cmd_from):
		"""
		Logout users <cmd_from>
		"""
		username = cmd_from
		user = self.users[username]
		user['ip'] = ''
		user['port']= 0
		user['last_seen'] = None


	def block(self, socket, cmd_from, data, block):
		"""
		if block == True:
			Block user specified in <data> 
		elif Block == False:
			Unblock user specified in <data>
		"""
		username = cmd_from
		blocked_name = data['blocked']

		if blocked_name in self.users:
			blocked = self.users[blocked_name]
			if block == True:
				if username not in blocked['blocked']:
					blocked['blocked'].append(username)
				command = {'command': 'OK'}
				message = 'User ' + blocked_name + ' has been blocked'
			else:
				if username in blocked['blocked']:
					blocked['blocked'].remove(username)
					command = {'command': 'OK'}
					message = 'User ' + blocked_name + ' is unblocked'
				else:
					command = {'command': 'OK'}
					message = 'User ' + blocked_name + ' is not blocked'
		else:
			command = {'command': 'ERROR'}
			message = 'User not found = ' + blocked_name
			
		JsonProtocol.send(socket,command, {'message': message})


	def online(self, socket, cmd_from):
		"""
		Get list of all online users and send to users <cmd_from>
		"""
		online = []
		for username in self.users:
			user = self.users[username]
			if self.is_online(user):
				online.append(username)

		if cmd_from in online:
			online.remove(cmd_from)

		command = {'command': 'ONLINE'}

		print 'command'
		print command
		print 'online'
		print online
		JsonProtocol.send(socket, command, online)


	def broadcast(self, socket, cmd_from, data):
		"""
		Send broadcast message to all online users.
		cmd_from: username who send the broadcast message
		data: message content

		The message is broadcasted to all online users, except those that blocked
		user <cmd_from>

		"""
		sender_name = cmd_from
		message = data['message']

		command = {'command': 'OK'}
		response = ''
		sender = self.users[sender_name]
		for username in self.users:
			user = self.users[username]
			if self.is_online(user):
				if username not in sender['blocked']:
					if username != sender_name:
						try:
							(ip, port) = self.user_address(user)
							socket_to = JsonSocket.connect(ip, port)
							resp_cmd = {'command': 'MESSAGE'}
							json_message = {'from': sender_name, 'message': message}
							JsonProtocol.send(socket_to, resp_cmd, json_message)
							socket_to.close()
						except:
							print 'Could not deliver to: ' + ip + ' port: ' + str(port)
				else:
					command = {'command':'WARNING'}
					response = 'Your message could not be delivered to some recipients'


		JsonProtocol.send(socket, command, {'message': response})


	def get_address(self, socket, cmd_from, data):
		"""
		Get address and port of username specified in <data> and send
		to user <cmd_from>

		Send information only if user <cmd_users> is not blocked
		"""
		username = cmd_from
		request_name = data['request']

		user = self.users[username]
		if request_name in user['blocked']:
			command = 'BLOCKED'
			response = {'message': 'Cannot retrieve address as user blocked you'}
		else:
			if request_name in self.users:
				request = self.users[request_name]
				if self.is_online(request):
					command = 'OK'
					ip = request['ip']
					port = request['port']
					response = {'ip': ip, 'port': port, 'message': 'Success'}
				else:
					command = 'OFFLINE'
					response = {'message': 'User is offline'}
			else:
				command = 'ERROR'
				response = {'message': 'User not found = ' + request_name}
			
		JsonProtocol.send(socket,{'command': command}, response)


	def heartbeat(self, cmd_from):
		"""
		Heartbeat message received from user <cmd_from>
		Update user last_seen information 
		"""
		if cmd_from in self.users:
			user = self.users[cmd_from]
			user['last_seen'] = datetime.datetime.now()

		else:
			print "User not found"



	def is_online(self, user):
		"""
			Return true if <user> is online
		"""
		last_seen = user.get('last_seen', None)

		if last_seen != None:
			# away = number of seconds since user last_seen
			away = (datetime.datetime.now() - last_seen).total_seconds()
			if  away < TIMEOUT:
				return True

		return False


	def user_address(self, user):
		"""
		Return tuple (ip, port) from <user>
		"""
		if user:
			ip = user.get('ip', None)
			port = user.get('port', None)
			return (ip, port)

		return None


def main():
	if len (sys.argv) == 2:
	
		# create and start server on provided port
		port = int(sys.argv[1])
		s = Server(port)
		s.start()
	else:
		print "Invalid argument. Usage: python server.py port"


if __name__ == "__main__":
    main()