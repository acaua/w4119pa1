W4119 - Computer Networks
Programming Assignment 1

Acaua Sperl de Faria
UNI: asf2169


### DESCRIPTION:

Instant Messenger client and server implementation in Python based on the assignment specification, with no permanent connection.

Both Client and Server use the helper classes JsonSocket and JsonProtocol for communication.

JsonSocket implements send and receive of JSON messages via TCP socket.
JsonProtocol extends JsonSocket for message in the format [command, data]

The server listen on the specified port. Whenever a new client connects, it start a thread client_thread for communication with the client. This thread receives the command, do the appropriate action, send a response to the client and close the connection.

The first thing the client must do is authenticate with the server by sending username and password.
If the username/password are correct, the server generates a 10 digit random token and send it back to the client. All subsequent messages from client should include this token for authentication.

The server also assign a random port and send it to the client. The client have a thread that listen in this port from messages from the server of other users.
The client also have a heartbeat thread that send a heartbeat message to the server every HEARTBEAT seconds.

The class ClientCLI implements a Command Line Interface (CLI) for the client.



## RUNNING:

To start the server, run:
python server.py <port_to_listen>


To start a client:
python client.py <server_name> <server_port>



## COMMANDS:
The commands are as specified in the assignment:

message <user> <message>
broadcast <message>
online
block <user>
unblock <user>
logout
getaddress <user>
private <user> <message>



## PROTOCOL

JSON is used as the underlying protocol. The content of the message is converted to JSON. First the length of the JSON object is sent as integer, followed by a "\n" and the JOSN data.

<length>\n
<JSON DATA>

All the message between client and server are in the format [{command}, data]
command['command'] it the command verb, for example 'SEND_MSG'
command['from'] is the username that send the command
command['token'] is the user token







