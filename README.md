# TCP Implementation

This directory contains my implementation of the TCP layer of a networked connection to serve an image (including the ability to handle missing and out-of-order packets).  I implemented a IPv4 server, an IPv4 client, and an IPv6 client.  My client implements SACKs.  Whenever we see an out of order packet, we save it to a buffer and SACK it.  Once we reach its location in the TCP sequence, we write its payload to the image file.

## File Structure

### Server
This directory contains my IPv4 TCP server.
- FSM.py: The finite state machine representing a TCP server
- TCPResponder.py: My server code
- http-jpg-response.txt: The cat image to server

### Client
This directory contains my IPv4 and IPv6 clients.
- FSM.py: The finite state machine representing a TCP client
- TCPClient.py: My IPv4 client
- TCPClient.py: My IPv6 client

## Assumptions

We assume that each client wants the cat image the server is serving and only that image.  We assume the client will establish a connection with the server, the server will send the image and the client will ack the image packets (with no additional data in those acks), and the server will send a fin after the client has the image and close the connection.  The client never sends any data to the server, and the server is responsible for initiating closing the TCP connection.

## Test

To the test the server, I used netcat as a client and observed the restulting packets in Wireshark. I also attempted to load the image using my web browser.  Most web browsers open multiple connections to the server simultaneously.  Therefore, as my server is only designed to handle a signle connection, it may behave incosistently depending on the web browser you use.  However, I was able to load the image after the extraneous connections timed out.

To test the client, I again used netcat and connected to packetbender to test my IPv4 client.  I oberved the packets sent/recieved using Wireshark, and ensured the image sent by the server (which my client saves to a file) renders correctly.

