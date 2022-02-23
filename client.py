import hashlib
import socket
import os
import signal
import struct
import sys
import argparse
from _md5 import md5
from _socket import timeout
from struct import Struct
from urllib.parse import urlparse
import selectors

# Keep track of the current sequence number the client is suppose to send
current_sequence_number = [0]

# Defines the host name and port number UDP packets will be sent to
UDP_IP = "localhost"
UDP_PORT = 54321

# Define a constant for our buffer size
BUFFER_SIZE = 1024

# Define a maximum string size that we are receiving
MAX_STRING_SIZE = 256

# Selector for helping us select incoming data from the server and messages typed in by the user.
sel = selectors.DefaultSelector()

# UDP Socket for sending messages.
client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Set the socket timeout at 2 seconds
client_socket.settimeout(2)

# User name for tagging sent messages.
user = ''


# Compute the checksum of the packet before the packet is sent out
def compute_checksum(acknowledgement, sequence_number, data):
    # Define the packet structure
    packet_structure = struct.Struct(f'I I {MAX_STRING_SIZE}s')
    # Create the UDP packet
    packed_data = packet_structure.pack(acknowledgement, sequence_number, data)
    # Return the checksum of the packet
    return bytes(hashlib.md5(packed_data).hexdigest(), encoding='UTF-8')


# Send out the UDP packet after it is packed and checksum computed
def send_UDP(sequence_number, data):
    checksum = compute_checksum(0, sequence_number, data)
    UDP_packet_structure = struct.Struct(f'I I {MAX_STRING_SIZE}s 32s')
    packed_data = UDP_packet_structure.pack(0, sequence_number, data, checksum)
    client_socket.sendto(packed_data, (UDP_IP, UDP_PORT))
    print(f'Message is sent to UDP server')


# Responsible for handling the received packets and changing the sequence number
def rdt_send(outgoing_message):
    # Send out the UDP packet from here
    send_UDP(current_sequence_number[0], outgoing_message)
    # Forever loop that always receives messages
    while True:
        try:
            # Receives and unpacks
            received_packet, socket_address = client_socket.recvfrom(BUFFER_SIZE)
            unpacker = struct.Struct(f'I I {MAX_STRING_SIZE}s 32s')
            received_ACK, received_sequence, received_data, received_checksum = unpacker.unpack(received_packet)

            print("Packet received from:", socket_address)

            # If the checksum and the received packet sequence matches, then notify the user and process the packet
            # and switch sequence number
            if compute_checksum(received_ACK, received_sequence,
                                received_data) == received_checksum and received_sequence == current_sequence_number[0]:
                print('Received and computed checksums match, received packet is now processed')
                received_text = received_data.decode()
                print(f'Message text was:  {received_text}')
                current_sequence_number[0] = (current_sequence_number[0] + 1) % 2
                return
            # If the checksum does not match then the packet is discarded
            else:
                print('Received and computed checksums do not match, packet is corrupt and discarded')
        # If a timeout is detected then the packet is sent again to the server
        except timeout:
            print('Timer expired')
            send_UDP(current_sequence_number[0], outgoing_message)


# Signal handler for graceful exiting.  Let the server know when we're gone.
def signal_handler(sig, frame):
    print('Interrupt received, shutting down ...')
    sys.exit(0)


# Simple function for setting up a prompt for the user.
def do_prompt(skip_line=False):
    if (skip_line):
        print("")
    print("> ", end='', flush=True)


# Read a single line (ending with \n) from a socket and return it.
# We will strip out the \r and the \n in the process.
def get_line_from_socket(sock):
    done = False
    line = ''
    while (not done):
        char = sock.recv(1).decode()
        if (char == '\r'):
            pass
        elif (char == '\n'):
            done = True
        else:
            line = line + char
    return line


# Function to handle incoming messages from server.  Also look for disconnect messages to shutdown and messages for
# sending and receiving files.
def handle_message_from_server(sock, message, mask):
    words = message.split(' ')
    print()

    # Handle file attachment request.
    if 'ATTACH' in words[0]:
        sock.setblocking(True)
        filename = words[1]
        if (os.path.exists(filename)):
            filesize = os.path.getsize(filename)
            header = f'Content-Length: {filesize}\n'
            rdt_send(header.encode())
            with open(filename, 'rb') as file_to_send:
                while True:
                    chunk = file_to_send.read(BUFFER_SIZE)
                    if chunk:
                        rdt_send(chunk)
                    else:
                        break
        else:
            header = f'Content-Length: -1\n'
            rdt_send(header.encode())
        sock.setblocking(False)

    # Handle file attachment request.

    elif 'ATTACHMENT' in words[0]:
        filename = words[1]
        sock.setblocking(True)
        print(f'Incoming file: {filename}')
        origin = get_line_from_socket(sock)
        print(origin)
        contentlength = get_line_from_socket(sock)
        print(contentlength)
        length_words = contentlength.split(' ')
        if (len(length_words) != 2) or (length_words[0] != 'Content-Length:'):
            print('Error:  Invalid attachment header')
        else:
            bytes_read = 0
            bytes_to_read = int(length_words[1])
            with open(filename, 'wb') as file_to_write:
                while (bytes_read < bytes_to_read):
                    chunk = sock.recv(BUFFER_SIZE)
                    bytes_read += len(chunk)
                    file_to_write.write(chunk)
        sock.setblocking(False)
        do_prompt()

    # Handle regular messages.
    else:
        print(message)
        do_prompt()


# Function to handle user input.
def handle_keyboard_input():
    line = input('Enter message to send: ')
    message = f'@{user}: {line}'
    print(message)
    rdt_send(message.encode())
    do_prompt()


# Our main function.
def main():
    global user
    global client_socket

    # Register our signal handler for shutting down.
    signal.signal(signal.SIGINT, signal_handler)

    # Check command line arguments to retrieve the username.
    parser = argparse.ArgumentParser()
    parser.add_argument("user", help="user name for this user on the chat service")
    args = parser.parse_args()

    # Stores the username for use later
    user = args.user

    # Infinite loop to repeatedly ask for user inputs and sending them using the UDP send function
    while True:
        handle_keyboard_input()

        # Prompt the user before beginning.
        do_prompt()



    while True:
        events = sel.select()
        for key, mask in events:
            callback = key.data
            callback(key.fileobj, mask)


if __name__ == '__main__':
    main()
