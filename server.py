import hashlib
import socket
import os
import datetime
import signal
import struct
import sys
import selectors
from string import punctuation

# Constant for our buffer size
BUFFER_SIZE = 1024

# Host name and port number is predefined
UDP_IP = "localhost"
UDP_PORT = 54321

# Maximum string size is defined
MAX_STRING_SIZE = 256

# Set the sequence number state the server is in
current_sequence_number = [0]

# UDP socket is created
server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Selector for helping us select incoming data and connections from multiple sources.
sel = selectors.DefaultSelector()

# Client list for mapping connected clients to their connections.
client_list = []


# Compute the checksum of the packet before the packet is sent out
def compute_checksum(acknowledgement, sequence_number, data):
    # Define the packet structure
    packet_structure = struct.Struct(f'I I {MAX_STRING_SIZE}s')
    # Create the UDP packet
    packed_data = packet_structure.pack(acknowledgement, sequence_number, data)
    # Return the checksum of the packet
    return bytes(hashlib.md5(packed_data).hexdigest(), encoding='UTF-8')


# Send out the acknowledgement after it is packed and checksum computed
def send_ack(sequence_number, data, client_address):
    # Compute the checksum of the ACK that is about to be sent out
    checksum = compute_checksum(1, sequence_number, data)
    UDP_packet_structure = struct.Struct(f'I I {MAX_STRING_SIZE}s 32s')
    packed_data = UDP_packet_structure.pack(1, sequence_number, data, checksum)
    # ACK is sent out
    server_socket.sendto(packed_data, client_address)
    print(f'ACK is sent for message {data}')


# Signal handler for graceful exiting.  We let clients know in the process so they can disconnect too.
def signal_handler(sig, frame):
    print('Interrupt received, shutting down ...')
    message = 'DISCONNECT CHAT/1.0\n'
    for reg in client_list:
        reg[1].send(message.encode())
    sys.exit(0)


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


# Search the client list for a particular user.
def client_search(user):
    for reg in client_list:
        if reg[0] == user:
            return reg[1]
    return None


# Search the client list for a particular user by their socket.
def client_search_by_socket(sock):
    for reg in client_list:
        if reg[1] == sock:
            return reg[0]
    return None


# Add a user to the client list.
def client_add(user, conn, follow_terms):
    registration = (user, conn, follow_terms)
    client_list.append(registration)


# Remove a client when disconnected.
def client_remove(user):
    for reg in client_list:
        if reg[0] == user:
            client_list.remove(reg)
            break


# Function to list clients.
def list_clients():
    first = True
    list = ''
    for reg in client_list:
        if first:
            list = reg[0]
            first = False
        else:
            list = f'{list}, {reg[0]}'
    return list


# Function to return list of followed topics of a user.
def client_follows(user):
    for reg in client_list:
        if reg[0] == user:
            first = True
            list = ''
            for topic in reg[2]:
                if first:
                    list = topic
                    first = False
                else:
                    list = f'{list}, {topic}'
            return list
    return None


# Function to add to list of followed topics of a user, returning True if added or False if topic already there.
def client_add_follow(user, topic):
    for reg in client_list:
        if reg[0] == user:
            if topic in reg[2]:
                return False
            else:
                reg[2].append(topic)
                return True
    return None


# Function to remove from list of followed topics of a user, returning True if removed or False if topic was not
# already there.
def client_remove_follow(user, topic):
    for reg in client_list:
        if reg[0] == user:
            if topic in reg[2]:
                reg[2].remove(topic)
                return True
            else:
                return False
    return None


# Function to read messages from clients.
def read_message(client_address, received_message):
    user = client_search_by_socket(client_address)
    print(f'Received message from user {user}:  ' + received_message)
    words = received_message.split(' ')
    print(words)

    # Check for specific commands.
    if ((len(words) == 2) and (
            ('!list' in words[1]) or ('!exit' in words[1]) or ('!follow?' in words[1]))):
        if '!list' in words[1]:
            response = list_clients() + '\n'
            send_ack(current_sequence_number[0], response.encode(), client_address)
        elif '!follow?' in words[1]:
            response = client_follows(user) + '\n'
            send_ack(current_sequence_number[0], response.encode(), client_address)

    # Check for specific commands with a parameter.
    elif (len(words) == 3) and (('!follow' in words[1]) or ('!unfollow' in words[1])):
        if '!follow' in words[1]:
            topic = words[2]
            if client_add_follow(user, topic):
                response = f'Now following {topic}\n'
            else:
                response = f'Error:  Was already following {topic}\n'
            send_ack(current_sequence_number[0], response.encode(), client_address)
        elif '!unfollow' in words[1]:
            topic = words[2]
            if topic == '@all':
                response = 'Error:  All users must follow @all\n'
            elif topic == '@' + user:
                response = 'Error:  Cannot unfollow yourself\n'
            elif client_remove_follow(user, topic):
                response = f'No longer following {topic}\n'
            else:
                response = f'Error:  Was not following {topic}\n'
            send_ack(current_sequence_number[0], response.encode(), client_address)

    # Check for user trying to upload/attach a file.  We strip the message to keep the user and any other text to
    # help forward the file.  Will send it to interested users like regular messages.
    elif (len(words) >= 3) and ('!attach' in words[1]):
        client_address.setblocking(True)
        filename = words[2]
        words.remove('!attach')
        words.remove(filename)
        response = f'ATTACH {filename} CHAT/1.0\n'
        send_ack(current_sequence_number[0], response.encode(), client_address)
        header = get_line_from_socket(client_address)
        header_words = header.split(' ')
        if (len(header_words) != 2) or (header_words[0] != 'Content-Length:'):
            response = f'Error:  Invalid attachment header\n'
        elif header_words[1] == '-1':
            response = f'Error:  Attached file {filename} could not be sent\n'
        else:
            interested_clients = []
            attach_size = header_words[1]
            attach_notice = f'ATTACHMENT {filename} CHAT/1.0\nOrigin: {user}\nContent-Length: {attach_size}\n'
            for reg in client_list:
                if reg[0] == user:
                    continue
                forwarded = False
                for term in reg[2]:
                    for word in words:
                        if (term == word.rstrip(punctuation)) and not forwarded:
                            interested_clients.append(reg[1])
                            reg[1].send(attach_notice.encode())
                            forwarded = True
            bytes_read = 0
            bytes_to_read = int(attach_size)
            while bytes_read < bytes_to_read:
                received_packet, client_address = server_socket.recvfrom(BUFFER_SIZE)
                unpacker = struct.Struct(f'I I {MAX_STRING_SIZE}s 32s')
                received_ACK, received_sequence, received_data, received_checksum = unpacker.unpack(received_packet)
                bytes_read += len(received_data)
                for client in interested_clients:
                    client.send(received_data)
            response = f'Attachment {filename} attached and distributed\n'
        send_ack(current_sequence_number[0], response.encode(), client_address)
        client_address.setblocking(False)

    # Look for follow terms and dispatch message to interested users.  Send at most only once, and don't send to
    # yourself.  Trailing punctuation is stripped. Need to re-add stripped newlines here.
    else:
        for reg in client_list:
            if reg[0] == user:
                continue
            forwarded = False
            for term in reg[2]:
                for word in words:
                    if (term == word.rstrip(punctuation)) and not forwarded:
                        client_sock = reg[1]
                        forwarded_message = f'{received_message}\n'
                        client_sock.send(forwarded_message.encode())
                        forwarded = True


# Our main function.
def main():
    # Set initial checksum compare result to false
    correct_checksum = False

    # Register our signal handler for shutting down.
    signal.signal(signal.SIGINT, signal_handler)

    # Bind the created UDP socket to a host name and port number
    server_socket.bind((UDP_IP, UDP_PORT))

    print('UDP server up and listening...')
    print('Will wait for client connections at port ' + str(server_socket.getsockname()[1]))
    print('Waiting for incoming client messages ...')

    # Infinite loop that takes input from clients and processes the inputs
    while True:
        # Receives input and source socket
        received_packet, client_address = server_socket.recvfrom(BUFFER_SIZE)
        # Define how the packet should be unpacked
        unpacker = struct.Struct(f'I I {MAX_STRING_SIZE}s 32s')
        # Unpack the received packet into variables
        received_ACK, received_sequence, received_data, received_checksum = unpacker.unpack(received_packet)
        received_message = received_data.decode()
        # Extract the sender's username from the received message
        user = received_message.split(':')[0]
        # Add the user to the list of users who connected to the server
        client_add(user, client_address, [])

        print("Packet received from:", client_address)

        # If the computed checksum matches the received checksum then send it to the function to process
        if compute_checksum(received_ACK, received_sequence, received_data) == received_checksum:
            correct_checksum = True
            print('Received and computed checksums match, received packet is now processed')
            read_message(client_address, received_message)
        # If the computed checksum does not match the received checksum print it out on the server
        else:
            print('Checksum does not match')
            correct_checksum = False

        # If the correct checksum variable is true and the sequence number matches then send the client an ACK
        if correct_checksum and received_sequence == current_sequence_number[0]:
            send_ack(current_sequence_number[0], received_data, client_address)
            # Change the state of the server to be ready to receive a message with the next sequence number
            current_sequence_number[0] = (current_sequence_number[0] + 1) % 2

        else:
            # If the correct checksum varable is false then send an ACK saying that an unexpected packet is received
            send_ack((current_sequence_number[0] + 1) % 2, received_data, client_address)

    # Keep the server running forever, waiting for connections or messages.
    while (True):
        events = sel.select()
        for key, mask in events:
            callback = key.data
            callback(key.fileobj, mask)


if __name__ == '__main__':
    main()
