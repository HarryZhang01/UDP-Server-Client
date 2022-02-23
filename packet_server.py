import socket
import struct
import hashlib

# Hard code location of the server.  Not what we'll want to be doing in the assignment,
# but okay for an example like this.

UDP_IP = "localhost"
UDP_PORT = 54321

# Define a maximum string size for the text we'll be receiving.

MAX_STRING_SIZE = 256


# Our main function.

def main():
    # Create our UDP socket and bind it to the address that clients expect us to be on.

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((UDP_IP, UDP_PORT))

    # Next, we loop forever waiting for packets to arrive from clients.

    while True:

        # We receive data and start to unpack it.  We'll use a 1024 byte buffer here.
        # Notice that our packet structure mirrors what the client is sending along.
        # The client and server have to agree on this or it won't work!

        received_packet, addr = sock.recvfrom(1024)
        unpacker = struct.Struct(f'I I {MAX_STRING_SIZE}s 32s')
        UDP_packet = unpacker.unpack(received_packet)

        # Extract out data that was received from the packet.  It unpacks to a tuple,
        # but it's easy enough to split apart.

        received_sequence = UDP_packet[0]
        received_size = UDP_packet[1]
        received_data = UDP_packet[2]
        received_checksum = UDP_packet[3]

        # Print out what we received.

        print("Packet received from:", addr)
        print("Packet data:", UDP_packet)

        # We now compute the checksum on what was received to compare with the checksum
        # that arrived with the data.  So, we repack our received packet parts into a tuple
        # and compute a checksum against that, just like we did on the sending side.

        values = (received_sequence, received_size, received_data)
        packer = struct.Struct(f'I I {MAX_STRING_SIZE}s')
        packed_data = packer.pack(*values)
        computed_checksum = bytes(hashlib.md5(packed_data).hexdigest(), encoding="UTF-8")

        # We can now compare the computed and received checksums to see if any corruption of
        # data can be detected.  Note that we only need to decode the data according to the
        # size we intended to send; the padding can be ignored.

        if received_checksum == computed_checksum:
            print('Received and computed checksums match, so packet can be processed')
            received_text = received_data[:received_size].decode()
            print(f'Message text was:  {received_text}')
        else:
            print(
                'Received and computed checksums do not match, so packet is corrupt and discarded')


if __name__ == '__main__':
    main()
