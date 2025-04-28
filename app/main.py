import socket
import struct

def parse_query(query):

    return None

def build_response(id, flags, qdcount, ancount, nscount, arcount):
    headers = struct.pack("!HHHHHH", id, flags, qdcount, ancount, nscount, arcount)

    return headers

def main():
    print("Logs from your program will appear here!")

    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))

    while True:
        try:
            buf, source = udp_socket.recvfrom(512)

            print(f"Incoming Query from {source} : {buf}")

            id = 1234
            flags = 0b1000000000000000
            qdcount = 0
            ancount = 0
            nscount = 0
            arcount = 0
            response = build_response(id, flags, qdcount, ancount, nscount, arcount)

            print(f"Sending Response: {response}")

            udp_socket.sendto(response, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break


if __name__ == "__main__":
    main()
