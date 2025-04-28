import socket
import struct

def parse_query(query):

    return None

def build_domain_name(domain_name):
    labels = domain_name.split(".")

    encoded_name = b""

    for label in labels:
        length = len(label)
        encoded_name += bytes([length])
        encoded_name += label.encode()

    encoded_name += b"\x00"

    return encoded_name

def build_response(headers, question):
    #headers
    id_bytes = headers["id"]
    flags_bytes = headers["flags"]
    qdcount_bytes = headers["qdcount"]
    ancount_bytes = headers["ancount"]
    nscount_bytes = headers["nscount"]
    arcount_bytes = headers["arcount"]

    headers = struct.pack("!HHHHHH", id_bytes, flags_bytes, qdcount_bytes, ancount_bytes, nscount_bytes, arcount_bytes)

    #question
    name_bytes = question["name"]
    type_bytes = question["type"]
    class_bytes = question["class"]

    question = name_bytes + struct.pack("!HH", type_bytes, class_bytes)

    return headers + question


def main():
    print("Logs from your program will appear here!")

    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))

    while True:
        try:
            buf, source = udp_socket.recvfrom(512)

            print(f"Incoming Query from {source} : {buf}")

            headers = {
                "id": 1234,
                "flags": 0b1000000000000000,
                "qdcount": 1,
                "ancount": 0,
                "nscount": 0,
                "arcount": 0
                }

            question = {
                "name": build_domain_name("codecrafters.io"),
                "type": 1,
                "class": 1,
            }

            response = build_response(headers, question)

            print(f"Sending Response: {response}")

            udp_socket.sendto(response, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break


if __name__ == "__main__":
    main()
