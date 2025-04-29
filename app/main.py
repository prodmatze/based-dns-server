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

def build_ip_address(ip_address):
    octets = ip_address.split(".")

    ip_encoded = b""

    for octet in octets:
        ip_encoded += bytes([int(octet)]) 

    return ip_encoded

# !H = One 16-bit unsigned integer (2bytes)
# !HH = Two 16-bit unsigned integers (4bytes) --> ONE AFTER THE OTHER
# !I = One 32-bit unsigned integer (4bytes) --> ALL IN ONE SINGLE STRING
def build_response(headers, question, answer):
    #header section
    id_header = headers["id"]
    flags_header = headers["flags"]
    qdcount_header = headers["qdcount"]
    ancount_header = headers["ancount"]
    nscount_header= headers["nscount"]
    arcount_header = headers["arcount"]

    headers = struct.pack("!HHHHHH", id_header, flags_header, qdcount_header, ancount_header, nscount_header, arcount_header)

    #question section
    name_question = question["name"]
    type_question = question["type"]
    class_question = question["class"]

    question = name_question + struct.pack("!HH", type_question, class_question)

    #answer section
    name_answer = answer["name"]
    type_answer = answer["type"]
    class_answer = answer["class"]
    ttl_answer = answer["ttl"]
    length_answer = answer["length"]
    data_answer = answer["data"]

    answer = name_answer + struct.pack("!HH", type_answer, class_answer) + struct.pack("!I", ttl_answer) + struct.pack("!H", length_answer) + data_answer
    
    return headers + question + answer


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
                "ancount": 1,
                "nscount": 0,
                "arcount": 0
                }

            question = {
                "name": build_domain_name("codecrafters.io"),
                "type": 1,
                "class": 1,
            }

            answer = {
                "name": build_domain_name("codecrafters.io"),
                "type": 1,
                "class": 1,
                "ttl": 60,
                "length": 4,
                "data": build_ip_address("8.8.8.8"),
            }

            response = build_response(headers, question, answer)

            print(f"Sending Response: {response}")

            udp_socket.sendto(response, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break


if __name__ == "__main__":
    main()
