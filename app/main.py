import socket
import struct
import argparse

argparser = argparse.ArgumentParser()
argparser.add_argument("--resolver")
args = argparser.parse_args()

query_forwarding = False

if args.resolver:
    resolve_ip, resolve_port = args.resolver.split(":")
    resolve_port = int(resolve_port)

    query_forwarding = True
    print(f"RESOLVING IN FORWARDING MODE - Using resolver at {resolve_ip}:{resolve_port}")
else:
    print(f"RESOLVING IN LOCAL MODE - NO FORWARDING")




def parse_header(query):

    #struct.unpack:
    #give struct.unpack a bytes object, and tell it how to interpret it
    #you can slice bytestring like any string/array: [0:2]  ->  return slice FROM 0 Index UP TO BUT NOT INCLUDING 2 INDEX -> first 2 
    #!H only indicates how to INTERPRET the sliced bytes -> !H = these are big-endian, unsigned short (2 bytes)
    #always returns tuple -> access [0]

    header = {
        "id": struct.unpack("!H", query[0:2])[0],
        "flags": struct.unpack("!H", query[2:4])[0],
        "qdcount": struct.unpack("!H", query[4:6])[0],
        "ancount": struct.unpack("!H", query[6:8])[0],
        "nscount": struct.unpack("!H", query[8:10])[0],
        "arcount": struct.unpack("!H", query[10:12])[0],
    }

    return header

def parse_name_section(query, offset):
    #offset = byte where name starts
    #encoded name = [label_length] -> [label] -> [label_length] -> [label] -> [null byte]
    labels = []

    pointer_indicator = 0b11000000
    pointer_mask = 0b0011111111111111

    while True:
        #query[offset] accesses individual byte
        label_length = query[offset]
        if query[offset] & pointer_indicator == pointer_indicator:
            pointer_bytes = query[offset:offset+2]
            pointer = struct.unpack("!H", pointer_bytes)[0] & pointer_mask
            domain_name, _ = parse_name_section(query, pointer)
            return domain_name, offset + 2
        if label_length == 0:           #repeat until loop reaches null byte
            offset += 1                 #skip null byte
            break
        offset += 1                     #start counting from one after length byte (one after the offset)
        label = query[offset:offset + label_length].decode()
        labels.append(label)
        offset += label_length

    domain_name = ".".join(labels)

    return domain_name, offset

def parse_question(query, offset):
    question_name, question_offset = parse_name_section(query, offset)
    question = {
        "name": question_name,
        "type": struct.unpack("!H", query[question_offset: question_offset+2]),
        "class": struct.unpack("!H", query[question_offset + 2: question_offset + 4])
    }

    post_question_offset = question_offset + 4
    return question, post_question_offset 

def parse_all_questions(query, qdcount, offset):
    questions = []

    for i in range(qdcount):
        question, post_question_offset = parse_question(query, offset)
        questions.append(question)
        offset = post_question_offset

    return questions, offset

def parse_answer(query, offset):
    answer_name, offset = parse_name_section(query, offset)

    type_ = struct.unpack("!H", query[offset:offset+2])[0]
    offset += 2
    
    class_ = struct.unpack("!H", query[offset:offset+2])[0]
    offset += 2

    ttl = struct.unpack("!I", query[offset:offset+4])[0]
    offset += 4

    rdlength = struct.unpack("!H", query[offset:offset+2])[0]
    offset += 2

    rdata = struct.unpack("!H", query[offset:offset+2])[0]
    offset += 2

    answer = {
        "name": answer_name,
        "type": type_,
        "class": class_, 
        "ttl": ttl,
        "length": rdlength,
        "data": rdata,
    }

    return answer, offset 

def parse_all_answers(query, qdcount, offset):
    answers = []

    for i in range(qdcount):
        answer, post_answer_offset = parse_answer(query, offset)
        answers.append(answer)
        offset = post_answer_offset

    return answers, offset

def parse_query(query, contains_answer=False):
    header = parse_header(query)
    question_count = header["qdcount"]

    questions, questions_offset = parse_all_questions(query, question_count, 12)
    answers = []

    if contains_answer:
        answer_count = header["ancount"]
        answers = parse_all_answers(query, answer_count, questions_offset)

    return {"header": header, "questions": questions, "answers": answers}

#setting individual bits and shifting to the right flag positions
#after ANDing them with the flag header, multibit fields need to get shifted right again!
flag_masks = {
    "qr": 1 << 15,              #query/respose
    "opcode": 0b1111 << 11,     #4-bit Opcode
    "aa": 1 << 10,              #Authoritative answer?
    "tc": 1 << 9,               #truncated
    "rd": 1 << 8,               #recursive desired
    "ra": 1 << 7,               #recursive available
    "z": 0b111 << 4,            #reserved (must be 0)
    "rcode": 0b1111,            #4-bit response code
}

def get_flags_from_flag(flags):

    parsed_flags = {
        "qr": 1 if flags & flag_masks["qr"] else 0,
        "opcode": (flags & flag_masks["opcode"]) >> 11,
        "aa": 1 if flags & flag_masks["aa"] else 0,  
        "tc": 1 if flags & flag_masks["tc"] else 0,  
        "rd": 1 if flags & flag_masks["rd"] else 0,  
        "ra": 1 if flags & flag_masks["ra"] else 0,  
        "z": (flags & flag_masks["z"]) >> 4,
        "rcode": flags & flag_masks["rcode"]
    }

    print("Parsed these Flags:")
    for key, value in parsed_flags.items():
        print(f"{key.upper():7}: {value}")

    return parsed_flags

def build_flags(flag_dict):
    qr = flag_dict["qr"] << 15
    opcode = flag_dict["opcode"] << 11
    aa = flag_dict["aa"] << 10 
    tc = flag_dict["tc"] << 9
    rd = flag_dict["rd"] << 8
    ra = flag_dict["ra"] << 7
    z = flag_dict["z"] << 4
    rcode = flag_dict["rcode"]

    flag_list = [qr, opcode, aa, tc, rd, ra, z, rcode]

    flags = 0

    for flag in flag_list:
        flags = flags | flag

    return flags

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
def build_header(header):
    id_header = header["id"]
    flags_header = header["flags"]
    qdcount_header = header["qdcount"]
    ancount_header = header["ancount"]
    nscount_header= header["nscount"]
    arcount_header = header["arcount"]

    header = struct.pack("!HHHHHH", id_header, flags_header, qdcount_header, ancount_header, nscount_header, arcount_header)

    return header

def build_question(question):
    name_question = question["name"]
    type_question = question["type"]
    class_question = question["class"]

    question = name_question + struct.pack("!HH", type_question, class_question)

    return question

def build_answer(answer):
    name_answer = answer["name"]
    type_answer = answer["type"]
    class_answer = answer["class"]
    ttl_answer = answer["ttl"]
    length_answer = answer["length"]
    data_answer = answer["data"]

    answer = name_answer + struct.pack("!HH", type_answer, class_answer) + struct.pack("!I", ttl_answer) + struct.pack("!H", length_answer) + data_answer

    return answer

def build_response(header, questions, answers):
    header = build_header(header)

    question_section = b""
    answer_section = b""

    for question in questions:
        question_section += build_question(question)

    for answer in answers:
        answer_section += build_answer(answer)

    return header + question_section + answer_section


def main():
    print("Logs from your program will appear here!")

    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))

    while True:
        try:
            buf, source = udp_socket.recvfrom(512)

            print(f"Incoming Query from {source} : {buf}")

            #parsing the query:
            parsed_query = parse_query(buf)
            query_flags = get_flags_from_flag(parsed_query["header"]["flags"])

            #setting flags for the answer
            flags_to_send = {
                "qr": 1,              
                "opcode": query_flags["opcode"],     
                "aa": 0,              
                "tc": 0,               
                "rd": query_flags["rd"],               
                "ra": 0,               
                "z": 000,            
                "rcode": 0 if query_flags["opcode"] == 0 else 4,            
                }

            headers = {
                "id": parsed_query["header"]["id"],
                "flags": build_flags(flags_to_send),
                "qdcount": parsed_query["header"]["qdcount"],
                "ancount": parsed_query["header"]["qdcount"],
                "nscount": 0,
                "arcount": 0
                }

            questions = []
            answers = []

            if query_forwarding:
                resolver_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                resolver_socket.sendto(buf, (resolve_ip, resolve_port))

                response, _ = resolver_socket.recvfrom(512)

                parsed_response = parse_query(response, contains_answer=True)

                headers = {
                    "id": parsed_query["header"]["id"],
                    "flags": parsed_response["header"]["flags"],
                    "qdcount": parsed_response["header"]["qdcount"],
                    "ancount": parsed_response["header"]["qdcount"],
                    "nscount": 0,
                    "arcount": 0
                    }

                # for i in range(parsed_response["header"]["qdcount"]):
                #     qname = parsed_response["questions"][i]["name"]
                #     print(f"PARSING QNAME_{i}: {qname}")
                #     questions.append(
                #         {
                #         "name": build_domain_name(qname),
                #         "type": 1,
                #         "class": 1,
                #         }
                #     )
                # 
                #     answers.append(
                #         {
                #         "name": build_domain_name(qname),
                #         "type": 1,
                #         "class": 1,
                #         "ttl": 60,
                #         "length": 4,
                #         "data": parsed_response["answers"][0]["data"],
                #         }
                #     )

                response = build_response(headers, parsed_response["questions"], parsed_response["answers"])
                udp_socket.sendto(response, source)

                break

            questions = []
            answers = []

            for i in range(parsed_query["header"]["qdcount"]):
                qname = parsed_query["questions"][i]["name"]
                print(f"PARSING QNAME_{i}: {qname}")
                questions.append(
                    {
                    "name": build_domain_name(qname),
                    "type": 1,
                    "class": 1,
                    }
                )
            
                answers.append(
                    {
                    "name": build_domain_name(qname),
                    "type": 1,
                    "class": 1,
                    "ttl": 60,
                    "length": 4,
                    "data": build_ip_address("8.8.8.8"),
                    }
                )

            print(f"BUILT THESE QUESTIONS ({len(questions)}): {questions}")
            print(f"BUILT THESE ANSWERS ({len(answers)}): {answers}")

            response = build_response(headers, questions, answers)

            print(f"Sending Response: {response}")

            udp_socket.sendto(response, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break

if __name__ == "__main__":
    main()
