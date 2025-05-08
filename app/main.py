import socket
import struct
import argparse

#configuration for command-line args
argparser = argparse.ArgumentParser()
argparser.add_argument("--resolver", help="Forward DNS queries to the specified resolver (ip:port)")
args = argparser.parse_args()

query_forwarding = False

if args.resolver:
    resolve_ip, resolve_port = args.resolver.split(":")
    resolve_port = int(resolve_port)

    query_forwarding = True
    print(f"RESOLVING IN FORWARDING MODE - Using resolver at {resolve_ip}:{resolve_port}")
else:
    query_forwarding = False
    print(f"RESOLVING IN LOCAL MODE - NO FORWARDING")

### DNS HEADER PARSING ###
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

### DNS NAME COMPRESSION PARSING ###
def parse_name_section(query, offset):
    #offset = byte where name starts
    #encoded name = [label_length] -> [label] -> [label_length] -> [label] -> [null byte]
    labels = []
    pointer_indicator = 0b11000000
    pointer_mask = 0b0011111111111111

    jumped = False              #track if we followed a pointer
    original_offset = offset
    final_offset = offset

    while True:
        #query[offset] : accesses individual byte
        label_length = query[offset]                                    #beginning of label section
        if label_length & pointer_indicator == pointer_indicator:       #check if beginning is a pointer
            pointer_bytes = query[offset:offset+2]                      #pointers are 2 bytes
            pointer = struct.unpack("!H", pointer_bytes)[0] & pointer_mask #get pointer value

            if not jumped:
                final_offset = offset + 2                               #increment final offset by 2(length of pointer) only once, when a pointer is encountered
                jumped = True

            offset = pointer
            continue

        if label_length == 0:               #repeat until loop reaches null byte
            if not jumped:              
                final_offset = offset + 1   #skip null byte

            break
        
        offset += 1                         #length is one byte, so start parsing one after the length byte
        label = query[offset:offset+label_length].decode()
        labels.append(label)
        offset += label_length

    domain_name = ".".join(labels)
    raw_name = query[original_offset:final_offset]

    return domain_name, final_offset, raw_name

### QUESTION PARSING ###
def parse_question(query, offset):
    question_name, question_offset, raw_name = parse_name_section(query, offset)
    question = {
        "name": question_name,
        "raw_name": raw_name,
        "type": struct.unpack("!H", query[question_offset: question_offset+2])[0],
        "class": struct.unpack("!H", query[question_offset + 2: question_offset + 4])[0]
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

### ANSWER PARSING ### 
def parse_answer(query, offset):
    answer_name, offset, raw_name = parse_name_section(query, offset)

    type_ = struct.unpack("!H", query[offset:offset+2])[0]
    offset += 2
    
    class_ = struct.unpack("!H", query[offset:offset+2])[0]
    offset += 2

    ttl = struct.unpack("!I", query[offset:offset+4])[0]
    offset += 4

    rdlength = struct.unpack("!H", query[offset:offset+2])[0]
    offset += 2

    rdata = query[offset:offset+rdlength]
    offset += rdlength

    answer = {
        "name": answer_name,
        "raw_name": raw_name,
        "type": type_,
        "class": class_, 
        "ttl": ttl,
        "length": rdlength,
        "rdata": rdata,
    }

    return answer, offset 

def parse_all_answers(query, qdcount, offset):
    answers = []

    for i in range(qdcount):
        answer, post_answer_offset = parse_answer(query, offset)
        answers.append(answer)
        offset = post_answer_offset

    return answers, offset

### PARSE COMPLETE QUERY ### 
def parse_query(query, contains_answer=False):
    header = parse_header(query)
    question_count = header["qdcount"]

    questions, questions_offset = parse_all_questions(query, question_count, 12)
    answers = []

    if contains_answer:
        answer_count = header["ancount"]
        answers, answer_offset = parse_all_answers(query, answer_count, questions_offset)

    return {"header": header, "questions": questions, "answers": answers}

### FLAG DECODING AND BUILDING ###
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

### BUILDERS ###
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
    print("Building Header...")
    id_header = header["id"]
    flags_header = header["flags"]
    qdcount_header = header["qdcount"]
    ancount_header = header["ancount"]
    nscount_header= header["nscount"]
    arcount_header = header["arcount"]

    header = struct.pack("!HHHHHH", id_header, flags_header, qdcount_header, ancount_header, nscount_header, arcount_header)

    return header

def build_question(question):
    print(f"Building Question...")
    name_question = build_domain_name(question["name"])
    type_question = question["type"]
    class_question = question["class"]

    question = name_question + struct.pack("!HH", type_question, class_question)

    return question

def build_answer(answer):
    print(f"Building Answer...")
    name_answer = build_domain_name(answer["name"])
    type_answer = answer["type"]
    class_answer = answer["class"]
    ttl_answer = answer["ttl"]
    length_answer = answer["length"]
    data_answer = answer["rdata"]

    answer = name_answer + struct.pack("!HH", type_answer, class_answer) + struct.pack("!I", ttl_answer) + struct.pack("!H", length_answer) + data_answer

    return answer

def build_response(header, questions, answers):
    print(f"\nBuilding Response with {len(questions)} Question(s) + {len(answers)} Answer(s):\n")
    header = build_header(header)

    question_section = b""
    answer_section = b""

    for question in questions:
        question_section += build_question(question)

    for answer in answers:
        answer_section += build_answer(answer)

    print("\nDone. RESPONSE is Built! \n")

    return header + question_section + answer_section

def build_query(header, questions):
    print(f"\nBuilding Query with {len(questions)} Question(s):\n")
    header = build_header(header)
    question_section = b""

    for question in questions:
        question_section += build_question(question)

    print("\nDone. QUERY is Built! \n")
    return header + question_section 

### MAIN SERVER LOOP ### 
def main():

    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))

    while True:
        print("\nAwaiting incoming Queries...\n")
        try:
            buf, source = udp_socket.recvfrom(512)

            print(f"Incoming Query from {source} : {buf}\n")
            #parsing the query:
            parsed_query = parse_query(buf)
            query_flags = get_flags_from_flag(parsed_query["header"]["flags"])

            #build response header template
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

            #forwarding mode
            if query_forwarding:
                resolver_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

                split_queries = []

                for question in parsed_query["questions"]:
                    query_header = parsed_query["header"].copy()
                    query_header["qdcount"] = 1
                    query_header["arcount"] = 0
                    query = build_query(query_header, [question])
                    split_queries.append(query)

                recieved_responses = []
                for query in split_queries:
                    print(f"Forwarding Query to Resolver {resolve_ip}:{resolve_port} ...\n")
                    try:
                        resolver_socket.sendto(query, (resolve_ip, resolve_port))
                        response, _ = resolver_socket.recvfrom(512)

                        parsed_response = parse_query(response, contains_answer=True)
                        print(f"Recieved Response from Resolver for Query: {parsed_query['questions'][0]['name']}")
                        recieved_responses.append(parsed_response)

                    except socket.timeout:
                        print(f"No response from resolver for query: {parsed_query['questions'][0]['name']}")

                print(f"Recieved a total of {len(recieved_responses)} Response(s)!\n")

                for response in recieved_responses:
                    questions += response["questions"]
                    answers += response["answers"]

                headers = {
                    "id": parsed_query["header"]["id"],
                    "flags": recieved_responses[0]["header"]["flags"],
                    "qdcount": len(questions),
                    "ancount": len(answers),
                    "nscount": 0,
                    "arcount": 0
                    }

                print(f"Now rebuilding/merging Response(s) with... \nHeader : {headers} \nQuestion(s) ({len(questions)}) : {questions}, {type(questions)} \nAnswer(s) ({len(answers)}) : {answers}, {type(answers)}")
                response = build_response(headers, questions, answers)

                print(f"Forwarding Response to original Client...")
                udp_socket.sendto(response, source)
                continue

            #local resolution (mock)
            questions = []
            answers = []
            for i in range(parsed_query["header"]["qdcount"]):
                qname = parsed_query["questions"][i]["name"]
                questions.append(
                    {
                    "name": qname,
                    "raw_name": qname,
                    "type": 1,
                    "class": 1,
                    }
                )
            
                answers.append(
                    {
                    "name": qname,
                    "raw_name": qname,
                    "type": 1,
                    "class": 1,
                    "ttl": 60,
                    "length": 4,
                    "rdata": build_ip_address("8.8.8.8"),
                    }
                )

            print(f"\nBuilt {len(questions)} Question(s):\n{questions} \n")
            print(f"Built{len(answers)} Answer(s):\n{answers}")

            response = build_response(headers, questions, answers)

            print(f"Sending Response to Client: {response}")

            udp_socket.sendto(response, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break

if __name__ == "__main__":
    main()
