### DNS Server with Optional Forwarding

This Python program implements a DNS server that can answer queries either:
- **locally**, with a hardcoded mock answer (8.8.8.8), or
- **by forwarding** them to an upstream resolver like 1.1.1.1 or 8.8.8.8.

It handles parsing, building, and forwarding real DNS queries with support for compressed domain names.

This was built from scratch as part of the Codecrafters “Build your own DNS Server” challenge.

---

## ✅ Features
- DNS packet parsing (header, questions, answers)
- DNS name compression handling
- Response construction from scratch
- Optional query forwarding to an upstream resolver
- Debug logs for educational purposes and development

---

## 🚀 How to Run

```bash
python3 main.py                 # Local mock response mode
python3 main.py --resolver 1.1.1.1:53   # Forwarding mode
```

> The server listens on `127.0.0.1:2053` by default.

To test it, run from another terminal:

```bash
dig @127.0.0.1 -p 2053 example.com A
```

Note: `dig` sends one query per domain. To test multiple-question behavior, you'd need to craft a custom DNS packet.

---

## 🧠 Design Overview

### Packet Parsing
- `parse_header()`: reads the 12-byte DNS header
- `parse_name_section()`: handles both raw labels and name compression pointers
- `parse_question()` and `parse_answer()`: decode questions/answers from the binary format

### Packet Construction
- `build_domain_name()`: encodes names with label lengths
- `build_header()`: packs header values into bytes
- `build_response()`: builds a valid DNS response from parsed components

### Query Forwarding
- If `--resolver` is used:
  - Splits multi-question queries into single-question packets
  - Sends each to the resolver, collects responses
  - Merges into one final response

