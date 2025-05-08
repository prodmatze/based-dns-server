# 🧠 BASED DNS Server (Python)

This is a fully functional DNS server implementation in Python, built from scratch as part of the [Codecrafters](https://codecrafters.io) “Build your own DNS Server” challenge.

It handles raw DNS query parsing, name compression resolution, and query forwarding — all implemented manually without third-party libraries.

---

## 🚀 Features

* ✅ Parses raw DNS packets (header, question, and answer sections)
* ✅ Supports DNS name compression (pointers)
* ✅ Answers locally with `8.8.8.8` when no resolver is set
* ✅ Forwards queries to an upstream resolver (like `1.1.1.1`) with full parsing of the response
* ✅ Handles multiple questions per query (splits and merges as required)

---

## 📦 How to Use

### 1. **Local Mock Server (answers with 8.8.8.8):**

```bash
python app/main.py
```

### 2. **Forwarding Mode (real DNS resolution):**

```bash
python app/main.py --resolver 1.1.1.1:53
```

In this mode, the server splits multi-question queries into individual requests (as required by the upstream resolver), forwards them, and merges the responses back.

---

## 🛠 What I Learned

* How DNS queries are structured at the byte level
* Parsing and constructing packets manually using Python’s `struct` module
* DNS name compression using pointers (`0xC0` mask)
* UDP socket programming and networking fundamentals
* Protocol debugging through iterative testing

---

## 💡 Inspiration

This project was built as part of the [Codecrafters.io](https://codecrafters.io) platform, which provides test-driven engineering challenges modeled after real-world systems. Every feature was verified against protocol-level tests, not just mock data.

---

## ✅ Next Steps / Ideas

* Add support for `AAAA` (IPv6) queries
* Implement a cache (with TTL expiration)
* Support additional DNS record types (e.g. MX, CNAME)
* Integrate logging / metrics collection for debugging or visualization
