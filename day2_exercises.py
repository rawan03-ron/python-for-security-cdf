import requests

# Exercise 1: fetch https://httpbin.org/uuid and print just the "uuid" field
response = requests.get("https://httpbin.org/uuid")
if response.status_code == 200:
    data = response.json()  # Parses JSON directly into a Python dictionary
    print("Extracted UUID:", data["uuid"])




from collections import Counter
import csv

exercise_connections_csv = """timestamp,src_ip,dst_port,protocol,bytes
2026-03-02T11:00:01,10.2.0.5,443,tcp,4000
2026-03-02T11:00:04,10.2.0.6,53,udp,120
2026-03-02T11:00:09,10.2.0.5,443,tcp,6500
2026-03-02T11:00:15,10.2.0.7,8080,tcp,300
2026-03-02T11:00:22,10.2.0.6,53,udp,90
2026-03-02T11:00:30,10.2.0.5,443,tcp,2200"""

with open("exercise_connections.csv", "w") as f:
  f.write(exercise_connections_csv)

# Exercise 2: find the src_ip with the highest total bytes transferred
ip_bytes = Counter()

with open("exercise_connections.csv", mode="r") as f:
  reader = csv.DictReader(f)
  for row in reader:
    # Convert string bytes to integer and accumulate per IP
    ip_bytes[row["src_ip"]] += int(row["bytes"])

top_talker, total_bytes = ip_bytes.most_common(1)[0]
print(f"Top Talker: {top_talker} with {total_bytes} bytes")



import hashlib
import socket


def quick_check(path, host, port):
  """Return {'sha256': ..., 'port_status': 'open'|'closed'}."""
  result = {}

  # 1. Compute SHA-256 Hash
  try:
    with open(path, "rb") as f:
      result["sha256"] = hashlib.sha256(f.read()).hexdigest()
  except FileNotFoundError:
    result["sha256"] = "FILE_NOT_FOUND"

  # 2. Check Port Status
  sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  sock.settimeout(0.5)
  conn_result = sock.connect_ex((host, port))
  sock.close()

  result["port_status"] = "open" if conn_result == 0 else "closed"

  return result


# Execution test:
print(quick_check("sample_file.txt", "127.0.0.1", 22))