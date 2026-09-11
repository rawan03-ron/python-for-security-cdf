"""
Day 2: Combined Deliverable
Program: Darb.tech CDF Programme - P2 Python Intensive

Contains:
1. Exercise 1: JSON UUID Extraction
2. Exercise 2: Top Talker by Bytes (CSV Processing)
3. Exercise 3: Quick Integrity Check (Hashing & Port Scanning)
4. Log Anomaly Flagger Tool (Keyword & IP Threshold Analysis)
"""

import csv
import hashlib
import re
import socket
from collections import Counter
import requests

# ==============================================================================
# PART 1: Day 2 Exercises (2.9 On Your Own)
# ==============================================================================


# Exercise 1: JSON Field Extraction
def exercise_1():
  print("=== Exercise 1: UUID Extraction ===")
  try:
    response = requests.get("https://httpbin.org/uuid", timeout=5)
    if response.status_code == 200:
      data = response.json()
      print("Extracted UUID:", data["uuid"])
    else:
      print(f"Failed to fetch UUID. Status Code: {response.status_code}")
  except Exception as e:
    print(f"Error in Exercise 1: {e}")


# Exercise 2: Top Talker by Bytes
def exercise_2():
  print("\n=== Exercise 2: Top Talker by Bytes ===")

  exercise_connections_csv = """timestamp,src_ip,dst_port,protocol,bytes
2026-03-02T11:00:01,10.2.0.5,443,tcp,4000
2026-03-02T11:00:04,10.2.0.6,53,udp,120
2026-03-02T11:00:09,10.2.0.5,443,tcp,6500
2026-03-02T11:00:15,10.2.0.7,8080,tcp,300
2026-03-02T11:00:22,10.2.0.6,53,udp,90
2026-03-02T11:00:30,10.2.0.5,443,tcp,2200"""

  with open("exercise_connections.csv", "w", encoding="utf-8") as f:
    f.write(exercise_connections_csv.strip())

  ip_bytes = Counter()
  with open("exercise_connections.csv", mode="r", encoding="utf-8") as f:
    reader = csv.DictReader(f)
    for row in reader:
      ip_bytes[row["src_ip"]] += int(row["bytes"])

  top_talker, total_bytes = ip_bytes.most_common(1)[0]
  print(f"Top Talker: {top_talker} with {total_bytes} bytes")


# Exercise 3: Quick Integrity Check
def quick_check(path, host, port):
  """Return {'sha256': ..., 'port_status': 'open'|'closed'}."""
  result = {}

  try:
    with open(path, "rb") as f:
      result["sha256"] = hashlib.sha256(f.read()).hexdigest()
  except FileNotFoundError:
    result["sha256"] = "FILE_NOT_FOUND"

  sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  sock.settimeout(0.5)
  conn_result = sock.connect_ex((host, port))
  sock.close()

  result["port_status"] = "open" if conn_result == 0 else "closed"
  return result


def exercise_3():
  print("\n=== Exercise 3: Quick Integrity Check ===")
  with open("sample_file.txt", "w", encoding="utf-8") as f:
    f.write("Sample content for testing.")

  check_results = quick_check("sample_file.txt", "127.0.0.1", 22)
  print("Quick Check Results:", check_results)


# ==============================================================================
# PART 2: Log Anomaly Flagger Tool
# ==============================================================================


def flag_keywords(filename, keywords):
  """Print any line in filename containing one of keywords (floor)."""
  print("\n--- Floor: Keyword Matching ---")
  with open(filename, "r", encoding="utf-8") as f:
    for line in f:
      if any(keyword in line for keyword in keywords):
        print(line.strip())


def flag_ip_threshold(filename, threshold):
  """Flag any source IP with more than `threshold` failed attempts (ceiling)."""
  print("\n--- Ceiling: IP Threshold Flagging ---")
  ip_counts = Counter()
  with open(filename, "r", encoding="utf-8") as f:
    for line in f:
      if "Failed password" in line:
        match = re.search(r"\d+\.\d+\.\d+\.\d+", line)
        if match:
          ip_counts[match.group()] += 1

  for ip, count in ip_counts.items():
    if count > threshold:
      print(f"FLAGGED: {ip} ({count} failed attempts)")


def run_log_flagger():
  sample_log_content = """
2026-09-10 10:00:01 Failed password for root from 192.168.1.50 port 22
2026-09-10 10:00:02 Failed password for admin from 192.168.1.50 port 22
2026-09-10 10:00:03 Failed password for user1 from 192.168.1.50 port 22
2026-09-10 10:00:04 Accepted password for user2 from 10.0.0.5 port 22
2026-09-10 10:00:05 CRITICAL: Unauthorized access attempt detected
"""
  with open("auth.log", "w", encoding="utf-8") as f:
    f.write(sample_log_content.strip())

  flag_keywords("auth.log", ["CRITICAL", "Unauthorized"])
  flag_ip_threshold("auth.log", threshold=2)


# ==============================================================================
# Execution Block
# ==============================================================================
if __name__ == "__main__":
  # Run Exercises
  exercise_1()
  exercise_2()
  exercise_3()

  # Run Log Flagger Tool
  run_log_flagger()
