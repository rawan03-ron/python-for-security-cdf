from collections import Counter
import re

# 1. إنشاء ملف سجل وهمي لاختبار الأداة (توفير البيانات)
sample_log_content = """
2026-09-10 10:00:01 Failed password for root from 192.168.1.50 port 22
2026-09-10 10:00:02 Failed password for admin from 192.168.1.50 port 22
2026-09-10 10:00:03 Failed password for user1 from 192.168.1.50 port 22
2026-09-10 10:00:04 Accepted password for user2 from 10.0.0.5 port 22
2026-09-10 10:00:05 CRITICAL: Unauthorized access attempt detected
"""

with open("auth.log", "w") as f:
  f.write(sample_log_content.strip())


# 2. Option B: Log Anomaly Flagger (الكود المعطى)
def flag_keywords(filename, keywords):
  """Print any line in filename containing one of keywords.

  (floor)
  """
  with open(filename) as f:
    for line in f:
      if any(keyword in line for keyword in keywords):
        print(line.strip())


def flag_ip_threshold(filename, threshold):
  """Flag any source IP with more than `threshold` failed attempts.

  (ceiling)
  """
  ip_counts = Counter()
  with open(filename) as f:
    for line in f:
      if "Failed password" in line:
        match = re.search(r"\d+\.\d+\.\d+\.\d+", line)
        if match:
          ip_counts[match.group()] += 1
  for ip, count in ip_counts.items():
    if count > threshold:
      print(f"FLAGGED: {ip} ({count} failed attempts)")


# 3. استدعاء الدوال وتطبيق الأداة (التشغيل الفعلية)
print("--- Floor: Keyword Matching ---")
flag_keywords("auth.log", ["CRITICAL", "Unauthorized"])

print("\n--- Ceiling: IP Threshold Flagging ---")
flag_ip_threshold("auth.log", threshold=2)