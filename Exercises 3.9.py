import csv
import hashlib
import os
from collections import Counter

# --- 1. تجهيز بيئة العمل والملفات التجريبية تلقائياً ---
os.makedirs("sample_evidence", exist_ok=True)
os.makedirs("dup_evidence", exist_ok=True)

# ملفات تجريبية للتمرين الأول
with open(os.path.join("sample_evidence", "small_log.txt"), "w") as f:
    f.write("Short log entry.")
with open(os.path.join("sample_evidence", "large_memory_dump.raw"), "w") as f:
    f.write("This is a much larger payload content simulating a big file!")

# ملفات تجريبية للتمرين الثالث
with open(os.path.join("dup_evidence", "invoice.docx"), "w") as f:
    f.write("identical payload content\n")
with open(os.path.join("dup_evidence", "svchost.exe"), "w") as f:
    f.write("identical payload content\n")
with open(os.path.join("dup_evidence", "notes.txt"), "w") as f:
    f.write("unrelated content\n")

# ملف CSV للتمرين الثاني
exercise_artifacts_csv = """timestamp,event_type,path
2026-03-02T14:00:00,process_started,/usr/bin/bash
2026-03-02T14:01:10,file_created,/tmp/loader.sh
2026-03-02T14:01:40,process_started,/tmp/loader.sh
2026-03-02T14:02:05,file_created,/tmp/loader.sh
2026-03-02T14:03:20,process_started,/tmp/loader.sh
2026-03-02T14:05:00,file_deleted,/tmp/loader.sh"""

with open("exercise_artifacts.csv", "w") as f:
    f.write(exercise_artifacts_csv)


# --- Exercise 1: Largest file ---
print("=== Exercise 1: Largest File ===")
folder = "sample_evidence"
largest_file = None
max_size = 0

for name in os.listdir(folder):
    path = os.path.join(folder, name)
    if os.path.isfile(path):
        size = os.stat(path).st_size
        if size > max_size:
            max_size = size
            largest_file = name

print(f"Largest file: {largest_file} ({max_size} bytes)\n")


# --- Exercise 2: Busiest path ---
print("=== Exercise 2: Busiest Path ===")
with open("exercise_artifacts.csv", "r") as f:
    reader = csv.DictReader(f)
    paths = [row["path"] for row in reader]

busiest_path, count = Counter(paths).most_common(1)[0]
print(f"Busiest path: {busiest_path} (appeared {count} times)\n")


# --- Exercise 3: Duplicate-content detector ---
print("=== Exercise 3: Duplicate-Content Detector ===")


def find_duplicates(folder):
    """Return {hash: [filenames]} for every hash shared by more than one file."""
    hashes = {}
    for name in os.listdir(folder):
        path = os.path.join(folder, name)
        if os.path.isfile(path):
            with open(path, "rb") as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
            hashes.setdefault(file_hash, []).append(name)

    # تصفية النتائج لإرجاع الملفات المكررة فقط
    duplicates = {h: files for h, files in hashes.items() if len(files) > 1}
    return duplicates


duplicates = find_duplicates("dup_evidence")
for h, files in duplicates.items():
    print(f"Hash: {h[:12]}... -> Files: {files}")