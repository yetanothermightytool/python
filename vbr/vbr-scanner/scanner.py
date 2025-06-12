#!/usr/bin/env python3
import argparse
import os
import hashlib
import sqlite3
import multiprocessing
from queue import Empty
from colorama import init, Fore, Style
import csv
import time
import sys
from datetime import datetime
import yara

init(autoreset=True)

# Number of files that are grouped and sent to each worker process
CHUNK_SIZE = 50

# Directores that are skipped during scanning
DEFAULT_EXCLUDES = [
   "Windows\\WinSxS",
   "Windows\\Temp",
   "Windows\\SysWOW64",
   "Windows\\System32\\DriverStore",
   "Windows\\Servicing",
   "ProgramData\\Microsoft\\Windows Defender",
   "ProgramData\\Microsoft\\Windows Defender\\Platform",
   "System Volume Information",
   "Recovery",
   "Windows\\Logs",
   "Windows\\SoftwareDistribution\\Download",
   "Windows\\Prefetch",
   "Program Files\\Common Files\\Microsoft Shared",
   "Windows\\Microsoft.NET\\Framework64",
   "$Recycle.Bin"
]

# Filetypes that are considered for YARA scan mode content
CONTENT_FILETYPES = [".txt", ".csv", ".log", ".doc", ".docx", ".pdf", ".rtf"]

# Arguments
def parse_args():
   parser = argparse.ArgumentParser(description="Backup scanner for known bad files")
   parser.add_argument("--mount", required=True, help="Path to the mounted backup filesystem")
   parser.add_argument("--workers", type=int, default=max(1, multiprocessing.cpu_count() // 2))
   parser.add_argument("--filetypes", help="Comma-separated list of file extensions (e.g. .exe,.dll)")
   parser.add_argument("--maxsize", type=int, help="Maximum file size in MB")
   parser.add_argument("--exclude", help="Comma-separated list of directories to exclude (partial paths)")
   parser.add_argument("--csv", help="Optional: save results to this CSV file")
   parser.add_argument("--verbose", action="store_true", help="Print all scanned files, not just matches")
   parser.add_argument("--logfile", help="Optional: path to logfile for matches")
   parser.add_argument("--yara", choices=["off", "all", "suspicious", "content"], default="off", help="Enable YARA scanning")
   return parser.parse_args()

# Logging function
def log_message(msg, logfile):
   if logfile:
       with open(logfile, "a", encoding="utf-8") as f:
           f.write(f"{datetime.now().isoformat()} {msg}\n")

# Scanner logic - Get files
def get_files(root, filetypes, maxsize, excludes):
   result = []
   normalized_excludes = [ex.lower().replace("/", os.sep).replace("\\", os.sep) for ex in excludes]
   for dirpath, _, files in os.walk(root):
       normalized_dirpath = dirpath.lower().replace("/", os.sep).replace("\\", os.sep)
       if any(ex in normalized_dirpath for ex in normalized_excludes):
           continue
       for name in files:
           path = os.path.join(dirpath, name)
           if filetypes and not any(path.lower().endswith(ft) for ft in filetypes):
               continue
           if maxsize:
               try:
                   if os.path.getsize(path) > maxsize * 1024 * 1024:
                       continue
               except:
                   continue
           result.append(path)
   return result

def sha256_file(path):
   h = hashlib.sha256()
   try:
       with open(path, "rb") as f:
           while chunk := f.read(8192):
               h.update(chunk)
       return h.hexdigest()
   except:
       return None

# Load hash values from database badfiles.db
def load_hashes(db_path="badfiles.db"):
   conn = sqlite3.connect(db_path)
   cur = conn.cursor()
   cur.execute("SELECT sha256, name, standard_path FROM lolbas WHERE sha256 IS NOT NULL")
   badfile_entries = cur.fetchall()
   cur.execute("SELECT sha256, file_name FROM malwarebazaar WHERE sha256 IS NOT NULL")
   malware_entries = cur.fetchall()
   conn.close()
   lolbas_hashes = {sha.lower(): name for sha, name, _ in badfile_entries if sha}
   lolbas_paths = dict((name.lower(), path) for _, name, path in badfile_entries if path)
   malware_hashes = {sha.lower(): name for sha, name in malware_entries if sha}
   return lolbas_hashes, malware_hashes, lolbas_paths

# When mounting Windows file systems to Linux - The old Slash story (not the guitarist)
def normalize(p):
   return os.path.normpath(p).replace("\\", os.sep).lower()

# Get the YARA rules from the yara_rules folder
def compile_yara_rules(path="yara_rules"):
   rules = {}
   for f in os.listdir(path):
       if f.endswith(".yar") or f.endswith(".yara"):
           rules[f] = os.path.join(path, f)
   return yara.compile(filepaths=rules) if rules else None

# Woker function
def worker(chunk_queue, result_queue, stats_queue, lol_hashes, mw_hashes, lol_paths, yara_rules, yara_mode, verbose, logfile):
   while True:
       try:
           chunk = chunk_queue.get(timeout=5)
       except Empty:
           break
       for path in chunk:
           filename = os.path.basename(path)
           lookup_name = filename.lower()
           norm_path = normalize(path)
           file_hash = sha256_file(path)
           suspicious = False

           # LOLBAS check
           if lookup_name in lol_paths:
               expected = normalize(lol_paths[lookup_name])
               try:
                   actual_rel = norm_path.split("windows" + os.sep, 1)[-1]
                   expected_rel = expected.split("windows" + os.sep, 1)[-1]
                   if actual_rel != expected_rel:
                       msg = f"⚠  LOLBAS OUT OF PLACE: {path} (expected {lol_paths[lookup_name]})"
                       print(f"\n{Fore.MAGENTA}{Style.BRIGHT}{msg}")
                       log_message(msg, logfile)
                       result_queue.put((path, None, "lolbas_out_of_place"))
                       stats_queue.put("lolbas")
                       suspicious = True
               except Exception:
                   pass

           # Malware hash match
           if file_hash:
               if file_hash in mw_hashes:
                   msg = f"❌ MATCH (MalwareBazaar): {path} → {mw_hashes[file_hash]}"
                   print(f"\n{Fore.RED}{Style.BRIGHT}{msg}")
                   log_message(msg, logfile)
                   result_queue.put((path, file_hash, mw_hashes[file_hash]))
                   stats_queue.put("hash")
                   suspicious = True
               else:
                   stats_queue.put("clean")
                   if verbose:
                       print(f"\n{Fore.GREEN}✔ CLEAN: {path}")
           else:
               msg = f"⚠️ File not readable: {path}"
               print(f"\n{Fore.YELLOW}{msg}")
               log_message(msg, logfile)
               stats_queue.put("error")

           # YARA matching depending on mode selection. Might be adjusted
           do_yara = yara_rules and (yara_mode in ("all", "content") or (yara_mode == "suspicious" and suspicious))
           if do_yara:
               print(f"{Fore.BLUE}🔬 YARA scan on: {path}")
               try:
                   matches = yara_rules.match(filepath=path)
                   for match in matches:
                       msg = f"❗ YARA MATCH: {path} → {match.rule}"
                       print(f"\n{Fore.BLUE}{Style.BRIGHT}{msg}")
                       log_message(msg, logfile)
                       result_queue.put((path, file_hash, f"YARA: {match.rule}"))
                       stats_queue.put("yara")
               except Exception as e:
                   msg = f"⚠️ YARA scan failed for {path}: {e}"
                   print(f"\n{Fore.YELLOW}{msg}")
                   log_message(msg, logfile)
       chunk_queue.task_done()

# Display progress during scan
def monitor(stats_queue, total, stop_flag, result_stats):
   start = time.time()
   while not stop_flag.is_set() or not stats_queue.empty():
       time.sleep(5)
       while not stats_queue.empty():
           s = stats_queue.get()
           result_stats[s] = result_stats.get(s, 0) + 1
       scanned = sum(result_stats.values())
       elapsed = time.time() - start
       rate = scanned / elapsed * 60 if elapsed else 0
       remaining = total - scanned
       eta = remaining / (scanned / elapsed) if scanned and elapsed else 0
       percent = (scanned / total) * 100 if total else 0
       sys.stdout.write(
           f"\r⏱️ Scanned: {scanned}/{total} "
           f"| Hash Matches: {result_stats.get('hash', 0)} "
           f"| LOLBAS Out: {result_stats.get('lolbas', 0)} "
           f"| YARA Matches: {result_stats.get('yara', 0)} "
           f"| Errors: {result_stats.get('error', 0)} "
           f"({percent:.1f}%) → {rate:,.0f} files/min | ETA: {time.strftime('%H:%M:%S', time.gmtime(round(eta)))}"
       )
       sys.stdout.flush()
   print()

# The magic happens here
def main():
   # Print arguments
   args = parse_args()
   print(f"{Fore.CYAN}🔍 Scanning: {args.mount}")
   print(f"{Fore.CYAN}⚙️ Workers: {args.workers}")
   if args.logfile:
       print(f"{Fore.CYAN}📝 Logging to: {args.logfile}")
   if args.yara != "off":
       print(f"{Fore.CYAN}🔬 YARA mode: {args.yara}")

   # Prepare YARA Scan
   if args.yara == "content":
       filetypes = CONTENT_FILETYPES
   else:
       filetypes = args.filetypes.split(",") if args.filetypes else None

   # Creating file and path list
   excludes  = args.exclude.split(",") if args.exclude else DEFAULT_EXCLUDES
   all_files = get_files(args.mount, filetypes, args.maxsize, excludes)
   total     = len(all_files)

   if total == 0:
       print(f"{Fore.YELLOW}⚠ No files found to scan. Check filters or exclusions.")
       return

   # Worker Queue Configuration
   chunk_queue  = multiprocessing.JoinableQueue()
   result_queue = multiprocessing.Queue()
   stats_queue  = multiprocessing.Queue()
   result_stats = multiprocessing.Manager().dict()

   # Split the found files in chunk groups and add them to the Worker queue
   for i in range(0, total, CHUNK_SIZE):
       chunk_queue.put(all_files[i:i + CHUNK_SIZE])

   # Load HASH sets
   lol_hashes, mw_hashes, lol_paths = load_hashes()
   # Compile the YARA rules
   yara_rules = compile_yara_rules() if args.yara != "off" else None

   # Event to signal when scanning must stop
   stop_flag    = multiprocessing.Event()

   # Start the monitoring
   monitor_proc = multiprocessing.Process(target=monitor, args=(stats_queue, total, stop_flag, result_stats))
   monitor_proc.start()

   # Create and start the worker process(es)
   workers = []
   for _ in range(args.workers):
       p = multiprocessing.Process(
           target=worker,
           args=(chunk_queue, result_queue, stats_queue,
                 lol_hashes, mw_hashes, lol_paths,
                 yara_rules, args.yara, args.verbose, args.logfile)
       )
       p.start()
       workers.append(p)

   # Wait for all chunks beeing processed by the worker(s)
   chunk_queue.join()

   # Set the stop flag
   stop_flag.set()

   monitor_proc.join()

   # Collect the results from the result queue
   results = []
   while not result_queue.empty():
       results.append(result_queue.get())

   # Save results to CSV file if specified. Will only be created if matches are found
   if args.csv and results:
       base, ext = os.path.splitext(args.csv)
       timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
       final_name = f"{base}_{timestamp}{ext}"
       os.makedirs(os.path.dirname(final_name), exist_ok=True)
       with open(final_name, "w", newline="", encoding="utf-8") as f:
           writer = csv.writer(f)
           writer.writerow(["Path", "SHA256", "Detected as"])
           writer.writerows(results)
       print(f"{Fore.YELLOW}💾 Results saved to: {final_name}")

   # Print scan summary
   print(f"\n{Fore.GREEN}{Style.BRIGHT}✅ Scan complete.")
   print(f"{Style.BRIGHT}- Files scanned:       {total}")
   print(f"{Style.BRIGHT}- Malware matches:     {result_stats.get('hash', 0)}")
   print(f"{Style.BRIGHT}- LOLBAS out of place: {result_stats.get('lolbas', 0)}")
   print(f"{Style.BRIGHT}- YARA matches:        {result_stats.get('yara', 0)}")
   print(f"{Style.BRIGHT}- Read errors:         {result_stats.get('error', 0)}")
   print(f"{Style.BRIGHT}- Clean files:         {result_stats.get('clean', 0)}")

if __name__ == "__main__":
   main()

