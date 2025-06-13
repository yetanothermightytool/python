#!/usr/bin/env python3
import sqlite3
import os
from textwrap import shorten
from tabulate import tabulate
from colorama import Fore, Style, init

init(autoreset=True)

def human_readable_size(size_bytes):
   for unit in ['B','KB','MB','GB','TB']:
       if abs(size_bytes) < 1024.0:
           return f"{size_bytes:3.1f} {unit}"
       size_bytes /= 1024.0
   return f"{size_bytes:.1f} PB"

def shorten_hash(hash_str, length=12):
   return hash_str[:length] + "…" if len(hash_str) > length else hash_str

def run_analysis():
   db_path = "file_index.db"
   bad_db_path = "badfiles.db"

   if not os.path.exists(db_path):
       print(f"{Fore.RED}❌ Error: file_index.db not found.")
       return
   if not os.path.exists(bad_db_path):
       print(f"{Fore.RED}❌ Error: badfiles.db not found.")
       return

   conn = sqlite3.connect(db_path)
   conn.row_factory = sqlite3.Row
   cursor = conn.cursor()

   try:
       cursor.execute(f"ATTACH DATABASE '{bad_db_path}' AS badfiles")
   except Exception as e:
       print(f"{Fore.RED}❌ Failed to attach badfiles.db: {e}")
       return

   queries = {
       "malware_matches": {
           "desc": "🦠 Malware matches found in file_index.db",
           "sql": """
               SELECT hostname, path, filename, sha256, rp_timestamp
               FROM files
               WHERE sha256 IN (SELECT sha256 FROM badfiles.malwarebazaar)
           """
       },
       "suspicious_locations": {
           "desc": "📁 Suspicious executables in user directories (e.g. AppData)",
           "sql": """
               SELECT hostname, filename, path
               FROM files
               WHERE LOWER(path) LIKE '%appdata%' AND filename LIKE '%.exe'
           """
       },
       "large_executables": {
           "desc": "💣 Executables larger than 50MB",
           "sql": """
               SELECT hostname, filename, path, size
               FROM files
               WHERE filename LIKE '%.exe' AND size > 52428800
           """
       },
       "hash_changed": {
           "desc": "🧬 Same file (host+name), but different content (hash)",
           "sql": """
               SELECT
                   f1.hostname,
                   f1.filename,
                   f1.sha256 AS old_hash,
                   f2.sha256 AS new_hash,
                   f1.rp_timestamp AS old_rp_date,
                   f2.rp_timestamp AS new_rp_date
               FROM files f1
               JOIN files f2
                 ON f1.hostname = f2.hostname
                AND f1.filename = f2.filename
                AND f1.sha256 != f2.sha256
               WHERE f1.rp_timestamp < f2.rp_timestamp
           """
       },
       "size_changed": {
           "desc": "📏 Same file (host+name), but different size",
           "sql": """
               SELECT
                   f1.hostname,
                   f1.filename,
                   f1.size AS old_size,
                   f2.size AS new_size,
                   f1.rp_timestamp AS old_rp_date,
                   f2.rp_timestamp AS new_rp_date
               FROM files f1
               JOIN files f2
                 ON f1.hostname = f2.hostname
                AND f1.filename = f2.filename
                AND f1.size != f2.size
               WHERE f1.rp_timestamp < f2.rp_timestamp
           """
       }
   }

   for key, q in queries.items():
       print(f"\n{Fore.BLUE}{Style.BRIGHT}{q['desc']}")
       try:
           cursor.execute(q["sql"])
           rows = cursor.fetchall()
           if not rows:
               print(f"{Fore.GREEN}✔ No suspicious items found in this category.")
               continue

           formatted = []
           for row in rows:
               r = dict(row)
               if 'size' in r:
                   r['size'] = human_readable_size(r['size'])
               if 'old_size' in r:
                   r['old_size'] = human_readable_size(r['old_size'])
               if 'new_size' in r:
                   r['new_size'] = human_readable_size(r['new_size'])
               if 'path' in r:
                   original_path = r['path']
                   if original_path.startswith("/tmp/Veeam.Mount.FS."):
                       parts = original_path.split(os.sep)
                       r['path'] = "..." + os.sep + os.sep.join(parts[4:]) if len(parts) > 4 else original_path
                   elif original_path.startswith("/mnt/"):
                       parts = original_path.split(os.sep)
                       r['path'] = "..." + os.sep + os.sep.join(parts[-3:]) if len(parts) > 3 else original_path
                   else:
                       parts = original_path.split(os.sep)
                       r['path'] = "..." + os.sep + os.sep.join(parts[-3:]) if len(parts) > 3 else original_path
               if 'sha256' in r:
                   r['sha256'] = shorten_hash(r['sha256'])
               if 'old_hash' in r:
                   r['old_hash'] = shorten_hash(r['old_hash'])
               if 'new_hash' in r:
                   r['new_hash'] = shorten_hash(r['new_hash'])
               if 'Hash' in r:
                   r['Hash'] = shorten_hash(r['Hash'])
               if 'Hosts' in r and isinstance(r['Hosts'], str):
                   r['Hosts'] = r['Hosts'].replace(",", ", ")
               formatted.append(r)

           print(tabulate(formatted, headers="keys", tablefmt="fancy_grid"))
           print(f"{Fore.YELLOW}{len(formatted)} entries found.")
       except Exception as e:
           print(f"{Fore.RED}⚠️ Error running query: {e}")

   conn.close()

if __name__ == "__main__":
   run_analysis()
