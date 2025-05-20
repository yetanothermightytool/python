#!/usr/bin/env python3
import sqlite3
import csv
import os
DB_PATH = "badfiles.db"
CSV_FILE = "lolbin_hashes.csv"

def init_db():
   conn = sqlite3.connect(DB_PATH)
   cur = conn.cursor()
   cur.execute("""
       CREATE TABLE IF NOT EXISTS lolbas (
           id INTEGER PRIMARY KEY,
           name TEXT COLLATE NOCASE,
           standard_path TEXT COLLATE NOCASE,
           description TEXT,
           usecase TEXT,
           mitre_id TEXT,
           sha256 TEXT
       );
   """)
   conn.commit()
   return conn

def import_csv(cur):
   if not os.path.exists(CSV_FILE):
       print(f"[!] CSV file '{CSV_FILE}' not found.")
       return
   with open(CSV_FILE, newline='', encoding='utf-8') as f:
       reader = csv.DictReader(f)
       for row in reader:
           name = row.get("Name", "").strip()
           path = row.get("Path", "").strip()
           sha256 = row.get("SHA256", "").strip()
           description = row.get("Description", "").strip()
           usecase = row.get("Usecase", "").strip()
           mitre = row.get("MitreID", "").strip()
           if not name or not path:
               continue
           cur.execute("SELECT id FROM lolbas WHERE LOWER(name) = ?", (name.lower(),))
           existing = cur.fetchone()
           if existing:
               print(f"[SKIP] {name} already in database.")
               continue
           cur.execute("""
               INSERT INTO lolbas (name, standard_path, description, usecase, mitre_id, sha256)
               VALUES (?, ?, ?, ?, ?, ?)
           """, (name, path, description, usecase, mitre, sha256))
           print(f"[ADD] {name} imported.")

def main():
   print("[*] Initializing database...")
   conn = init_db()
   cur = conn.cursor()
   import_csv(cur)
   conn.commit()
   conn.close()
   print("[+] Done.")
if __name__ == "__main__":
   main()
