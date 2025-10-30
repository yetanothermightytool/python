#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, pathlib, re, sys
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    from stix2 import MemoryStore, Filter
except Exception:
    print("ERROR: please install 'stix2' (pip install stix2)", file=sys.stderr)
    raise

BUNDLE_FILE = pathlib.Path("/home/analyst/stix/attack-stix-data/enterprise-attack/enterprise-attack.json")

ALLOWED_OS = {"Windows","Linux","macOS"}
DET_RE = re.compile(r"/detectionstrategies/(DET\d+)", re.IGNORECASE)

# Common helpers
def load_store(p: pathlib.Path) -> MemoryStore:
    data = json.loads(p.read_text(encoding="utf-8"))
    objs = data["objects"] if isinstance(data, dict) and "objects" in data else data
    if not isinstance(objs, list):
        raise ValueError("Unexpected bundle structure")
    return MemoryStore(stix_data=objs, allow_custom=True)

def adversaries_sentence(text: Optional[str]) -> str:
    if not text:
        return ""
    flat = " ".join(text.split())
    for part in [p.strip() for p in flat.split(".") if p.strip()]:
        if part.startswith("Adversaries may") or part.startswith("Adversaries might"):
            return part + "."
    return ""

def parse_os_list(raw: Optional[str]) -> Optional[Set[str]]:
    if not raw:
        return None
    sel = {p.strip() for p in raw.split(",") if p.strip()}
    sel = {p for p in sel if p in ALLOWED_OS}
    return sel or None

def external_id_of(obj: Dict[str, Any]) -> Optional[str]:
    for r in obj.get("external_references", []) or []:
        eid = r.get("external_id")
        if eid:
            return eid
    return None

def det_id_from_analytic(a: Dict[str, Any]) -> Optional[str]:
    for r in a.get("external_references", []) or []:
        url = r.get("url")
        if not url:
            continue
        m = DET_RE.search(url)
        if m:
            return m.group(1).upper()
    return None

# Technique -> Strategies -> Analytics
def find_tech(store: MemoryStore, tech_external_id: str) -> Optional[Dict[str, Any]]:
    res = store.query([
        Filter("type","=","attack-pattern"),
        Filter("external_references.external_id","=",tech_external_id)
    ])
    return res[0] if res else None

def groups_using(store: MemoryStore, tech_id: str) -> List[str]:
    rels = store.query([
        Filter("type","=","relationship"),
        Filter("relationship_type","=","uses"),
        Filter("target_ref","=",tech_id)
    ])
    g_ids = {r.get("source_ref") for r in rels if r.get("source_ref")}
    if not g_ids:
        return []
    groups = store.query([Filter("type","=","intrusion-set")])
    names = [g.get("name", g.get("id")) for g in groups if g.get("id") in g_ids]
    return sorted(set(names))

def strategy_ids_via_detects(store: MemoryStore, tech_id: str) -> Set[str]:
    rels = store.query([
        Filter("type","=","relationship"),
        Filter("relationship_type","=","detects"),
        Filter("target_ref","=",tech_id)
    ])
    return {r.get("source_ref") for r in rels if r.get("source_ref")}

def strategies_by_ids(store: MemoryStore, ids: Set[str]) -> List[Dict[str, Any]]:
    if not ids:
        return []
    all_strats = store.query([Filter("type","=","x-mitre-detection-strategy")])
    return [s for s in all_strats if s.get("id") in ids]

def strategies_name_contains_tech(store: MemoryStore, tech_external_id: str) -> List[Dict[str, Any]]:
    strats = store.query([Filter("type","=","x-mitre-detection-strategy")])
    return [s for s in strats if tech_external_id in (s.get("name",""))]

def analytics_from_strategy_refs(store: MemoryStore, strat: Dict[str, Any]) -> List[Dict[str, Any]]:
    for k in ("x_mitre_analytic_refs","x-mitre-analytic-refs","x_mitre_analytics_refs","x-mitre-analytics-refs"):
        v = strat.get(k)
        if isinstance(v, list) and all(isinstance(x, str) for x in v):
            refs = set(v); break
    else:
        return []
    all_analytics = store.query([Filter("type","=","x-mitre-analytic")])
    return [a for a in all_analytics if a.get("id") in refs]

def filter_analytics_by_os(objs: List[Dict[str, Any]], os_sel: Optional[Set[str]]) -> List[Dict[str, Any]]:
    if os_sel is None:
        return objs
    out = []
    for a in objs:
        plats = set(a.get("x_mitre_platforms") or a.get("x-mitre-platforms") or [])
        if plats & os_sel:
            out.append(a)
    return out

def short(txt: str, limit: int = 400) -> str:
    if not txt:
        return ""
    flat = " ".join(txt.split())
    return flat if len(flat) <= limit else flat[:limit] + " ...[truncated]"

# Quick keyword search
def text_fields(obj: Dict[str, Any]) -> str:
    """Build a simple searchable text from common fields."""
    parts = [obj.get("type",""), obj.get("name",""), obj.get("description","")]
    # include external refs textual bits
    for r in obj.get("external_references", []) or []:
        parts.append(r.get("source_name","") or "")
        parts.append(r.get("url","") or "")
        parts.append(r.get("external_id","") or "")
    # include platforms for analytics/techniques
    plats = obj.get("x_mitre_platforms") or obj.get("x-mitre-platforms") or []
    if plats:
        parts.append(" ".join(plats))
    return " ".join([p for p in parts if p]).lower()

def score_match(q_tokens: List[str], text: str, name: str) -> int:
    """Very small heuristic scorer: name hits weigh more."""
    score = 0
    for t in q_tokens:
        if t in name:
            score += 3
        if t in text:
            score += 1
    return score

def simple_search(store: MemoryStore, q: str, os_sel: Optional[Set[str]]=None, max_hits: int=15) -> List[Tuple[int, Dict[str, Any]]]:
    """AND-match all tokens across Techniques, Strategies, Analytics; return list of (score, obj)."""
    q_tokens = [t.lower() for t in q.split() if t.strip()]
    if not q_tokens:
        return []

    pool = []
    pool.extend(store.query([Filter("type","=","attack-pattern")]))
    pool.extend(store.query([Filter("type","=","x-mitre-detection-strategy")]))
    pool.extend(store.query([Filter("type","=","x-mitre-analytic")]))

    hits = []
    for obj in pool:
        # OS filter only applies to analytics, others unaffected
        if obj.get("type") == "x-mitre-analytic" and os_sel is not None:
            plats = set(obj.get("x_mitre_platforms") or obj.get("x-mitre-platforms") or [])
            if not (plats & os_sel):
                continue
        name_l = (obj.get("name","") or "").lower()
        text = text_fields(obj)
        if all((t in text) for t in q_tokens):
            sc = score_match(q_tokens, text, name_l)
            hits.append((sc, obj))

    # sort by score desc, then name
    hits.sort(key=lambda x: (-x[0], (x[1].get("name","") or "")))
    return hits[:max_hits]

# Group overview
def find_group(store: MemoryStore, name_or_alias: str) -> Optional[Dict[str, Any]]:
    """Find intrusion-set by exact name or alias (case-insensitive)."""
    target = name_or_alias.lower()
    groups = store.query([Filter("type","=","intrusion-set")])
    for g in groups:
        if (g.get("name","") or "").lower() == target:
            return g
        # aliases may be stored under 'aliases' or 'x_mitre_aliases'
        for key in ("aliases","x_mitre_aliases","x-mitre-aliases"):
            for alias in g.get(key, []) or []:
                if isinstance(alias, str) and alias.lower() == target:
                    return g
    return None

def group_uses_techniques(store: MemoryStore, group_id: str) -> List[Dict[str, Any]]:
    """Return attack-patterns used by the intrusion-set (via relationships)."""
    rels = store.query([
        Filter("type","=","relationship"),
        Filter("relationship_type","=","uses"),
        Filter("source_ref","=",group_id)
    ])
    t_ids = {r.get("target_ref") for r in rels if r.get("target_ref")}
    if not t_ids:
        return []
    techs = store.query([Filter("type","=","attack-pattern")])
    out = [t for t in techs if t.get("id") in t_ids]
    # sort by external_id then name
    def t_id(t):
        for r in t.get("external_references",[]) or []:
            if r.get("external_id","").startswith("T"):
                return r["external_id"]
        return ""
    return sorted(out, key=lambda x: (t_id(x), x.get("name","")))

# CLI runner
def main() -> int:
    ap = argparse.ArgumentParser(description="ATT&CK offline query (search, group overview, technique details)")
    ap.add_argument("-t","--technique", default=None, help="Technique external_id, e.g. T1518.002")
    ap.add_argument("-o","--os", default=None, help="Optional OS filter: Windows,Linux,macOS (enables analytic detail output)")
    ap.add_argument("--q", default=None, help='Keyword query, e.g. "Backup Software"')
    ap.add_argument("-g","--group", default=None, help='Group name or alias, e.g. "APT38"')
    args = ap.parse_args()

    store = load_store(BUNDLE_FILE)
    os_sel = parse_os_list(args.os)

    # Mode 1 Group overview
    if args.group:
        grp = find_group(store, args.group)
        if not grp:
            print(f"[!] Group not found: {args.group}")
            return 4
        gname = grp.get("name", args.group)
        print(f"Group: {gname}")
        techs = group_uses_techniques(store, grp["id"])
        print(f"Techniques used: {len(techs)}")
        for t in techs:
            ext = next((r.get("external_id") for r in t.get("external_references",[]) or [] if r.get("external_id","").startswith("T")), "")
            print(f" - {ext + ' ' if ext else ''}{t.get('name','')}")
        print("\nTip: pass one of the T-IDs with -t to see detection strategies and analytics.")
        return 0

    # Mode 2 Keyword search
    if args.q:
        hits = simple_search(store, args.q, os_sel=os_sel, max_hits=20)
        if not hits:
            print("No results.")
            return 0
        print(f"Results for query: {args.q}  (top {len(hits)})")
        for sc, obj in hits:
            typ = obj.get("type","")
            name = obj.get("name","")
            eid = external_id_of(obj) or ""
            # tiny snippet: show first matching sentence from description if present
            desc = obj.get("description","") or ""
            snip = adversaries_sentence(desc) or (" ".join(desc.split())[:180] + "..." if desc else "")
            tag_os = ""
            if typ == "x-mitre-analytic":
                plats = obj.get("x_mitre_platforms") or obj.get("x-mitre-platforms") or []
                if plats: tag_os = f"  [OS: {', '.join(plats)}]"
            print(f"- ({typ}) {eid + ' ' if eid else ''}{name}{tag_os}  [score {sc}]")
            if snip:
                print(f"    {snip}")
        print("\nTip: use -t <T-ID> to drill down into detection strategies and analytics.")
        return 0

    # Mode 3 Technique details
    if not args.technique:
        print("Nothing to do. Provide one of: --q, --group, or --technique.")
        return 0

    tech = find_tech(store, args.technique)
    if not tech:
        print(f"[!] Technique {args.technique} not found")
        return 3

    tech_id = tech["id"]
    tech_name = tech.get("name", args.technique)

    print(f"Technique: {tech_name} ({args.technique})")
    print(f"Description: {adversaries_sentence(tech.get('description','')) or '<none>'}\n")

    gs = groups_using(store, tech_id)
    print(f"Groups using {args.technique}: {len(gs)}")
    for n in gs:
        print(" -", n)
    print()

    strat_ids = strategy_ids_via_detects(store, tech_id)
    strategies = strategies_by_ids(store, strat_ids)
    if not strategies:
        strategies = strategies_name_contains_tech(store, args.technique)

    printed_header = False
    for strat in sorted(strategies, key=lambda s: s.get("name","")):
        det_id = None
        for r in strat.get("external_references", []) or []:
            eid = r.get("external_id")
            if isinstance(eid, str) and eid.upper().startswith("DET"):
                det_id = eid.upper(); break
        strat_name = strat.get("name", det_id or strat.get("id","<strategy>"))
        analytics = analytics_from_strategy_refs(store, strat)
        analytics = filter_analytics_by_os(analytics, os_sel)
        if not analytics:
            continue

        if not printed_header:
            print(f"Analytics detecting {args.technique}:")
            printed_header = True

        if det_id:
            print(f"\nDetection Strategy: {strat_name} ({det_id})")
        else:
            print(f"\nDetection Strategy: {strat_name}")

        analytics_sorted = sorted(analytics, key=lambda a: (external_id_of(a) or "", a.get("name","")))
        for a in analytics_sorted:
            an_id = external_id_of(a) or ""
            an_name = a.get("name", a.get("id"))
            print(f" - {an_id + ' ' if an_id else ''}{an_name}")
            # If OS filter provided, print extra analytic details
            if os_sel is not None:
                adesc = short(a.get("description",""))
                if adesc:
                    print(f"    description: {adesc}")
                logs = a.get("x_mitre_log_source_references") or a.get("x-mitre-log-source-references") or []
                if isinstance(logs, list) and logs:
                    print("    log_sources:")
                    for l in logs:
                        name = l.get("name"); chan = l.get("channel")
                        parts = []
                        if name: parts.append(name)
                        if chan: parts.append(f"channel={chan}")
                        print("      - " + ", ".join(parts) if parts else "      - <unknown>")
                muts = a.get("x_mitre_mutable_elements") or a.get("x-mitre-mutable-elements") or []
                if isinstance(muts, list) and muts:
                    print("    tunables:")
                    for m in muts:
                        fld = m.get("field"); dsc = m.get("description")
                        if fld and dsc: print(f"      - {fld}: {dsc}")
                        elif fld:      print(f"      - {fld}")
                        elif dsc:      print(f"      - {dsc}")

    if not printed_header:
        print(f"Analytics detecting {args.technique}: 0")

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
