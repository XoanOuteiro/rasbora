function __snmpr_report --description "render an snmpr walk file as a report, do not call directly"
    # usage: __snmpr_report WALK OUT [PREV]
    #   WALK  numeric snmpwalk/snmpbulkwalk output (-On), walked from .1
    #   OUT   report file to write; the same text goes to stdout
    #   PREV  previous walk of the same community, for the diff section
    #
    # The walk file is the record. This only reads it. Every line of the walk
    # lands in exactly one section of the report, so nothing the agent sent
    # is dropped: known tables are joined into rows, every string value not
    # consumed by a table is listed once in STRINGS, and whatever is left,
    # the counters and integers, goes to OTHER grouped by branch.
    #
    # Python because the joins and the hex decoding are a page of code that
    # would be soup in fish, and it is on every Kali. The script uses only
    # double quotes so it can live inside one fish single-quoted string.
    set -l script '
import sys, re, collections

walk, out = sys.argv[1], sys.argv[2]
prev = sys.argv[3] if len(sys.argv) > 3 else None

LINE = re.compile(r"^(\.[0-9.]+) = (?:([A-Za-z][A-Za-z0-9 -]*): ?)?(.*)$")

def parse(path):
    """oid -> (type, value). Continuation lines (multi-line STRING / Hex-STRING)
    are glued onto the previous value."""
    d = collections.OrderedDict()
    last = None
    try:
        f = open(path, errors="replace")
    except OSError:
        return d
    for raw in f:
        line = raw.rstrip("\n")
        m = LINE.match(line)
        if m:
            oid, typ, val = m.group(1), m.group(2) or "", m.group(3)
            if typ == "" and val == "\"\"":
                typ, val = "STRING", ""
            d[oid] = [typ, val]
            last = oid
        elif last is not None and not line.startswith("End of MIB") and line.strip() != "":
            d[last][1] += "\n" + line
    f.close()
    # quotes come off after gluing, or a multi-line STRING keeps its closing one
    for e in d.values():
        v = e[1]
        if e[0] == "STRING" and len(v) >= 2 and v[0] == "\"" and v[-1] == "\"":
            e[1] = v[1:-1]
    return d

def hexdecode(val):
    """Hex-STRING -> printable text if it is text, else the hex kept as is."""
    hexs = val.replace("\n", " ").split()
    try:
        b = bytes(int(h, 16) for h in hexs)
    except ValueError:
        return val, False
    b = b.rstrip(b"\x00")
    if not b:
        return "", True
    try:
        s = b.decode("utf-8")
    except UnicodeDecodeError:
        try:
            s = b.decode("utf-16-le") if len(b) % 2 == 0 and b[1:2] == b"\x00" else None
        except UnicodeDecodeError:
            s = None
    if s is None:
        return val, False
    printable = sum(1 for c in s if c.isprintable() or c in "\n\t")
    if len(s) and printable / len(s) >= 0.9:
        return s, True
    return val, False

def text(entry):
    """display value for one entry, hex decoded where it was text."""
    typ, val = entry
    if typ == "Hex-STRING":
        s, ok = hexdecode(val)
        return s if ok else "hex: " + val.replace("\n", " ")
    return val

def is_string(entry):
    typ, val = entry
    if typ == "STRING":
        return True
    if typ == "Hex-STRING":
        return hexdecode(val)[1]
    return False

def strindex(idx):
    """nsExtend / UCD string indexes are length.c.c.c -> name"""
    parts = idx.split(".")
    try:
        n = int(parts[0])
        if len(parts) == n + 1:
            return "".join(chr(int(c)) for c in parts[1:])
    except ValueError:
        pass
    return idx

def sub(d, prefix, used):
    """entries under prefix, keyed by the index that follows it. Marks them used."""
    p = prefix if prefix.endswith(".") else prefix + "."
    r = collections.OrderedDict()
    for oid in d:
        if oid.startswith(p):
            r[oid[len(p):]] = d[oid]
            used.add(oid)
    return r

def scalar(d, oid, used):
    if oid in d:
        used.add(oid)
        return text(d[oid])
    return None

def ipport(idx):
    """a.b.c.d.port -> a.b.c.d:port"""
    p = idx.split(".")
    if len(p) >= 5:
        return ".".join(p[:4]) + ":" + p[4]
    return idx

MIB2 = ".1.3.6.1.2.1."
HOST = MIB2 + "25."
ENT  = ".1.3.6.1.4.1."

BRANCH = [
    (MIB2 + "1.",  "system"),       (MIB2 + "2.",  "interfaces"),
    (MIB2 + "3.",  "at"),           (MIB2 + "4.",  "ip"),
    (MIB2 + "5.",  "icmp"),         (MIB2 + "6.",  "tcp"),
    (MIB2 + "7.",  "udp"),          (MIB2 + "11.", "snmp"),
    (MIB2 + "25.", "host"),         (MIB2 + "31.", "ifMIB"),
    (ENT + "2021.", "ucdavis (net-snmp)"),
    (ENT + "8072.", "net-snmp agent"),
    (ENT + "77.",   "lanmanager (windows)"),
    (ENT + "311.",  "microsoft"),
    (MIB2, "mib-2 other"), (ENT, "enterprise other"),
]
def branch(oid):
    for p, name in BRANCH:
        if oid.startswith(p):
            if name.endswith("other"):
                nxt = oid[len(p):].split(".")[0]
                return name + " " + nxt
            return name
    return "outside mib-2/enterprise"

d = parse(walk)
lines = []
def w(s=""):
    lines.append(s)
def hdr(t):
    w(); w("== " + t + " ==")

if not d:
    w("[!] empty walk: " + walk)
    print("\n".join(lines))
    open(out, "w").write("\n".join(lines) + "\n")
    sys.exit(1)

used = set()
w("%d objects in %s" % (len(d), walk))

# ---- system ------------------------------------------------------------
hdr("SYSTEM")
for name, o in (("descr", "1.1.0"), ("name", "1.5.0"), ("contact", "1.4.0"),
                ("location", "1.6.0"), ("uptime", "1.3.0"), ("objectid", "1.2.0")):
    v = scalar(d, MIB2 + o, used)
    if v is not None:
        w("  %-9s %s" % (name, v.replace("\n", " | ")))
dom = scalar(d, ENT + "77.1.4.1.0", used)
if dom is not None:
    w("  %-9s %s" % ("domain", dom))

# ---- windows lanmanager -------------------------------------------------
users  = sub(d, ENT + "77.1.2.25.1.1", used)
if users:
    hdr("WINDOWS USERS  (.77.1.2.25)")
    for v in users.values():
        w("  " + text(v))
sh_n = sub(d, ENT + "77.1.2.27.1.1", used)
sh_p = sub(d, ENT + "77.1.2.27.1.2", used)
sh_c = sub(d, ENT + "77.1.2.27.1.3", used)
if sh_n:
    hdr("WINDOWS SHARES  (.77.1.2.27)")
    for i, v in sh_n.items():
        w("  %-20s %-30s %s" % (text(v), text(sh_p.get(i, ["", ""])), text(sh_c.get(i, ["", ""]))))
svcs = sub(d, ENT + "77.1.2.3.1.1", used)
if svcs:
    hdr("WINDOWS SERVICES  (.77.1.2.3)  %d running" % len(svcs))
    for v in svcs.values():
        w("  " + text(v))

# ---- processes ---------------------------------------------------------
pn = sub(d, HOST + "4.2.1.2", used)
pp = sub(d, HOST + "4.2.1.4", used)
pa = sub(d, HOST + "4.2.1.5", used)
for col in ("4.2.1.1", "4.2.1.3", "4.2.1.6", "4.2.1.7", "5.1.1.1", "5.1.1.2"):
    sub(d, HOST + col, used)      # pid/id/type/status/cpu/mem: noise, consumed
if pn:
    hdr("PROCESSES  (.25.4.2)  %d   name | path | parameters" % len(pn))
    withargs = []
    for pid in sorted(pn, key=lambda x: int(x) if x.isdigit() else 0):
        n, p, a = text(pn[pid]), text(pp.get(pid, ["", ""])), text(pa.get(pid, ["", ""]))
        row = "  %6s  %-22s %-40s %s" % (pid, n, p, a)
        if a.strip():
            withargs.append(row)
        w(row)
    if withargs:
        w()
        w("  -- with parameters, read these first --")
        for r in withargs:
            w(r)

# ---- installed software ------------------------------------------------
inst = sub(d, HOST + "6.3.1.2", used)
for col in ("6.3.1.1", "6.3.1.3", "6.3.1.4", "6.3.1.5", "6.1.0", "6.2.0"):
    sub(d, HOST + col, used)
if inst:
    hdr("INSTALLED SOFTWARE  (.25.6.3)  %d" % len(inst))
    for v in inst.values():
        w("  " + text(v))

# ---- storage -----------------------------------------------------------
st = sub(d, HOST + "2.3.1.3", used)
for col in ("2.3.1.1", "2.3.1.2", "2.3.1.4", "2.3.1.5", "2.3.1.6", "2.3.1.7", "2.2.0"):
    sub(d, HOST + col, used)
dsk = sub(d, ENT + "2021.9.1.2", used)
if st or dsk:
    hdr("STORAGE  (.25.2.3 / ucd .2021.9)")
    for v in st.values():
        w("  " + text(v))
    for v in dsk.values():
        w("  " + text(v) + "   (ucd dskPath)")

# ---- network -----------------------------------------------------------
ifd = sub(d, MIB2 + "2.2.1.2", used)
ips = sub(d, MIB2 + "4.20.1.1", used)
if ifd or ips:
    hdr("NETWORK")
    for i, v in ifd.items():
        w("  if %-3s %s" % (i, text(v)))
    for v in ips.values():
        w("  ip    " + text(v))
tcp = sub(d, MIB2 + "6.13.1.3", used)
udp = sub(d, MIB2 + "7.5.1.2", used)
for col in ("6.13.1.1", "6.13.1.2", "6.13.1.4", "6.13.1.5", "7.5.1.1"):
    sub(d, MIB2 + col, used)
if tcp or udp:
    hdr("SOCKETS  (tcp .6.13 / udp .7.5)")
    listen, estab = [], []
    for idx, v in tcp.items():
        p = idx.split(".")
        local = ipport(idx)
        remote = ipport(".".join(p[5:])) if len(p) >= 10 else ""
        state = v[1].strip()
        if state == "2":
            listen.append(local)
        else:
            estab.append("%s -> %s (state %s)" % (local, remote, state))
    for l in listen:
        w("  tcp LISTEN  " + l)
    for e in estab:
        w("  tcp         " + e)
    for idx in udp:
        w("  udp         " + ipport(idx))

# ---- net-snmp extend ---------------------------------------------------
xc = sub(d, ENT + "8072.1.3.2.2.1.2", used)
xa = sub(d, ENT + "8072.1.3.2.2.1.3", used)
xo = sub(d, ENT + "8072.1.3.2.3.1.2", used)
xl = sub(d, ENT + "8072.1.3.2.4.1.2", used)
for col in ("8072.1.3.2.1.0", "8072.1.3.2.2.1.1", "8072.1.3.2.2.1.4", "8072.1.3.2.2.1.5",
            "8072.1.3.2.2.1.6", "8072.1.3.2.2.1.7", "8072.1.3.2.2.1.20", "8072.1.3.2.2.1.21",
            "8072.1.3.2.3.1.1", "8072.1.3.2.3.1.3", "8072.1.3.2.3.1.4"):
    sub(d, ENT + col, used)
if xc or xo:
    hdr("NET-SNMP EXTEND  (.8072.1.3.2)  scripts wired into snmpd.conf")
    for i in xc:
        name = strindex(i)
        w("  [%s] %s %s" % (name, text(xc[i]), text(xa.get(i, ["", ""]))))
        o = xo.get(i)
        if o is not None:
            for ln in text(o).split("\n"):
                w("      | " + ln)
    w("  (a RW community makes this table remote code execution; test with snmpset)")

# ---- ucd exec ----------------------------------------------------------
en = sub(d, ENT + "2021.8.1.2", used)
ec = sub(d, ENT + "2021.8.1.3", used)
eo = sub(d, ENT + "2021.8.1.101", used)
for col in ("2021.8.1.1", "2021.8.1.100", "2021.8.1.102", "2021.8.1.103"):
    sub(d, ENT + col, used)
if en:
    hdr("UCD EXEC  (.2021.8)")
    for i in en:
        w("  [%s] %s" % (text(en[i]), text(ec.get(i, ["", ""]))))
        o = eo.get(i)
        if o is not None:
            for ln in text(o).split("\n"):
                w("      | " + ln)

# ---- every remaining string, once ---------------------------------------
hdr("STRINGS  every distinct string value not shown above, read all of them")
seen = collections.OrderedDict()
for oid, e in d.items():
    if oid in used or not is_string(e):
        continue
    used.add(oid)
    s = text(e).strip()
    if s == "":
        continue
    seen.setdefault(s, []).append(oid)
if not seen:
    w("  (none)")
for s, oids in sorted(seen.items(), key=lambda kv: kv[1][0]):
    tag = "%s%s" % (oids[0], "" if len(oids) == 1 else " (+%d)" % (len(oids) - 1))
    first = True
    for ln in s.split("\n"):
        w("  %-45s %s" % (tag if first else "", ln))
        first = False

# ---- the rest: counters, integers, oids, addresses ----------------------
rest = collections.OrderedDict()
for oid, e in d.items():
    if oid in used:
        continue
    rest.setdefault(branch(oid), []).append((oid, e))
hdr("OTHER  non-string objects by branch (%d)" % sum(len(v) for v in rest.values()))
for b, items in rest.items():
    w("  %-28s %d" % (b, len(items)))
w()
w("snmptranslate -m ALL -Of OID   names any numeric OID above")

report = "\n".join(lines)
print(report)

# ---- full dump of OTHER goes to the file only ---------------------------
full = [report, "", "== OTHER, every object =="]
for b, items in rest.items():
    full.append("  -- " + b + " --")
    for oid, e in items:
        full.append("  %s = %s: %s" % (oid, e[0], e[1].replace("\n", " ")))
open(out, "w").write("\n".join(full) + "\n")

# ---- diff against the previous walk -------------------------------------
if prev:
    p = parse(prev)
    if p:
        VOLATILE = ("Counter32", "Counter64", "Gauge32", "Timeticks")
        added   = [o for o in d if o not in p]
        removed = [o for o in p if o not in d]
        changed = [o for o in d if o in p and d[o][0] not in VOLATILE
                   and o != MIB2 + "1.3.0" and d[o][1] != p[o][1]]
        dl = []
        dl.append("== DIFF vs %s ==" % prev)
        dl.append("  +%d new  -%d gone  ~%d changed  (counters, gauges, uptime ignored)"
                  % (len(added), len(removed), len(changed)))
        for o in added:
            dl.append("  + %s = %s" % (o, text(d[o]).replace("\n", " ")))
        for o in removed:
            dl.append("  - %s = %s" % (o, text(p[o]).replace("\n", " ")))
        for o in changed:
            dl.append("  ~ %s" % o)
            dl.append("      was %s" % text(p[o]).replace("\n", " "))
            dl.append("      now %s" % text(d[o]).replace("\n", " "))
        dtxt = "\n".join(dl)
        print()
        print(dtxt)
        dpath = out.replace("report-", "diff-") if "report-" in out else out + ".diff"
        open(dpath, "w").write(dtxt + "\n")
        print("  -> " + dpath)
'
    python3 -c "$script" $argv
end
