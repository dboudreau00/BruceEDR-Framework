"""Regenerates BruceEDR's offline geo assets for the Network map view.

    python tools/build-geo.py intel/geo

Downloads the five RIR delegated-statistics files (public statistics, freely
redistributable) and Natural Earth 110m admin-0 (public domain / CC0), then writes:

    ipv4-country.bin   65536 x uint16 little-endian, one country index per /16
    countries.csv      index,iso2,name,lat,lon
    world.txt          simplified equirectangular outlines, one ring per line

Requires network access; nothing else in BruceEDR does. See intel/geo/README.md for
what this data can and cannot be trusted to say.
"""
import collections, json, os, struct, sys, urllib.request

OUT = sys.argv[1] if len(sys.argv) > 1 else "intel/geo"
CACHE = os.path.join(OUT, ".cache")

RIR = {
    "arin":    "https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest",
    "ripencc": "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-latest",
    "apnic":   "https://ftp.apnic.net/stats/apnic/delegated-apnic-latest",
    "lacnic":  "https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-latest",
    "afrinic": "https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-latest",
}
NE = ("https://raw.githubusercontent.com/nvkelso/natural-earth-vector/master/"
      "geojson/ne_110m_admin_0_countries.geojson")


def fetch(url, path):
    """Download once and cache, so a re-run does not re-pull ~25 MB."""
    if os.path.exists(path) and os.path.getsize(path) > 0:
        print(f"  cached  {os.path.basename(path)}")
        return
    print(f"  fetch   {url}")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with urllib.request.urlopen(url, timeout=180) as r, open(path, "wb") as fh:
        fh.write(r.read())


print("downloading sources")
fetch(NE, os.path.join(CACHE, "ne110.json"))
for name, url in RIR.items():
    fetch(url, os.path.join(CACHE, f"{name}.txt"))
print("building")

# ---------------------------------------------------------------- country table
feat = json.load(open(os.path.join(CACHE, "ne110.json"), encoding="utf-8"))["features"]
meta = {}          # iso2 -> (name, lat, lon)
rings = []         # (iso2, [(lon,lat), ...])

for f in feat:
    p = f["properties"]
    iso = (p.get("ISO_A2_EH") or p.get("ISO_A2") or "").strip().upper()
    if len(iso) != 2 or not iso.isalpha():
        iso = ""
    name = p.get("NAME") or iso
    if iso and iso not in meta:
        meta[iso] = (name, float(p["LABEL_Y"]), float(p["LABEL_X"]))

    g = f["geometry"]
    polys = g["coordinates"] if g["type"] == "MultiPolygon" else [g["coordinates"]]
    for poly in polys:
        for ring in poly:                       # outer ring + holes; draw all as outlines
            rings.append((iso, [(float(x), float(y)) for x, y in ring]))

# ---------------------------------------------------------------- ip -> country
blocks = collections.defaultdict(collections.Counter)
for path in [os.path.join(CACHE, f"{n}.txt") for n in RIR]:
    for line in open(path, encoding="utf-8", errors="replace"):
        if line.startswith("#") or "|" not in line:
            continue
        p = line.rstrip("\n").split("|")
        if len(p) < 7 or p[2] != "ipv4":
            continue
        cc = p[1].strip().upper()
        if len(cc) != 2 or not cc.isalpha():
            continue
        try:
            a, b, c, d = (int(x) for x in p[3].split("."))
            n = int(p[4])
        except Exception:
            continue
        lo = (a << 24) | (b << 16) | (c << 8) | d
        hi = lo + n - 1
        for blk in range(lo >> 16, (hi >> 16) + 1):
            bs, be = blk << 16, (blk << 16) | 0xFFFF
            blocks[blk][cc] += min(hi, be) - max(lo, bs) + 1

# Only keep countries we can actually place on the map; index 0 means "unknown".
used = {cc for c in blocks.values() for cc in c}
codes = sorted(cc for cc in used if cc in meta)
index = {cc: i + 1 for i, cc in enumerate(codes)}

table = bytearray(65536 * 2)
placed = 0
for blk, counter in blocks.items():
    for cc, _ in counter.most_common():
        if cc in index:
            struct.pack_into("<H", table, blk * 2, index[cc])
            placed += 1
            break
open(f"{OUT}/ipv4-country.bin", "wb").write(bytes(table))

with open(f"{OUT}/countries.csv", "w", encoding="utf-8", newline="\n") as fh:
    fh.write("index,iso2,name,lat,lon\n")
    for cc in codes:
        name, lat, lon = meta[cc]
        fh.write(f'{index[cc]},{cc},"{name}",{lat:.4f},{lon:.4f}\n')

# ---------------------------------------------------------------- world outline
def simplify(pts, tol):
    """Douglas-Peucker, iterative so a long coastline cannot blow the stack."""
    if len(pts) < 3:
        return pts
    keep = [False] * len(pts)
    keep[0] = keep[-1] = True
    stack = [(0, len(pts) - 1)]
    while stack:
        i, j = stack.pop()
        if j <= i + 1:
            continue
        x1, y1 = pts[i]
        x2, y2 = pts[j]
        dx, dy = x2 - x1, y2 - y1
        den = dx * dx + dy * dy
        best, bi = -1.0, -1
        for k in range(i + 1, j):
            px, py = pts[k]
            if den == 0:
                d = (px - x1) ** 2 + (py - y1) ** 2
            else:
                t = ((px - x1) * dx + (py - y1) * dy) / den
                t = 0.0 if t < 0 else (1.0 if t > 1 else t)
                d = (px - (x1 + t * dx)) ** 2 + (py - (y1 + t * dy)) ** 2
            if d > best:
                best, bi = d, k
        if best > tol * tol:
            keep[bi] = True
            stack.append((i, bi))
            stack.append((bi, j))
    return [p for p, k in zip(pts, keep) if k]

lines, kept = [], 0
for iso, ring in rings:
    s = simplify(ring, 0.35)          # ~0.35 degrees: continent shape, no coastal detail
    if len(s) < 3:
        continue
    kept += 1
    coords = " ".join(f"{x:.2f},{y:.2f}" for x, y in s)
    lines.append(f"{iso}|{coords}")
open(f"{OUT}/world.txt", "w", encoding="utf-8", newline="\n").write("\n".join(lines))

print(f"countries placed : {len(codes)}")
print(f"/16 blocks mapped: {placed} of 65536")
print(f"outline rings    : {kept} (from {len(rings)})")
print(f"world.txt        : {sum(len(l) for l in lines) // 1024} KB")
