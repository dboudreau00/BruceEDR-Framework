# Offline geo assets

These three files back the **Network map** view. They are generated, not hand-edited, and
regenerated with `tools/build-geo.py`.

| File | What it is | Size |
|---|---|---|
| `ipv4-country.bin` | 65 536 × `uint16` (little-endian), one country index per IPv4 `/16` | 128 KB |
| `countries.csv` | `index,iso2,name,lat,lon` — the index space `ipv4-country.bin` refers to | 6 KB |
| `world.txt` | Simplified landmass outlines, `ISO|lon,lat lon,lat …`, one ring per line | 55 KB |

## Sources and licensing

- **IP → country**: the five RIR *delegated statistics* files (ARIN, RIPE NCC, APNIC,
  LACNIC, AFRINIC). These are published by the registries as public statistics and are
  freely redistributable.
- **Country label points and outlines**: [Natural Earth](https://www.naturalearthdata.com/)
  110m admin-0, which is in the **public domain** (CC0).

Neither source imposes an attribution requirement, but both are credited here because a
security tool should be able to say where its data came from.

## What this is *not*

**This is allocation geography, not packet geography.** The table says which country an
address block was *allocated to*, per the RIRs. It does not say where the machine at the
other end actually is. In particular:

- **CDNs and anycast** (Cloudflare, Akamai, Google, Fastly) will land on the wrong
  continent, because one advertised block serves the whole world.
- **VPS and hosting resellers** inherit their upstream's registration country.
- **Resolution is `/16`.** A small allocation sitting inside a larger block of a different
  country shows the larger block's country.
- **IPv6 is not mapped at all.** Those endpoints are reported as unplaced rather than
  guessed at.

Treat a marker as *"this block is registered in X"*, never as *"the attacker is in X"*.
Attribution by IP geography alone is not sound, and the map is a triage aid, not evidence.

## Why it is offline

An EDR agent must never ask a third-party geo-IP service where an address is. Doing so
would tell that service — in real time — exactly which infrastructure a defender is
investigating. That is a far worse problem than an occasionally misplaced dot, so the
lookup is a local table and **ProcessShield makes no network call to build this view**.

## Regenerating

```bash
python tools/build-geo.py intel/geo
```

The script downloads the RIR files and the Natural Earth GeoJSON, then rewrites all three
outputs. Allocation data drifts slowly; refreshing once or twice a year is plenty.
