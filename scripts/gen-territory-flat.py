#!/usr/bin/env python3
"""
Generate a flat territory.glb for the Oxley Golden Triangle territory.
Uses only Python stdlib — no numpy, Pillow, or network access required.

Elevation is approximated as 0 (sea level). SE Texas is mostly 0-30 m so
a flat mesh is a credible stand-in until the full Mapzen bake is done.

Usage:
  python3 scripts/gen-territory-flat.py
"""
import json, math, struct, zlib
from pathlib import Path

# ─── Region (Liberty → Orange, south to Kirbyville) ───────────────────────
LAT_MIN, LAT_MAX = 30.00, 30.70
LNG_MIN, LNG_MAX = -94.80, -93.70
CENTER_LAT = (LAT_MIN + LAT_MAX) / 2
CENTER_LNG = (LNG_MIN + LNG_MAX) / 2
MESH_W = 128   # columns (E-W)
MESH_H = 96    # rows    (N-S)

OUT_GLB = Path(__file__).resolve().parent.parent / "public" / "territory.glb"
OUT_GLB.parent.mkdir(parents=True, exist_ok=True)

# ─── WGS-84 ───────────────────────────────────────────────────────────────
_A  = 6378137.0
_E2 = 6.69437999014e-3

def latlng_to_ecef(lat, lng, h=0.0):
    lr, nr = math.radians(lat), math.radians(lng)
    s, c = math.sin(lr), math.cos(lr)
    n = _A / math.sqrt(1.0 - _E2 * s * s)
    return ((n+h)*c*math.cos(nr), (n+h)*c*math.sin(nr), (n*(1-_E2)+h)*s)

def _enu_inv(lat, lng):
    """ENU^-1 = ENU^T  →  rows are [east, up, -north]."""
    lr, nr = math.radians(lat), math.radians(lng)
    sl, cl = math.sin(lr), math.cos(lr)
    sn, cn = math.sin(nr), math.cos(nr)
    return ((-sn, cn, 0.0), (cl*cn, cl*sn, sl), (sl*cn, sl*sn, -cl))

_CE = latlng_to_ecef(CENTER_LAT, CENTER_LNG)
_EI = _enu_inv(CENTER_LAT, CENTER_LNG)

def ecef_to_local(e):
    d = (e[0]-_CE[0], e[1]-_CE[1], e[2]-_CE[2])
    return (
        _EI[0][0]*d[0]+_EI[0][1]*d[1]+_EI[0][2]*d[2],
        _EI[1][0]*d[0]+_EI[1][1]*d[1]+_EI[1][2]*d[2],
        _EI[2][0]*d[0]+_EI[2][1]*d[1]+_EI[2][2]*d[2],
    )

# ─── Mesh ─────────────────────────────────────────────────────────────────
def build_mesh():
    verts, uvs = [], []
    for r in range(MESH_H):
        lat = LAT_MAX - (LAT_MAX - LAT_MIN) * r / (MESH_H - 1)
        for c in range(MESH_W):
            lng = LNG_MIN + (LNG_MAX - LNG_MIN) * c / (MESH_W - 1)
            lx, ly, lz = ecef_to_local(latlng_to_ecef(lat, lng, 0.0))
            verts += [lx, ly, lz]
            uvs   += [c / (MESH_W - 1), 1.0 - r / (MESH_H - 1)]

    indices = []
    for r in range(MESH_H - 1):
        for c in range(MESH_W - 1):
            a = r*MESH_W+c; b=a+1; d=a+MESH_W; e=d+1
            indices += [a, d, b, b, d, e]
    return verts, uvs, indices

# ─── Solid-colour PNG texture ─────────────────────────────────────────────
def _chunk(name, body):
    crc = zlib.crc32(name + body) & 0xffffffff
    return struct.pack('>I', len(body)) + name + body + struct.pack('>I', crc)

def solid_png(R, G, B, w=2, h=2):
    raw = b''.join(b'\x00' + bytes([R, G, B] * w) for _ in range(h))
    return (b'\x89PNG\r\n\x1a\n'
            + _chunk(b'IHDR', struct.pack('>IIBBBBB', w, h, 8, 2, 0, 0, 0))
            + _chunk(b'IDAT', zlib.compress(raw))
            + _chunk(b'IEND', b''))

# ─── GLB writer ───────────────────────────────────────────────────────────
def _p4(b): return b + b'\x00' * ((-len(b)) % 4)

def write_glb(verts, uvs, indices, img_bytes, path):
    ni, nv = len(indices), len(verts) // 3

    idx_b = b''.join(struct.pack('<I', v) for v in indices)
    pos_b = b''.join(struct.pack('<f', v) for v in verts)
    uv_b  = b''.join(struct.pack('<f', v) for v in uvs)

    parts = [_p4(idx_b), _p4(pos_b), _p4(uv_b), _p4(img_bytes)]
    blob  = b''.join(parts)
    off   = [sum(len(p) for p in parts[:i]) for i in range(4)]

    vx = verts[0::3]; vy = verts[1::3]; vz = verts[2::3]
    pmin = [min(vx), min(vy), min(vz)]
    pmax = [max(vx), max(vy), max(vz)]

    gltf = {
        "asset": {"version": "2.0", "generator": "oxley-territory-flat"},
        "scene": 0,
        "scenes": [{"nodes": [0]}],
        "nodes":  [{"mesh": 0}],
        "meshes": [{"primitives": [{"attributes": {"POSITION": 1, "TEXCOORD_0": 2},
                                    "indices": 0, "material": 0}]}],
        "materials": [{"pbrMetallicRoughness": {
                            "baseColorTexture": {"index": 0},
                            "metallicFactor": 0.0, "roughnessFactor": 1.0},
                       "doubleSided": True}],
        "textures": [{"source": 0, "sampler": 0}],
        "images":   [{"bufferView": 3, "mimeType": "image/png"}],
        "samplers": [{"magFilter": 9729, "minFilter": 9987,
                      "wrapS": 33071, "wrapT": 33071}],
        "buffers":  [{"byteLength": len(blob)}],
        "bufferViews": [
            {"buffer": 0, "byteOffset": off[0], "byteLength": len(idx_b), "target": 34963},
            {"buffer": 0, "byteOffset": off[1], "byteLength": len(pos_b), "target": 34962},
            {"buffer": 0, "byteOffset": off[2], "byteLength": len(uv_b),  "target": 34962},
            {"buffer": 0, "byteOffset": off[3], "byteLength": len(img_bytes)},
        ],
        "accessors": [
            {"bufferView": 0, "componentType": 5125, "count": ni, "type": "SCALAR"},
            {"bufferView": 1, "componentType": 5126, "count": nv, "type": "VEC3",
             "min": pmin, "max": pmax},
            {"bufferView": 2, "componentType": 5126, "count": nv, "type": "VEC2"},
        ],
    }

    j = _p4(json.dumps(gltf, separators=(',', ':')).encode())
    jc = struct.pack('<II', len(j),    0x4E4F534A) + j     # JSON chunk
    bc = struct.pack('<II', len(blob), 0x004E4942) + blob   # BIN  chunk
    hdr = struct.pack('<III', 0x46546C67, 2, 12 + len(jc) + len(bc))

    with open(path, 'wb') as f:
        f.write(hdr + jc + bc)
    print(f"[done] {path}  ({(12+len(jc)+len(bc))/1e6:.2f} MB, "
          f"{nv} verts, {ni//3} tris)")

# ─── main ─────────────────────────────────────────────────────────────────
def main():
    print(f"Building flat mesh {MESH_W}×{MESH_H} for "
          f"{LAT_MIN}–{LAT_MAX}°N  {LNG_MIN}–{LNG_MAX}°E")
    verts, uvs, indices = build_mesh()
    img = solid_png(120, 148, 80)   # muted olive-green for terrain
    write_glb(verts, uvs, indices, img, OUT_GLB)

if __name__ == '__main__':
    main()
