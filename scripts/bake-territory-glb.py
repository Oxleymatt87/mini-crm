#!/usr/bin/env python3
"""
Bake a single .glb of the Oxley sales territory (Liberty / Beaumont /
Orange / Kountze / Silsbee / Buna / Kirbyville) for use as the static
ground mesh in map-xr.html when the user enters immersive AR.

Pulls free, no-key data:
  - Mapzen Terrarium terrain tiles (PNG, RGB-encoded elevation)
  - ESRI World Imagery tiles for the texture

Writes:
  public/territory.glb        — single GLB with mesh + draped imagery

Usage:
  pip install requests Pillow numpy pygltflib
  python3 scripts/bake-territory-glb.py
"""
from __future__ import annotations

import io
import math
import os
import struct
import sys
from pathlib import Path

import numpy as np
import requests
from PIL import Image
from pygltflib import (
    GLTF2, Asset, Scene, Node, Mesh, Primitive, Buffer, BufferView,
    Accessor, Material, PbrMetallicRoughness, TextureInfo, Texture, Image as GLImage, Sampler,
)

# ─── Region ────────────────────────────────────────────────────────────
LAT_MIN, LAT_MAX = 30.00, 30.70   # Liberty south → Kirbyville north
LNG_MIN, LNG_MAX = -94.80, -93.70 # Liberty west  → Orange east
CENTER_LAT = (LAT_MIN + LAT_MAX) / 2
CENTER_LNG = (LNG_MIN + LNG_MAX) / 2

TERRAIN_ZOOM = 11   # ~76 m / px terrain — plenty for a mesh at this scale
IMAGERY_ZOOM = 13   # ~19 m / px draped imagery — readable street grid

# Mesh density. The full heightmap from z11 is way denser than we need
# for a headset-friendly mesh; downsample to this many vertices.
MESH_W = 384
MESH_H = 256

OUT_GLB = Path(__file__).resolve().parent.parent / "public" / "territory.glb"
OUT_GLB.parent.mkdir(parents=True, exist_ok=True)

TERRAIN_URL = "https://elevation-tiles-prod.s3.amazonaws.com/terrarium/{z}/{x}/{y}.png"
IMAGERY_URL = "https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}"

session = requests.Session()
session.headers["User-Agent"] = "oxley-territory-baker/1.0"


# ─── Web Mercator helpers ──────────────────────────────────────────────
def lnglat_to_tile(lng: float, lat: float, z: int) -> tuple[int, int]:
    n = 2 ** z
    x = int((lng + 180.0) / 360.0 * n)
    lat_rad = math.radians(lat)
    y = int((1 - math.asinh(math.tan(lat_rad)) / math.pi) / 2 * n)
    return x, y


def tile_to_lng(x: int, z: int) -> float:
    return x / (2 ** z) * 360.0 - 180.0


def tile_to_lat(y: int, z: int) -> float:
    n = math.pi - 2.0 * math.pi * y / (2 ** z)
    return math.degrees(math.atan(0.5 * (math.exp(n) - math.exp(-n))))


def fetch_tile(url: str) -> Image.Image:
    r = session.get(url, timeout=30)
    r.raise_for_status()
    return Image.open(io.BytesIO(r.content))


# ─── ECEF / ENU (mirrors map-xr.html so coordinates align with the pin layer) ──
WGS84_A = 6378137.0
WGS84_E2 = 6.69437999014e-3


def latlng_to_ecef(lat: float, lng: float, h: float = 0.0) -> np.ndarray:
    lat_r = math.radians(lat)
    lng_r = math.radians(lng)
    s, c = math.sin(lat_r), math.cos(lat_r)
    n_rad = WGS84_A / math.sqrt(1 - WGS84_E2 * s * s)
    return np.array([
        (n_rad + h) * c * math.cos(lng_r),
        (n_rad + h) * c * math.sin(lng_r),
        (n_rad * (1 - WGS84_E2) + h) * s,
    ])


def enu_basis(lat: float, lng: float) -> np.ndarray:
    lat_r = math.radians(lat)
    lng_r = math.radians(lng)
    sl, cl = math.sin(lat_r), math.cos(lat_r)
    sn, cn = math.sin(lng_r), math.cos(lng_r)
    east = np.array([-sn, cn, 0])
    north = np.array([-sl * cn, -sl * sn, cl])
    up = np.array([cl * cn, cl * sn, sl])
    # map-xr.html: east → +X, up → +Y, -north → +Z
    return np.column_stack([east, up, -north])


CENTER_ECEF = latlng_to_ecef(CENTER_LAT, CENTER_LNG)
ENU = enu_basis(CENTER_LAT, CENTER_LNG)
ENU_INV = np.linalg.inv(ENU)


def ecef_to_local(ecef: np.ndarray) -> np.ndarray:
    return ENU_INV @ (ecef - CENTER_ECEF)


# ─── Terrain pull ──────────────────────────────────────────────────────
def fetch_terrain() -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Stitch terrain tiles covering the bbox; return (heights, lat_grid, lng_grid)."""
    z = TERRAIN_ZOOM
    x0, y1 = lnglat_to_tile(LNG_MIN, LAT_MIN, z)
    x1, y0 = lnglat_to_tile(LNG_MAX, LAT_MAX, z)
    nx, ny = x1 - x0 + 1, y1 - y0 + 1
    print(f"[terrain] z{z} tiles: x{x0}..{x1} ({nx}), y{y0}..{y1} ({ny}) = {nx * ny} tiles")

    big = np.zeros((ny * 256, nx * 256), dtype=np.float32)
    for j, ty in enumerate(range(y0, y1 + 1)):
        for i, tx in enumerate(range(x0, x1 + 1)):
            url = TERRAIN_URL.format(z=z, x=tx, y=ty)
            try:
                tile = fetch_tile(url).convert("RGB")
            except Exception as e:
                print(f"  miss {tx},{ty}: {e}")
                continue
            arr = np.asarray(tile, dtype=np.float32)
            # terrarium encoding: elev = (R*256 + G + B/256) - 32768
            elev = arr[..., 0] * 256.0 + arr[..., 1] + arr[..., 2] / 256.0 - 32768.0
            big[j * 256:(j + 1) * 256, i * 256:(i + 1) * 256] = elev
            print(f"  tile {tx},{ty} ✓  elev range {elev.min():.0f}..{elev.max():.0f} m")

    # Build lat/lng grid that matches the stitched pixel layout.
    px_h, px_w = big.shape
    lng_grid = np.linspace(tile_to_lng(x0, z), tile_to_lng(x1 + 1, z), px_w)
    # Lat in mercator goes north-positive but pixel rows go south-positive:
    lat_grid = np.linspace(tile_to_lat(y0, z), tile_to_lat(y1 + 1, z), px_h)
    return big, lat_grid, lng_grid


def fetch_imagery() -> Image.Image:
    z = IMAGERY_ZOOM
    x0, y1 = lnglat_to_tile(LNG_MIN, LAT_MIN, z)
    x1, y0 = lnglat_to_tile(LNG_MAX, LAT_MAX, z)
    nx, ny = x1 - x0 + 1, y1 - y0 + 1
    print(f"[imagery] z{z} tiles: x{x0}..{x1} ({nx}), y{y0}..{y1} ({ny}) = {nx * ny} tiles")

    big = Image.new("RGB", (nx * 256, ny * 256), (0, 0, 0))
    for j, ty in enumerate(range(y0, y1 + 1)):
        for i, tx in enumerate(range(x0, x1 + 1)):
            url = IMAGERY_URL.format(z=z, x=tx, y=ty)
            try:
                tile = fetch_tile(url).convert("RGB")
                big.paste(tile, (i * 256, j * 256))
            except Exception as e:
                print(f"  miss {tx},{ty}: {e}")
            if (j * nx + i) % 25 == 0:
                print(f"  imagery {j * nx + i + 1}/{nx * ny}")
    return big


# ─── Mesh build ────────────────────────────────────────────────────────
def build_mesh(heights: np.ndarray, lat_grid: np.ndarray, lng_grid: np.ndarray):
    """Downsample heights to (MESH_H × MESH_W) and convert to local-frame XYZ + UVs."""
    src_h, src_w = heights.shape
    js = np.linspace(0, src_h - 1, MESH_H).astype(np.int32)
    is_ = np.linspace(0, src_w - 1, MESH_W).astype(np.int32)
    sample_lat = lat_grid[js]
    sample_lng = lng_grid[is_]
    sample_elev = heights[np.ix_(js, is_)]

    verts = np.zeros((MESH_H * MESH_W, 3), dtype=np.float32)
    uvs = np.zeros((MESH_H * MESH_W, 2), dtype=np.float32)
    for r in range(MESH_H):
        for c in range(MESH_W):
            local = ecef_to_local(latlng_to_ecef(float(sample_lat[r]), float(sample_lng[c]), float(sample_elev[r, c])))
            i = r * MESH_W + c
            verts[i] = local
            uvs[i] = (c / (MESH_W - 1), 1.0 - r / (MESH_H - 1))

    # Two triangles per quad. Winding chosen so +Y is up.
    indices = np.zeros(((MESH_H - 1) * (MESH_W - 1) * 2 * 3,), dtype=np.uint32)
    k = 0
    for r in range(MESH_H - 1):
        for c in range(MESH_W - 1):
            a = r * MESH_W + c
            b = a + 1
            d = a + MESH_W
            e = d + 1
            indices[k:k + 6] = (a, d, b, b, d, e)
            k += 6
    return verts, uvs, indices


# ─── glTF write ────────────────────────────────────────────────────────
def pad4(b: bytes) -> bytes:
    pad = (4 - len(b) % 4) % 4
    return b + b"\x00" * pad


def write_glb(verts: np.ndarray, uvs: np.ndarray, indices: np.ndarray, image_bytes: bytes, out_path: Path) -> None:
    # Pack a single binary buffer: indices, positions, uvs, image.
    idx_b = indices.astype(np.uint32).tobytes()
    pos_b = verts.astype(np.float32).tobytes()
    uv_b = uvs.astype(np.float32).tobytes()
    img_b = image_bytes

    parts = [pad4(idx_b), pad4(pos_b), pad4(uv_b), pad4(img_b)]
    buffer_blob = b"".join(parts)

    offsets = []
    cur = 0
    for p in parts:
        offsets.append(cur)
        cur += len(p)

    g = GLTF2(asset=Asset(version="2.0", generator="oxley-territory-baker"))
    g.buffers.append(Buffer(byteLength=len(buffer_blob)))

    g.bufferViews.extend([
        BufferView(buffer=0, byteOffset=offsets[0], byteLength=len(idx_b), target=34963),  # ELEMENT_ARRAY_BUFFER
        BufferView(buffer=0, byteOffset=offsets[1], byteLength=len(pos_b), target=34962),  # ARRAY_BUFFER
        BufferView(buffer=0, byteOffset=offsets[2], byteLength=len(uv_b), target=34962),
        BufferView(buffer=0, byteOffset=offsets[3], byteLength=len(img_b)),
    ])

    pmin = verts.min(axis=0).tolist()
    pmax = verts.max(axis=0).tolist()
    g.accessors.extend([
        Accessor(bufferView=0, componentType=5125, count=len(indices), type="SCALAR"),  # uint32
        Accessor(bufferView=1, componentType=5126, count=len(verts), type="VEC3", min=pmin, max=pmax),  # float32
        Accessor(bufferView=2, componentType=5126, count=len(uvs), type="VEC2"),
    ])

    g.images.append(GLImage(bufferView=3, mimeType="image/jpeg"))
    g.samplers.append(Sampler(magFilter=9729, minFilter=9987, wrapS=33071, wrapT=33071))
    g.textures.append(Texture(source=0, sampler=0))
    g.materials.append(Material(
        pbrMetallicRoughness=PbrMetallicRoughness(
            baseColorTexture=TextureInfo(index=0),
            metallicFactor=0.0,
            roughnessFactor=1.0,
        ),
        doubleSided=True,
    ))

    primitive = Primitive(
        attributes={"POSITION": 1, "TEXCOORD_0": 2},
        indices=0,
        material=0,
    )
    g.meshes.append(Mesh(primitives=[primitive]))
    g.nodes.append(Node(mesh=0))
    g.scenes.append(Scene(nodes=[0]))
    g.scene = 0

    g.set_binary_blob(buffer_blob)
    g.save_binary(str(out_path))
    print(f"[done] wrote {out_path}  ({len(buffer_blob) / 1e6:.1f} MB)")


# ─── main ──────────────────────────────────────────────────────────────
def main() -> int:
    print(f"region: lat {LAT_MIN}..{LAT_MAX}  lng {LNG_MIN}..{LNG_MAX}")
    print(f"center: {CENTER_LAT:.4f}, {CENTER_LNG:.4f}")

    heights, lat_grid, lng_grid = fetch_terrain()
    img = fetch_imagery()

    # Match image aspect to mesh sample area: clip image to the bbox in
    # lng/lat (the tile grid is slightly wider than the bbox in both axes).
    z = IMAGERY_ZOOM
    x0, y1 = lnglat_to_tile(LNG_MIN, LAT_MIN, z)
    x1, y0 = lnglat_to_tile(LNG_MAX, LAT_MAX, z)
    img_w_lng = tile_to_lng(x1 + 1, z) - tile_to_lng(x0, z)
    img_h_lat = tile_to_lat(y0, z) - tile_to_lat(y1 + 1, z)
    px_per_lng = img.width / img_w_lng
    px_per_lat = img.height / img_h_lat
    left = (LNG_MIN - tile_to_lng(x0, z)) * px_per_lng
    right = (LNG_MAX - tile_to_lng(x0, z)) * px_per_lng
    top = (tile_to_lat(y0, z) - LAT_MAX) * px_per_lat
    bottom = (tile_to_lat(y0, z) - LAT_MIN) * px_per_lat
    img = img.crop((int(left), int(top), int(right), int(bottom)))
    print(f"[imagery] cropped to {img.size}")

    # Encode as JPEG (transparent = wasted bytes).
    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=82, optimize=True)
    img_bytes = buf.getvalue()
    print(f"[imagery] {len(img_bytes) / 1e6:.1f} MB jpeg")

    print(f"building mesh: {MESH_W}x{MESH_H} = {MESH_W * MESH_H} verts, {(MESH_W - 1) * (MESH_H - 1) * 2} tris")
    verts, uvs, indices = build_mesh(heights, lat_grid, lng_grid)
    write_glb(verts, uvs, indices, img_bytes, OUT_GLB)
    return 0


if __name__ == "__main__":
    sys.exit(main())
