#!/usr/bin/env python3
"""Seed corpus and dictionary management for Category 1 parser targets.

Generates minimal valid seed files for libpng, libjpeg-turbo, libxml2, and zlib.
Optionally downloads oss-fuzz corpora from GCS if gsutil is available.

Usage:
    python targets/fetch_corpora.py

This script is idempotent: files that already exist are not overwritten.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import shutil
import struct
import subprocess
import zlib
from pathlib import Path

TARGETS_DIR = Path(__file__).parent.resolve()


# ---------------------------------------------------------------------------
# PNG generation helpers
# ---------------------------------------------------------------------------


def _png_chunk(chunk_type: bytes, data: bytes) -> bytes:
    """Build a PNG chunk: length + type + data + CRC."""
    length = struct.pack(">I", len(data))
    crc_input = chunk_type + data
    crc = struct.pack(">I", zlib.crc32(crc_input) & 0xFFFFFFFF)
    return length + chunk_type + data + crc


def make_minimal_png() -> bytes:
    """Generate a minimal valid 1x1 white RGBA PNG."""
    PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"

    # IHDR: width=1, height=1, bit_depth=8, color_type=2 (RGB), compression=0, filter=0, interlace=0
    ihdr_data = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    ihdr_chunk = _png_chunk(b"IHDR", ihdr_data)

    # IDAT: single white pixel. Raw scanline: filter_byte=0, R=255, G=255, B=255
    raw_scanline = b"\x00\xff\xff\xff"
    compressed = zlib.compress(raw_scanline, level=9)
    idat_chunk = _png_chunk(b"IDAT", compressed)

    iend_chunk = _png_chunk(b"IEND", b"")

    return PNG_SIGNATURE + ihdr_chunk + idat_chunk + iend_chunk


def make_minimal_palette_png() -> bytes:
    """Generate a minimal valid 1x1 palette (indexed-colour) PNG."""
    PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"

    # IHDR: 1x1, bit_depth=8, color_type=3 (indexed), compression=0, filter=0, interlace=0
    ihdr_data = struct.pack(">IIBBBBB", 1, 1, 8, 3, 0, 0, 0)
    ihdr_chunk = _png_chunk(b"IHDR", ihdr_data)

    # PLTE: one palette entry — white (255, 255, 255)
    plte_data = b"\xff\xff\xff"
    plte_chunk = _png_chunk(b"PLTE", plte_data)

    # IDAT: single pixel index=0, filter_byte=0
    raw_scanline = b"\x00\x00"
    compressed = zlib.compress(raw_scanline, level=9)
    idat_chunk = _png_chunk(b"IDAT", compressed)

    iend_chunk = _png_chunk(b"IEND", b"")

    return PNG_SIGNATURE + ihdr_chunk + plte_chunk + idat_chunk + iend_chunk


# ---------------------------------------------------------------------------
# JPEG generation helpers
# ---------------------------------------------------------------------------


def make_minimal_jpeg() -> bytes:
    """Generate a minimal valid 1x1 grayscale JFIF JPEG."""
    # SOI
    soi = b"\xff\xd8"

    # APP0 / JFIF marker
    app0_payload = (
        b"JFIF\x00"  # identifier + null
        b"\x01\x01"  # version 1.1
        b"\x00"  # aspect ratio units: 0 = no units
        b"\x00\x01"  # X density = 1
        b"\x00\x01"  # Y density = 1
        b"\x00\x00"  # thumbnail size 0x0
    )
    app0 = b"\xff\xe0" + struct.pack(">H", 2 + len(app0_payload)) + app0_payload

    # DQT — define quantization table (8x8, all-1s for minimal size)
    qt_data = b"\x00" + bytes([1] * 64)  # table 0, precision 0 (8-bit), all 1s
    dqt = b"\xff\xdb" + struct.pack(">H", 2 + len(qt_data)) + qt_data

    # SOF0 — Start Of Frame (baseline DCT), 1x1, 1 component (Y only)
    sof0_payload = (
        b"\x08"  # precision 8 bits
        + struct.pack(">H", 1)  # height = 1
        + struct.pack(">H", 1)  # width  = 1
        + b"\x01"  # 1 component
        + b"\x01"  # component id = 1 (Y)
        + b"\x11"  # H/V sampling = 1x1
        + b"\x00"  # quant table 0
    )
    sof0 = b"\xff\xc0" + struct.pack(">H", 2 + len(sof0_payload)) + sof0_payload

    # DHT — define Huffman table (DC, table 0).
    # Use a real minimal Huffman table for DC component.
    # BITS: counts per code length 1..16
    bits = bytes([0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])  # 1 code of length 2
    huffvals = b"\x00"  # one value: 0
    dht_data = b"\x00" + bits + huffvals  # table class/id = 0 (DC, table 0)
    dht = b"\xff\xc4" + struct.pack(">H", 2 + len(dht_data)) + dht_data

    # SOS — Start Of Scan
    sos_payload = (
        b"\x01"  # 1 component
        + b"\x01"  # component selector = 1 (Y)
        + b"\x00"  # DC/AC table: DC=0, AC=0
        + b"\x00"  # Ss (start of spectral selection)
        + b"\x3f"  # Se (end of spectral selection)
        + b"\x00"  # Ah/Al
    )
    sos = b"\xff\xda" + struct.pack(">H", 2 + len(sos_payload)) + sos_payload

    # Compressed data: a single DC coefficient of 0 (EOB), encoded as all-zero bits
    # Minimal entropy-coded segment: 0x7f (stuffed) ends cleanly; use 0xf8 (MSB=1, valid end bits)
    compressed_data = b"\x7f\xa1"

    # EOI
    eoi = b"\xff\xd9"

    return soi + app0 + dqt + sof0 + dht + sos + compressed_data + eoi


# ---------------------------------------------------------------------------
# zlib / gzip generation helpers
# ---------------------------------------------------------------------------


def make_empty_gzip() -> bytes:
    """Generate a valid empty gzip stream."""
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz:
        gz.write(b"")
    return buf.getvalue()


def make_hello_gzip() -> bytes:
    """Generate a gzip stream containing 'hello world'."""
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz:
        gz.write(b"hello world")
    return buf.getvalue()


def make_hello_zlib() -> bytes:
    """Generate a zlib-wrapped deflate stream of 'hello world'."""
    return zlib.compress(b"hello world", level=6)


# ---------------------------------------------------------------------------
# File writing helpers
# ---------------------------------------------------------------------------


def write_file(path: Path, data: bytes | str, *, skip_if_exists: bool = True) -> bool:
    """Write data to path. Returns True if written, False if skipped."""
    if skip_if_exists and path.exists():
        print(f"  [skip] {path.relative_to(TARGETS_DIR)} (already exists)")
        return False

    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, str):
        path.write_text(data, encoding="utf-8")
    else:
        path.write_bytes(data)

    size = path.stat().st_size
    sha = hashlib.sha256(path.read_bytes()).hexdigest()[:12]
    print(f"  [wrote] {path.relative_to(TARGETS_DIR)} ({size} bytes, sha256={sha})")
    return True


# ---------------------------------------------------------------------------
# Per-target corpus generation
# ---------------------------------------------------------------------------


def generate_libpng_corpus(base: Path) -> int:
    """Generate libpng corpus and dictionary. Returns count of files written."""
    corpus_dir = base / "libpng" / "corpus"
    dict_dir = base / "libpng" / "dictionary"

    count = 0
    count += write_file(corpus_dir / "minimal.png", make_minimal_png())
    count += write_file(corpus_dir / "minimal_palette.png", make_minimal_palette_png())

    png_dict = """\
# PNG chunk types and keywords
"\\x89PNG\\r\\n\\x1a\\n"
"IHDR"
"IDAT"
"IEND"
"PLTE"
"tEXt"
"zTXt"
"iTXt"
"cHRM"
"gAMA"
"sRGB"
"bKGD"
"hIST"
"tRNS"
"pHYs"
"sBIT"
"sPLT"
"tIME"
"acTL"
"fcTL"
"fdAT"
"""
    count += write_file(dict_dir / "png.dict", png_dict)
    return count


def generate_libjpeg_corpus(base: Path) -> int:
    """Generate libjpeg-turbo corpus and dictionary. Returns count of files written."""
    corpus_dir = base / "libjpeg-turbo" / "corpus"
    dict_dir = base / "libjpeg-turbo" / "dictionary"

    count = 0
    count += write_file(corpus_dir / "minimal.jpg", make_minimal_jpeg())

    jpeg_dict = """\
# JPEG markers
"\\xff\\xd8"
"\\xff\\xe0"
"\\xff\\xe1"
"\\xff\\xdb"
"\\xff\\xc0"
"\\xff\\xc4"
"\\xff\\xda"
"\\xff\\xd9"
"\\xff\\xfe"
"JFIF"
"Exif"
"""
    count += write_file(dict_dir / "jpeg.dict", jpeg_dict)
    return count


def generate_libxml2_corpus(base: Path) -> int:
    """Generate libxml2 corpus and dictionary. Returns count of files written."""
    corpus_dir = base / "libxml2" / "corpus"
    dict_dir = base / "libxml2" / "dictionary"

    count = 0

    count += write_file(
        corpus_dir / "minimal.xml",
        '<?xml version="1.0"?><root/>\n',
    )
    count += write_file(
        corpus_dir / "namespaces.xml",
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<root xmlns:ex="http://example.com/ns" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">\n'
        '  <ex:child xsi:type="ex:MyType">value</ex:child>\n'
        "</root>\n",
    )
    count += write_file(
        corpus_dir / "entities.xml",
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        "<root>\n"
        "  <safe>&amp; &lt; &gt; &quot; &apos;</safe>\n"
        "  <numeric>&#65; &#x42;</numeric>\n"
        "</root>\n",
    )

    nested_elems = (
        "\n".join(f'  {"  " * i}<level{i} attr{i}="val{i}">' for i in range(1, 26))
        + "\n    <leaf>content</leaf>\n"
        + "\n".join(f"  {'  ' * i}</level{i}>" for i in range(25, 0, -1))
    )
    count += write_file(
        corpus_dir / "large_doc.xml",
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        "<document>\n" + nested_elems + "\n</document>\n",
    )

    count += write_file(
        corpus_dir / "minimal.dtd",
        "<!ELEMENT root (child*)>\n"
        "<!ELEMENT child (#PCDATA)>\n"
        "<!ATTLIST child id ID #IMPLIED>\n",
    )

    count += write_file(
        corpus_dir / "xinclude.xml",
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<root xmlns:xi="http://www.w3.org/2001/XInclude">\n'
        '  <xi:include href="minimal.xml" parse="xml"/>\n'
        '  <xi:include href="nonexistent.xml" parse="xml">\n'
        "    <xi:fallback><fallback-content/></xi:fallback>\n"
        "  </xi:include>\n"
        "</root>\n",
    )

    xml_dict = """\
# XML tokens
"<?xml"
"version="
"encoding="
"<!DOCTYPE"
"<!ENTITY"
"<![CDATA["
"]]>"
"xmlns:"
"<root"
"</root>"
"&amp;"
"&lt;"
"&gt;"
"&quot;"
"&apos;"
"""
    count += write_file(dict_dir / "xml.dict", xml_dict)
    return count


def generate_zlib_corpus(base: Path) -> int:
    """Generate zlib corpus and dictionary. Returns count of files written."""
    corpus_dir = base / "zlib" / "corpus"
    dict_dir = base / "zlib" / "dictionary"

    count = 0
    count += write_file(corpus_dir / "empty.gz", make_empty_gzip())
    count += write_file(corpus_dir / "hello.gz", make_hello_gzip())
    count += write_file(corpus_dir / "hello.zz", make_hello_zlib())

    zlib_dict = """\
# zlib/gzip/deflate magic bytes
"\\x1f\\x8b"
"\\x78\\x9c"
"\\x78\\x01"
"\\x78\\xda"
"\\x1f\\x8b\\x08"
"""
    count += write_file(dict_dir / "zlib.dict", zlib_dict)
    return count


# ---------------------------------------------------------------------------
# Optional: GCS corpus download
# ---------------------------------------------------------------------------


def try_download_ossfuzz_corpus(
    target_name: str, fuzzer_name: str, dest_dir: Path
) -> None:
    """Attempt to download oss-fuzz corpus from GCS using gsutil.

    Silently skips if gsutil is not available or the bucket is inaccessible.
    """
    if shutil.which("gsutil") is None:
        print(
            f"  [skip] gsutil not found — skipping GCS download for {target_name}/{fuzzer_name}"
        )
        return

    gcs_url = f"gs://clusterfuzz-corpus/libFuzzer/{target_name}_{fuzzer_name}/"
    dest_dir.mkdir(parents=True, exist_ok=True)
    cmd = ["gsutil", "-m", "cp", "-r", gcs_url, str(dest_dir)]
    print(f"  [gsutil] downloading {gcs_url} → {dest_dir}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if result.returncode != 0:
            print(
                f"  [warn] gsutil exited {result.returncode}: {result.stderr.strip()[:200]}"
            )
        else:
            files = list(dest_dir.glob("*"))
            print(f"  [ok] downloaded {len(files)} files from GCS")
    except subprocess.TimeoutExpired:
        print("  [warn] gsutil timed out after 120s")
    except Exception as exc:
        print(f"  [warn] gsutil error: {exc}")


# ---------------------------------------------------------------------------
# Minimization hint
# ---------------------------------------------------------------------------


def print_minimization_hints() -> None:
    """Print libfuzzer -merge=1 commands for each target."""
    print()
    print("To minimize corpora with libfuzzer -merge=1, run:")
    targets_and_fuzzers = [
        ("libpng", "libpng_read_fuzzer"),
        ("libjpeg-turbo", "libjpeg_turbo_fuzzer"),
        ("libxml2", "libxml2_xml_read_memory_fuzzer"),
        ("libxml2", "xml_xpath_fuzzer"),
        ("zlib", "zlib_uncompress_fuzzer"),
    ]
    for target, fuzzer in targets_and_fuzzers:
        print(
            f"  ./{fuzzer} -merge=1 targets/{target}/corpus/ targets/{target}/corpus/"
        )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    print("Seed corpus fetch/generate for Category 1 targets")
    print(f"Targets directory: {TARGETS_DIR}")
    print()

    total = 0

    print("=== libpng ===")
    total += generate_libpng_corpus(TARGETS_DIR)

    print()
    print("=== libjpeg-turbo ===")
    total += generate_libjpeg_corpus(TARGETS_DIR)

    print()
    print("=== libxml2 ===")
    total += generate_libxml2_corpus(TARGETS_DIR)

    print()
    print("=== zlib ===")
    total += generate_zlib_corpus(TARGETS_DIR)

    print()
    print("Optional: attempting GCS downloads (requires gsutil + gcloud auth)...")
    try_download_ossfuzz_corpus(
        "libpng", "libpng_read_fuzzer", TARGETS_DIR / "libpng" / "corpus"
    )
    try_download_ossfuzz_corpus(
        "libjpeg-turbo",
        "libjpeg_turbo_fuzzer",
        TARGETS_DIR / "libjpeg-turbo" / "corpus",
    )
    try_download_ossfuzz_corpus(
        "libxml2", "libxml2_xml_read_memory_fuzzer", TARGETS_DIR / "libxml2" / "corpus"
    )
    try_download_ossfuzz_corpus(
        "zlib", "zlib_uncompress_fuzzer", TARGETS_DIR / "zlib" / "corpus"
    )

    print_minimization_hints()

    print()
    print(f"Done. {total} new file(s) written.")


if __name__ == "__main__":
    main()
