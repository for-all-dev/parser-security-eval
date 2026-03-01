"""Tests that Tier 1 target corpus directories are populated with valid seed files."""

from __future__ import annotations

import gzip
import zlib
from pathlib import Path

import pytest

# The targets/ directory is two levels up from scaffold/src/tests/
SCAFFOLD_DIR = Path(__file__).parent.parent.parent.resolve()
TARGETS_DIR = SCAFFOLD_DIR.parent / "targets"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def corpus_files(target: str, suffix: str) -> list[Path]:
    """Return all files in a target's corpus/ directory matching suffix."""
    corpus_dir = TARGETS_DIR / target / "corpus"
    return list(corpus_dir.glob(f"*{suffix}"))


def dict_file(target: str, name: str) -> Path:
    return TARGETS_DIR / target / "dictionary" / name


# ---------------------------------------------------------------------------
# Generic corpus presence tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "target",
    ["libpng", "libjpeg-turbo", "libxml2", "zlib"],
)
def test_corpus_dir_exists_and_nonempty(target: str) -> None:
    corpus_dir = TARGETS_DIR / target / "corpus"
    assert corpus_dir.is_dir(), f"{target}/corpus/ directory missing"
    files = [f for f in corpus_dir.iterdir() if f.is_file()]
    assert len(files) > 0, f"{target}/corpus/ is empty"


@pytest.mark.parametrize(
    "target",
    ["libpng", "libjpeg-turbo", "libxml2", "zlib"],
)
def test_dictionary_dir_exists_and_nonempty(target: str) -> None:
    dict_dir = TARGETS_DIR / target / "dictionary"
    assert dict_dir.is_dir(), f"{target}/dictionary/ directory missing"
    files = [f for f in dict_dir.iterdir() if f.is_file()]
    assert len(files) > 0, f"{target}/dictionary/ is empty"


# ---------------------------------------------------------------------------
# libpng
# ---------------------------------------------------------------------------


class TestLibpngCorpus:
    def test_minimal_png_exists(self) -> None:
        path = TARGETS_DIR / "libpng" / "corpus" / "minimal.png"
        assert path.exists(), "minimal.png missing"
        assert path.stat().st_size > 0

    def test_minimal_palette_png_exists(self) -> None:
        path = TARGETS_DIR / "libpng" / "corpus" / "minimal_palette.png"
        assert path.exists(), "minimal_palette.png missing"
        assert path.stat().st_size > 0

    def test_png_signature(self) -> None:
        for png_path in (TARGETS_DIR / "libpng" / "corpus").glob("*.png"):
            data = png_path.read_bytes()
            assert data[:8] == b"\x89PNG\r\n\x1a\n", (
                f"{png_path.name}: bad PNG signature"
            )

    def test_png_has_ihdr_chunk(self) -> None:
        for png_path in (TARGETS_DIR / "libpng" / "corpus").glob("*.png"):
            data = png_path.read_bytes()
            # First chunk after signature starts at offset 8; type at offset 12
            assert data[12:16] == b"IHDR", f"{png_path.name}: first chunk is not IHDR"

    def test_png_has_iend_chunk(self) -> None:
        for png_path in (TARGETS_DIR / "libpng" / "corpus").glob("*.png"):
            data = png_path.read_bytes()
            # IEND chunk type appears in last 12 bytes (length=0, type=IEND, crc)
            assert b"IEND" in data, f"{png_path.name}: IEND chunk missing"

    def test_png_dict_exists(self) -> None:
        d = dict_file("libpng", "png.dict")
        assert d.exists(), "libpng/dictionary/png.dict missing"
        content = d.read_text()
        assert "IHDR" in content
        assert "IDAT" in content
        assert "IEND" in content
        assert "PLTE" in content


# ---------------------------------------------------------------------------
# libjpeg-turbo
# ---------------------------------------------------------------------------


class TestLibjpegCorpus:
    def test_minimal_jpg_exists(self) -> None:
        path = TARGETS_DIR / "libjpeg-turbo" / "corpus" / "minimal.jpg"
        assert path.exists(), "minimal.jpg missing"

    def test_jpeg_soi_eoi_markers(self) -> None:
        for jpg_path in (TARGETS_DIR / "libjpeg-turbo" / "corpus").glob("*.jpg"):
            data = jpg_path.read_bytes()
            assert data[:2] == b"\xff\xd8", f"{jpg_path.name}: missing SOI marker"
            assert data[-2:] == b"\xff\xd9", f"{jpg_path.name}: missing EOI marker"

    def test_jpeg_has_app0_or_app1(self) -> None:
        """JFIF files have APP0 (0xffe0); Exif files have APP1 (0xffe1)."""
        path = TARGETS_DIR / "libjpeg-turbo" / "corpus" / "minimal.jpg"
        data = path.read_bytes()
        assert data[2:4] in (b"\xff\xe0", b"\xff\xe1"), (
            "minimal.jpg: no APP0/APP1 marker after SOI"
        )

    def test_jpeg_dict_exists(self) -> None:
        d = dict_file("libjpeg-turbo", "jpeg.dict")
        assert d.exists(), "libjpeg-turbo/dictionary/jpeg.dict missing"
        content = d.read_text()
        assert "JFIF" in content
        assert "\\xff\\xd8" in content
        assert "\\xff\\xd9" in content


# ---------------------------------------------------------------------------
# libxml2
# ---------------------------------------------------------------------------


class TestLibxml2Corpus:
    def test_minimal_xml_valid(self) -> None:
        path = TARGETS_DIR / "libxml2" / "corpus" / "minimal.xml"
        assert path.exists()
        content = path.read_text()
        assert "<?xml" in content
        # Confirm it has a root element
        assert "<root" in content or "<document" in content

    def test_required_xml_files_exist(self) -> None:
        required = [
            "minimal.xml",
            "namespaces.xml",
            "entities.xml",
            "large_doc.xml",
            "minimal.dtd",
            "xinclude.xml",
        ]
        corpus_dir = TARGETS_DIR / "libxml2" / "corpus"
        for name in required:
            assert (corpus_dir / name).exists(), f"libxml2/corpus/{name} missing"

    def test_namespaces_xml_has_xmlns(self) -> None:
        content = (TARGETS_DIR / "libxml2" / "corpus" / "namespaces.xml").read_text()
        assert "xmlns" in content

    def test_entities_xml_has_safe_entities(self) -> None:
        content = (TARGETS_DIR / "libxml2" / "corpus" / "entities.xml").read_text()
        assert "&amp;" in content
        assert "&lt;" in content

    def test_large_doc_has_multiple_elements(self) -> None:
        content = (TARGETS_DIR / "libxml2" / "corpus" / "large_doc.xml").read_text()
        element_count = content.count("<level")
        assert element_count >= 20, (
            f"large_doc.xml only has {element_count} level elements"
        )

    def test_xinclude_xml_has_xi_include(self) -> None:
        content = (TARGETS_DIR / "libxml2" / "corpus" / "xinclude.xml").read_text()
        assert "xi:include" in content or "XInclude" in content

    def test_xml_dict_exists(self) -> None:
        d = dict_file("libxml2", "xml.dict")
        assert d.exists(), "libxml2/dictionary/xml.dict missing"
        content = d.read_text()
        assert "<?xml" in content
        assert "<!DOCTYPE" in content
        assert "xmlns:" in content
        assert "&amp;" in content


# ---------------------------------------------------------------------------
# zlib
# ---------------------------------------------------------------------------


class TestZlibCorpus:
    def test_required_files_exist(self) -> None:
        corpus_dir = TARGETS_DIR / "zlib" / "corpus"
        assert (corpus_dir / "empty.gz").exists(), "empty.gz missing"
        assert (corpus_dir / "hello.gz").exists(), "hello.gz missing"
        assert (corpus_dir / "hello.zz").exists(), "hello.zz missing"

    def test_empty_gz_is_valid_gzip(self) -> None:
        path = TARGETS_DIR / "zlib" / "corpus" / "empty.gz"
        data = path.read_bytes()
        assert data[:2] == b"\x1f\x8b", "empty.gz: wrong gzip magic"
        decompressed = gzip.decompress(data)
        assert decompressed == b"", (
            f"empty.gz should decompress to empty, got {decompressed!r}"
        )

    def test_hello_gz_decompresses_correctly(self) -> None:
        path = TARGETS_DIR / "zlib" / "corpus" / "hello.gz"
        data = path.read_bytes()
        assert data[:2] == b"\x1f\x8b", "hello.gz: wrong gzip magic"
        decompressed = gzip.decompress(data)
        assert decompressed == b"hello world"

    def test_hello_zz_is_valid_zlib(self) -> None:
        path = TARGETS_DIR / "zlib" / "corpus" / "hello.zz"
        data = path.read_bytes()
        # zlib streams start with 0x78 (CMF byte)
        assert data[0:1] == b"\x78", f"hello.zz: unexpected first byte {data[0]:02x}"
        decompressed = zlib.decompress(data)
        assert decompressed == b"hello world"

    def test_zlib_dict_exists(self) -> None:
        d = dict_file("zlib", "zlib.dict")
        assert d.exists(), "zlib/dictionary/zlib.dict missing"
        content = d.read_text()
        assert "\\x1f\\x8b" in content
        assert "\\x78\\x9c" in content
