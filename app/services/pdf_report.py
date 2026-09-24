"""Dependency-free PDF generation for audit-ready reports (BE-12).

A PDF is a structured document format; for a text report we don't need a heavy library.
This emits a valid multi-page PDF (Helvetica, US-Letter) from the plain-text/Markdown
report. It is intentionally minimal but produces a real, openable .pdf — sufficient for
an "audit-ready" text report. For richly-formatted PDFs, swap in reportlab/WeasyPrint.
"""

from __future__ import annotations

PAGE_W, PAGE_H = 612, 792  # US Letter points
MARGIN = 54
FONT_SIZE = 9
LEADING = 12
MAX_CHARS = 95  # rough monospace-ish wrap width for Helvetica 9pt


def _escape(text: str) -> str:
    return text.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")


def _wrap(line: str, width: int = MAX_CHARS) -> list[str]:
    line = line.replace("\t", "    ").rstrip("\n")
    if not line:
        return [""]
    out: list[str] = []
    while len(line) > width:
        cut = line.rfind(" ", 0, width)
        if cut <= 0:
            cut = width
        out.append(line[:cut])
        line = line[cut:].lstrip()
    out.append(line)
    return out


def _paginate(text: str) -> list[list[str]]:
    lines_per_page = int((PAGE_H - 2 * MARGIN) / LEADING)
    wrapped: list[str] = []
    for raw in text.split("\n"):
        wrapped.extend(_wrap(raw))
    pages: list[list[str]] = []
    for i in range(0, len(wrapped), lines_per_page):
        pages.append(wrapped[i : i + lines_per_page])
    return pages or [[""]]


def text_to_pdf(text: str) -> bytes:
    """Render plain text (or Markdown source) into a valid multi-page PDF byte string."""
    pages = _paginate(text)
    objects: list[bytes] = []

    # Object numbering: 1=Catalog, 2=Pages, 3=Font, then per page: content + page objs.
    font_obj = 3
    page_obj_ids: list[int] = []
    content_streams: list[tuple[int, bytes]] = []

    next_id = 4
    for page_lines in pages:
        content_id = next_id
        page_id = next_id + 1
        next_id += 2
        page_obj_ids.append(page_id)

        y = PAGE_H - MARGIN
        parts = ["BT", f"/F1 {FONT_SIZE} Tf", f"{LEADING} TL", f"{MARGIN} {y} Td"]
        first = True
        for ln in page_lines:
            if first:
                parts.append(f"({_escape(ln)}) Tj")
                first = False
            else:
                parts.append(f"T* ({_escape(ln)}) Tj")
        parts.append("ET")
        stream = ("\n".join(parts)).encode("latin-1", "replace")
        content_streams.append((content_id, stream))

    # Build objects
    catalog = b"<< /Type /Catalog /Pages 2 0 R >>"
    kids = " ".join(f"{pid} 0 R" for pid in page_obj_ids)
    pages_obj = f"<< /Type /Pages /Count {len(page_obj_ids)} /Kids [{kids}] >>".encode()
    font = b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"

    obj_bytes: dict[int, bytes] = {1: catalog, 2: pages_obj, font_obj: font}
    for (content_id, stream), page_id in zip(content_streams, page_obj_ids):
        obj_bytes[content_id] = (
            f"<< /Length {len(stream)} >>\nstream\n".encode() + stream + b"\nendstream"
        )
        obj_bytes[page_id] = (
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {PAGE_W} {PAGE_H}] "
            f"/Resources << /Font << /F1 {font_obj} 0 R >> >> "
            f"/Contents {content_id} 0 R >>".encode()
        )

    # Serialize with xref
    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets: dict[int, int] = {}
    for oid in sorted(obj_bytes):
        offsets[oid] = len(out)
        out += f"{oid} 0 obj\n".encode() + obj_bytes[oid] + b"\nendobj\n"

    xref_pos = len(out)
    n = max(obj_bytes) + 1
    out += f"xref\n0 {n}\n".encode()
    out += b"0000000000 65535 f \n"
    for oid in range(1, n):
        if oid in offsets:
            out += f"{offsets[oid]:010d} 00000 n \n".encode()
        else:
            out += b"0000000000 65535 f \n"
    out += (
        f"trailer\n<< /Size {n} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n".encode()
    )
    return bytes(out)
