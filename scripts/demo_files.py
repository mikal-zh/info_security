# PROJECT, 2026
# info_security
# File description:
# Fictitious demo files: KTP scan, Word contract and interview video.

"""Fictitious demo files: a KTP scan, a Word contract and a video."""

import io
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path

from PIL import Image, ImageDraw

KTP_ROWS = [
    "NIK : 3578012304980001", "Nama : ADITYA PRATAMA PUTRA",
    "Tempat/Tgl Lahir : SURABAYA, 14-04-1998", "Jenis Kelamin : LAKI-LAKI",
    "Alamat : JL. RAYA ITS NO. 10", "Agama : ISLAM",
    "Status Perkawinan : KAWIN", "Pekerjaan : KARYAWAN SWASTA",
    "Kewarganegaraan : WNI",
]

CONTRACT_LINES = [
    "EMPLOYMENT CONTRACT (SPECIMEN)",
    "Employee: Aditya Pratama Putra, NIK 3578012304980001",
    "Position: Logistics Analyst. Start date: 3 November 2026.",
    "Monthly gross salary: IDR 9,500,000, paid to Bank Mandiri "
    "141-00-1234567-8.",
] + ["Clause text. " * 40] * 30

PKG = "http://schemas.openxmlformats.org/package/2006"
DOCX_TYPE = ("application/vnd.openxmlformats-officedocument."
             "wordprocessingml.document.main+xml")
OFFICE_DOC = ("http://schemas.openxmlformats.org/officeDocument/2006/"
              "relationships/officeDocument")
WORD_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
XML_HEAD = '<?xml version="1.0" encoding="UTF-8"?>'
CONTENT_TYPES = (
    f'{XML_HEAD}<Types xmlns="{PKG}/content-types">'
    '<Default Extension="rels" ContentType="application/'
    'vnd.openxmlformats-package.relationships+xml"/>'
    '<Default Extension="xml" ContentType="application/xml"/>'
    f'<Override PartName="/word/document.xml" ContentType="{DOCX_TYPE}"/>'
    '</Types>')
RELATIONSHIPS = (
    f'{XML_HEAD}<Relationships xmlns="{PKG}/relationships">'
    f'<Relationship Id="rId1" Type="{OFFICE_DOC}" '
    'Target="word/document.xml"/></Relationships>')

FFMPEG_ARGS = [
    "-loglevel", "error", "-f", "lavfi",
    "-i", "testsrc2=size=1280x720:rate=25", "-f", "lavfi",
    "-i", "sine=frequency=440", "-t", "20", "-pix_fmt", "yuv420p",
    "-c:v", "libx264", "-c:a", "aac", "-shortest",
]


def ktp_scan() -> bytes:
    """A specimen KTP card as a PNG image."""
    image = Image.new("RGB", (856, 540), (214, 232, 245))
    draw = ImageDraw.Draw(image)
    draw.text((300, 20), "PROVINSI JAWA TIMUR - KOTA SURABAYA (SPECIMEN)",
              fill=(0, 0, 0))
    for index, row in enumerate(KTP_ROWS):
        draw.text((40, 80 + index * 40), row, fill=(20, 20, 20))
    draw.rectangle([640, 90, 810, 320], fill=(180, 190, 200),
                   outline=(90, 90, 90))
    draw.text((690, 200), "PHOTO", fill=(60, 60, 60))
    buffer = io.BytesIO()
    image.save(buffer, "PNG")
    return buffer.getvalue()


def contract_docx() -> bytes:
    """A minimal valid Word document, built without extra dependencies."""
    body = "".join(f"<w:p><w:r><w:t>{line}</w:t></w:r></w:p>"
                   for line in CONTRACT_LINES)
    document = (f'{XML_HEAD}<w:document xmlns:w="{WORD_NS}">'
                f"<w:body>{body}</w:body></w:document>")
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", CONTENT_TYPES)
        archive.writestr("_rels/.rels", RELATIONSHIPS)
        archive.writestr("word/document.xml", document)
    return buffer.getvalue()


def interview_video() -> bytes | None:
    """A 20-second 720p test video, or None when ffmpeg is missing."""
    if not shutil.which("ffmpeg"):
        print("ffmpeg not found: skipping the demo video.")
        return None
    with tempfile.TemporaryDirectory() as tmp:
        output = Path(tmp) / "interview.mp4"
        subprocess.run(["ffmpeg", *FFMPEG_ARGS, str(output)], check=True)
        return output.read_bytes()
