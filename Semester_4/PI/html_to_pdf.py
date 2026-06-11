#!/usr/bin/env python3
"""
Convert the Privacy Study Guide HTML into a print-ready PDF.

Requirements:
    pip install weasyprint

Setup:
    Place the following files in the same folder:

    your-folder/
    ├── html_to_pdf.py                          ← this script
    ├── Privacy_Study_Guide_print_ready.html     ← the HTML file
    └── fonts/                                   ← font files (see below)
        ├── SourceSerif4-Regular.ttf
        ├── SourceSerif4-It.ttf
        ├── SourceSerif4-Semibold.ttf
        ├── SourceSerif4-Bold.ttf
        ├── SourceSerif4-BoldIt.ttf
        ├── SourceSerif4-Black.ttf
        ├── JetBrainsMono-Regular.ttf
        ├── JetBrainsMono-Medium.ttf
        └── JetBrainsMono-Bold.ttf

    Font downloads (open-source, free):
      Source Serif 4:  https://github.com/adobe-fonts/source-serif/tree/release/TTF
      JetBrains Mono: https://github.com/JetBrains/JetBrainsMono/tree/master/fonts/ttf

Usage:
    python html_to_pdf.py
    python html_to_pdf.py my_custom_guide.html output.pdf
"""

import sys
from pathlib import Path

from weasyprint import HTML
from weasyprint.text.fonts import FontConfiguration


def convert(html_path: str, pdf_path: str) -> None:
    """Read an HTML file and render it to a PDF via weasyprint."""

    html_file = Path(html_path).resolve()
    if not html_file.exists():
        print(f"Error: {html_file} not found.")
        sys.exit(1)

    html_content = html_file.read_text(encoding="utf-8")

    # weasyprint resolves relative URLs (like fonts/) from the base_url,
    # which we set to the HTML file's directory.
    base_url = str(html_file.parent) + "/"

    fc = FontConfiguration()

    print(f"Reading   {html_file.name}")
    print(f"Base URL  {base_url}")
    print(f"Rendering PDF ...")

    HTML(string=html_content, base_url=base_url).write_pdf(pdf_path, font_config=fc)

    print(f"Done → {pdf_path}")


if __name__ == "__main__":
    # Default file names
    default_html = "datenschutz_folien_zusammenfassung.html"
    default_pdf = "datenschutz_folien_zusammenfassung.pdf"

    html_in = sys.argv[1] if len(sys.argv) > 1 else default_html
    pdf_out = sys.argv[2] if len(sys.argv) > 2 else default_pdf

    convert(html_in, pdf_out)
