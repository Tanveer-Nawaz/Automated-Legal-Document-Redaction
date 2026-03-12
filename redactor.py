"""
redactor.py
Core PII detection and redaction engine.
Uses spaCy NER (if available) + comprehensive legal regex patterns.
"""

import re
import csv
import io
import os
from datetime import datetime
from typing import List, Tuple, Dict

# ---------------------------------------------------------------------------
# Try to import optional heavy deps; fall back gracefully
# ---------------------------------------------------------------------------
try:
    import fitz  # PyMuPDF
    PYMUPDF_AVAILABLE = True
except ImportError:
    PYMUPDF_AVAILABLE = False

try:
    import spacy
    try:
        nlp = spacy.load("en_core_web_sm")
        SPACY_AVAILABLE = True
    except OSError:
        try:
            nlp = spacy.load("en_core_web_md")
            SPACY_AVAILABLE = True
        except OSError:
            SPACY_AVAILABLE = False
except ImportError:
    SPACY_AVAILABLE = False


# ---------------------------------------------------------------------------
# Legal PII Regex Patterns
# ---------------------------------------------------------------------------

PATTERNS: List[Tuple[str, str, re.Pattern]] = [
    # ── Contact & Identity ──────────────────────────────────────────────
    ("EMAIL", "Contact Information",
     re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b')),

    ("PHONE", "Contact Information",
     re.compile(
         r'(?<!\d)(\+?\d{1,3}[\s\-.]?)?'
         r'(\(?\d{2,4}\)?[\s\-.]?)'
         r'\d{3,4}[\s\-.]?\d{3,5}(?!\d)'
     )),

    ("URL", "Contact Information",
     re.compile(r'https?://[^\s<>"\']+|www\.[^\s<>"\']+')),

    # ── Government / Case IDs ────────────────────────────────────────────
    ("SSN", "Government ID",
     re.compile(r'\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b')),

    ("PASSPORT", "Government ID",
     re.compile(r'\b[A-Z]{1,2}\d{6,9}\b')),

    ("NATIONAL_ID", "Government ID",
     re.compile(r'\b(?:ID|NIC|CNIC|Passport|DL|License)\s*(?:No\.?|Number|#)?\s*[:\-]?\s*[A-Z0-9\-]{6,20}\b',
                re.IGNORECASE)),

    ("CASE_NUMBER", "Case / Legal ID",
     re.compile(
         r'\b(?:Case|Docket|File|Matter|Cause|Claim|Index|Ref(?:erence)?|No\.?|CR|CV|CIV|CRIM|ADM)'
         r'[\s.\-#:]*\d{1,6}[\s\-/]*(?:\d{2,4})?(?:[\s\-/][A-Z]{1,5})?\b',
         re.IGNORECASE)),

    ("CONTRACT_NUM", "Case / Legal ID",
     re.compile(r'\b(?:Contract|Agreement|Order|Invoice|PO|SO)[\s.\-#:]*[A-Z0-9]{3,15}\b',
                re.IGNORECASE)),

    # ── Financial ────────────────────────────────────────────────────────
    ("CREDIT_CARD", "Financial",
     re.compile(r'\b(?:\d{4}[\s\-]?){3}\d{4}\b')),

    ("BANK_ACCOUNT", "Financial",
     re.compile(r'\b(?:Account|Acct|A/C)\s*(?:No\.?|Number|#)?\s*[:\-]?\s*\d{6,18}\b', re.IGNORECASE)),

    ("IBAN", "Financial",
     re.compile(r'\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b')),

    ("ROUTING", "Financial",
     re.compile(r'\b(?:ABA|Routing|Sort Code)[\s.\-#:]*\d{8,9}\b', re.IGNORECASE)),

    ("CURRENCY_AMOUNT", "Financial",
     re.compile(
         r'(?:USD|PKR|GBP|EUR|Rs\.?|INR|\$|£|€)\s*\d{1,3}(?:,\d{3})*(?:\.\d{2})?'
         r'|\d{1,3}(?:,\d{3})*(?:\.\d{2})?\s*(?:USD|PKR|GBP|EUR|rupees?|dollars?|pounds?)',
         re.IGNORECASE)),

    ("TAX_ID", "Financial",
     re.compile(r'\b(?:TIN|EIN|VAT|GST|NTN|STRN|Tax\s*ID)[\s.\-#:]*[A-Z0-9\-]{5,20}\b',
                re.IGNORECASE)),

    # ── Dates ────────────────────────────────────────────────────────────
    ("DATE", "Temporal",
     re.compile(
         r'\b\d{1,2}[\/\-\.]\d{1,2}[\/\-\.]\d{2,4}\b'
         r'|\b(?:January|February|March|April|May|June|July|August|September|October|November|December)'
         r'\s+\d{1,2},?\s+\d{4}\b'
         r'|\b\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\.?\s+\d{4}\b',
         re.IGNORECASE)),

    # ── Addresses ────────────────────────────────────────────────────────
    ("ADDRESS_STREET", "Address",
     re.compile(
         r'\d{1,5}\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,3}'
         r'\s+(?:Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl)\b',
         re.IGNORECASE)),

    ("ZIP_CODE", "Address",
     re.compile(r'\b\d{5}(?:[-\s]\d{4})?\b|\b[A-Z]{1,2}\d{1,2}[A-Z]?\s*\d[A-Z]{2}\b')),

    # ── Personal Names (heuristic – spaCy is better for this) ───────────
    ("HONORIFIC_NAME", "Personal Name",
     re.compile(
         r'\b(?:Mr\.?|Mrs\.?|Ms\.?|Miss|Dr\.?|Prof\.?|Advocate|Adv\.?|Counsel|Esq\.?)'
         r'\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,2}\b'
     )),

    # ── Confidential legal clauses ───────────────────────────────────────
    ("CONFIDENTIAL_CLAUSE", "Confidential Clause",
     re.compile(
         r'\b(?:CONFIDENTIAL|PRIVILEGED|ATTORNEY[-\s]CLIENT|WORK\s+PRODUCT'
         r'|TRADE\s+SECRET|PROPRIETARY|DO\s+NOT\s+DISCLOSE'
         r'|PRIVATE\s+AND\s+CONFIDENTIAL)\b',
         re.IGNORECASE)),

    # ── Signatures / initials ────────────────────────────────────────────
    ("SIGNATURE", "Signature",
     re.compile(r'\b(?:Signed?|Signature|Initials?|Witnessed?\s+by|Executed\s+by)\s*:?\s*[A-Z][^\n]{1,50}',
                re.IGNORECASE)),

    # ── IP addresses ─────────────────────────────────────────────────────
    ("IP_ADDRESS", "Technical Identifier",
     re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')),
]


# ---------------------------------------------------------------------------
# PII Detection
# ---------------------------------------------------------------------------

class PIIMatch:
    """Represents a single detected PII occurrence."""
    def __init__(self, pii_type: str, category: str, text: str,
                 start: int, end: int, page: int, source: str):
        self.pii_type = pii_type
        self.category = category
        self.text = text
        self.start = start
        self.end = end
        self.page = page
        self.source = source  # "regex" or "spacy"


def detect_pii_in_text(text: str, page_num: int = 0) -> List[PIIMatch]:
    """Run all detectors on a block of text and return non-overlapping matches."""
    matches: List[PIIMatch] = []

    # 1. spaCy NER (if available)
    if SPACY_AVAILABLE:
        doc = nlp(text)
        spacy_labels = {
            "PERSON": ("PERSON", "Personal Name"),
            "ORG": ("ORGANIZATION", "Organization"),
            "GPE": ("LOCATION", "Address"),
            "LOC": ("LOCATION", "Address"),
            "MONEY": ("CURRENCY_AMOUNT", "Financial"),
            "DATE": ("DATE", "Temporal"),
            "TIME": ("TIME", "Temporal"),
            "CARDINAL": None,   # skip bare numbers
            "LAW": ("LEGAL_REF", "Legal Reference"),
        }
        for ent in doc.ents:
            mapping = spacy_labels.get(ent.label_)
            if mapping:
                matches.append(PIIMatch(
                    pii_type=mapping[0],
                    category=mapping[1],
                    text=ent.text,
                    start=ent.start_char,
                    end=ent.end_char,
                    page=page_num,
                    source="spacy"
                ))

    # 2. Regex patterns
    for pii_type, category, pattern in PATTERNS:
        for m in pattern.finditer(text):
            matches.append(PIIMatch(
                pii_type=pii_type,
                category=category,
                text=m.group(),
                start=m.start(),
                end=m.end(),
                page=page_num,
                source="regex"
            ))

    # 3. Remove overlapping matches (keep longest)
    matches.sort(key=lambda x: (x.start, -(x.end - x.start)))
    non_overlap: List[PIIMatch] = []
    last_end = -1
    for m in matches:
        if m.start >= last_end:
            non_overlap.append(m)
            last_end = m.end

    return non_overlap


# ---------------------------------------------------------------------------
# PDF Redaction (PyMuPDF)
# ---------------------------------------------------------------------------

def redact_pdf(input_path: str, output_path: str) -> Tuple[List[Dict], int]:
    """
    Open a PDF, detect PII on every page, apply black-box redaction,
    and save to output_path.

    Returns (audit_records, total_redactions).
    """
    if not PYMUPDF_AVAILABLE:
        raise RuntimeError(
            "PyMuPDF (fitz) is not installed. "
            "Run: pip install pymupdf"
        )

    doc = fitz.open(input_path)
    audit: List[Dict] = []
    total = 0

    for page_num, page in enumerate(doc, start=1):
        text = page.get_text("text")
        pii_matches = detect_pii_in_text(text, page_num)

        for match in pii_matches:
            # Search for the text on the actual page (handles layout)
            areas = page.search_for(match.text)
            for rect in areas:
                # Draw filled black rectangle
                page.add_redact_annot(rect, fill=(0, 0, 0))
                audit.append({
                    "page": page_num,
                    "pii_type": match.pii_type,
                    "category": match.category,
                    "redacted_text": match.text,
                    "detection_method": match.source,
                    "timestamp": datetime.now().isoformat(timespec="seconds"),
                })
                total += 1

        page.apply_redactions()

    doc.save(output_path, garbage=4, deflate=True)
    doc.close()
    return audit, total


# ---------------------------------------------------------------------------
# Text-only redaction (fallback when PyMuPDF not available)
# ---------------------------------------------------------------------------

def redact_text_only(text: str) -> Tuple[str, List[Dict]]:
    """Replace PII in plain text with [TYPE] tokens. Used for preview."""
    matches = detect_pii_in_text(text, page_num=1)
    audit = []
    # Replace from end to start so offsets stay valid
    chars = list(text)
    for m in reversed(matches):
        replacement = f"[{m.pii_type}]"
        chars[m.start:m.end] = list(replacement)
        audit.append({
            "page": 1,
            "pii_type": m.pii_type,
            "category": m.category,
            "redacted_text": m.text,
            "detection_method": m.source,
            "timestamp": datetime.now().isoformat(timespec="seconds"),
        })
    return "".join(chars), list(reversed(audit))


# ---------------------------------------------------------------------------
# Audit CSV / Summary helpers
# ---------------------------------------------------------------------------

def audit_to_csv(audit: List[Dict]) -> str:
    """Convert audit records to CSV string."""
    if not audit:
        return "page,pii_type,category,redacted_text,detection_method,timestamp\n"
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=audit[0].keys())
    writer.writeheader()
    writer.writerows(audit)
    return output.getvalue()


def audit_summary(audit: List[Dict]) -> Dict:
    """Summarise audit records by category."""
    summary: Dict[str, int] = {}
    for record in audit:
        cat = record["category"]
        summary[cat] = summary.get(cat, 0) + 1
    return summary
