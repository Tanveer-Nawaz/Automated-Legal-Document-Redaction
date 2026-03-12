# LexRedact — Automated Legal Document Redaction

**Team Alpha Internship Project**

A Flask-based web application that automatically detects and redacts sensitive PII from legal PDF documents using spaCy NER + comprehensive legal regex patterns, producing redacted PDFs with black-box masking and full CSV audit logs.

---

## Features

- **Upload** any legal PDF via drag-and-drop or file picker
- **Detect** 18+ categories of PII: names, addresses, emails, phone numbers, case numbers, SSNs, financial data, dates, confidential clauses, signatures, and more
- **Redact** with classic black-box masking directly on the PDF
- **Download** the redacted PDF + a full CSV audit log (page, type, original text, timestamp)
- **Dual detection engine**: spaCy NER (contextual) + regex (structured patterns)
- **Audit report** page with statistics and category breakdown

---

## Quick Start

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Download spaCy model
```bash
python -m spacy download en_core_web_sm
```

### 3. Run the app
```bash
python app.py
```

### 4. Open your browser
```
http://localhost:5000
```

---

## Project Structure

```
legal_redactor/
├── app.py              # Flask routes & job management
├── redactor.py         # Core PII detection engine
├── requirements.txt    # Python dependencies
├── templates/
│   ├── index.html      # Upload page
│   └── result.html     # Audit report page
├── uploads/            # Temporary input storage (auto-created)
└── outputs/            # Redacted PDFs & CSVs (auto-created)
```

---

## PII Categories Detected

| Category | Examples |
|---|---|
| Personal Name | Mr. John Smith, Dr. Sarah Khan |
| Government ID | SSN, CNIC, Passport No., Driver's License |
| Case / Legal ID | Case No. CR-2024-001, Docket #5523 |
| Contact Info | email@domain.com, +1-555-1234 |
| Address | 123 Main Street, SW1A 1AA |
| Financial | Account No., IBAN, credit cards, currency amounts |
| Tax ID | TIN, EIN, NTN, VAT, GST |
| Dates | All formats: MM/DD/YYYY, 12 Jan 2024, etc. |
| Confidential Clause | ATTORNEY-CLIENT, WORK PRODUCT, TRADE SECRET |
| Signature | "Signed by:", "Executed by:" |
| IP Address | Internal/technical identifiers |

---

## Detection Method

1. **spaCy NER** (`en_core_web_sm` or `en_core_web_md`):
   - Detects PERSON, ORG, GPE, MONEY, DATE, LAW entities contextually
   - Handles ambiguous names better than regex

2. **Legal Regex Patterns** (18 patterns):
   - Structured PII: SSN, IBAN, phone numbers, credit cards, case numbers
   - Legal-specific: contract numbers, confidential clauses, signatures

Both engines run in parallel; overlapping matches are deduplicated (longest match wins).

---

## Evaluation Metrics (as per project spec)

The system can be evaluated on:
- **Redaction Accuracy** — % of actual PII correctly redacted
- **False Omission Rate** — % of PII missed
- **False Redaction Rate** — % of non-PII incorrectly redacted
- **Contextual Integrity** — readability of remaining document content

---

## Tech Stack

- **Backend**: Python 3.10+, Flask
- **PDF Processing**: PyMuPDF (fitz)
- **NLP**: spaCy en_core_web_sm
- **Pattern Matching**: Python `re` (18 legal patterns)
- **Frontend**: Vanilla HTML/CSS/JS (no framework needed)
- **Reports**: CSV via Python stdlib

---

## Extending the System

To add new PII patterns, open `redactor.py` and add a tuple to the `PATTERNS` list:

```python
("MY_PATTERN", "My Category",
 re.compile(r'your-regex-here', re.IGNORECASE)),
```

To use a larger spaCy model for better accuracy:
```bash
python -m spacy download en_core_web_lg
# Then update in redactor.py: spacy.load("en_core_web_lg")
```

---

## Notes for Presentation

- The system handles **over-redaction** vs **under-redaction** tradeoff by using context-aware spaCy NER alongside strict regex
- The **audit log** satisfies legal compliance requirements for documenting what was redacted
- The **fallback mode** (regex only) ensures the system works even without GPU/heavy models
- This architecture is production-ready and can scale to thousands of pages with batch processing
