# File Metadata & Security Analyzer

A desktop tool that inspects files for hidden metadata and basic security risks, then lets you strip what shouldn't be shared.

This was my final year project for the B.Eng Software Engineering degree at the University of Greater Manchester (module SWE6010).

## Why

Most files carry more than what you see. Office documents can hold author names, company names, edit history and comments. Photos can hold the camera's serial number and the GPS location where they were taken. Office files can also hide VBA macros that run code when the file is opened.

People share files every day without knowing any of this is attached. That is how names, locations and internal details end up where they were never meant to be. Document metadata has been at the center of real data-protection incidents; the 2003 UK government "dodgy dossier" is a well-known example.

This tool makes that risk visible and fixable: it shows what a file is carrying, flags anything that looks dangerous (a fake file extension, hidden macros), and produces a clean copy.

## What it does

- Shows the metadata in images (JPEG, PNG), PDFs and Office documents (DOCX, PPTX, XLSX), including photo GPS location, date taken and camera serial number
- Removes that metadata and exports a clean copy
- Detects fake file extensions, for example an `.exe` renamed to `.pdf`, by checking the file's content instead of trusting its name
- Scans Office files for VBA macros
- Optional malware scan with the VirusTotal API
- Never changes your original file: all analysis and cleaning runs on a temporary copy

## Requirements

- Python 3.8 or newer
- Windows, macOS or Linux

## Setup

All source files are in `Source Code/`.

```bash
cd "Source Code"
pip install -r requirements.txt
```

On macOS and Linux, install libmagic first (Windows does not need this):

- Ubuntu/Debian: `sudo apt install libmagic1`
- macOS: `brew install libmagic`

To turn on malware scanning, get a free API key from [virustotal.com](https://www.virustotal.com) and put it in `Source Code/config.py`:

```python
VIRUSTOTAL_API_KEY = "your-key-here"
```

This step is optional. Everything except the VirusTotal scan works fully offline.

## Running it

```bash
cd "Source Code"
python main.py
```

1. **Import File**: pick a file to analyze.
2. The app shows the file details, any metadata found, the macro check and an overall risk status.
3. **Remove Metadata** cleans the imported copy. **Export Safe File** saves a cleaned copy where you choose.
4. **Fix Extension** renames the copy when its extension does not match the real file type.
5. **Scan with VirusTotal** uploads the file for a malware scan. This needs internet and an API key, and the app asks before uploading.

## Project structure

| File | Responsibility |
|---|---|
| `Source Code/main.py` | Entry point and logging setup |
| `Source Code/gui.py` | Tkinter interface |
| `Source Code/logic.py` | Metadata extraction, macro detection and file cleaning |
| `Source Code/config.py` | Settings (API key, max file size) |

## Known limitations

- For Office files it removes the document properties (author, company, dates, custom fields and so on). It does not remove names inside the document itself, such as tracked changes or comment authors.
- Cleaning a PDF keeps its pages but drops bookmarks and form data.
- Cleaning an image saves it again, so JPEG photos are re-compressed at high quality.
- Other file types are shown and checked, but exported as they are.

## Troubleshooting

- **"No module named tkinter"**: on Ubuntu/Debian run `sudo apt install python3-tk`. On macOS, install Python from python.org.
- **"failed to find libmagic"**: install libmagic as shown in Setup.
- **App won't start**: check you are on Python 3.8 or newer and run `pip install -r requirements.txt` again.

## Author

Mueed Ali Khan, B.Eng Software Engineering, University of Greater Manchester

## License

MIT. See [LICENSE](LICENSE).
