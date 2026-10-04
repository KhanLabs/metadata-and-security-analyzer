Metadata and Security Analyzer

A desktop application that helps you remove hidden metadata from files and check them for security threats.

What it does

Extracts and displays metadata from images, PDFs, and Office documents
Removes sensitive metadata (author names, GPS locations, edit history, etc.)
Detects file extension spoofing (e.g., an .exe disguised as .pdf)
Finds VBA macros in Office files
Optional malware scanning via VirusTotal

Requirements

Python 3.8 or higher
Windows, macOS, or Linux

Setup

Download or clone all the source files into a folder

Open a terminal/command prompt in that folder

Install the required libraries:
   pip install -r requirements.txt

   If you get a permission error on Linux/Mac, try:
   pip install -r requirements.txt --break-system-packages

(Optional) Add your VirusTotal API key:
   - Open config.py
   - Replace the API key with your own from virustotal.com
   - This is only needed if you want to scan files for malware

Running the Application

Just run:
python main.py

The application window will open.

How to Use

Click Import File and select any file you want to analyze

The app will show you:
   - File information (size, type, extension)
   - Any metadata found
   - Whether macros were detected
   - Overall risk status (green = safe, red = high risk)

To remove metadata, click Remove Metadata

To save a clean copy, click Export Safe File

If the file extension doesn't match the actual file type, click Fix Extension

To scan for malware (requires internet), click Scan with VirusTotal

Supported File Types

Images: JPEG, PNG
Documents: PDF, DOCX, PPTX, XLSX

Files Included

main.py - Starts the application
gui.py - The user interface
logic.py - All the analysis and cleaning functions
config.py - Settings (API key, file size limit)
requirements.txt - List of required Python libraries

Troubleshooting

"No module named tkinter"
On Ubuntu/Debian: sudo apt install python3-tk
On Mac: Tkinter comes with Python, try reinstalling Python from python.org

"No module named magic"
On Windows: pip install python-magic-bin
On Ubuntu: sudo apt install libmagic1
On Mac: brew install libmagic

Application won't start
Make sure you're using Python 3.8+
Check that all files are in the same folder
Try running pip install -r requirements.txt again

Notes

Your original files are never modified. The app works on temporary copies.
All processing happens locally on your computer (except VirusTotal scanning).
Logs are saved in the logs folder for debugging.

Developed by Mueed Ali Khan as a final year project for the B.Eng Software Engineering degree at the University of Greater Manchester.