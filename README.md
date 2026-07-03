\# Basic Antivirus Simulation Using Python



A safe, educational Python project that demonstrates how a signature-based antivirus scanner works.



\## Project Overview



This project scans files inside a selected folder, calculates their SHA-256 hashes, and compares those hashes with a known malware signature database.



If a file hash matches a signature, the file is flagged as malicious and moved to a quarantine folder. A scan report is also generated automatically.



> Note: This project is made for educational and ethical purposes only. It does not use or detect real malware unless real signatures are added.



\## Features



\- Scans files inside the `test\_files` folder

\- Calculates SHA-256 hashes of files

\- Compares hashes with a malware signature database

\- Detects known malicious file signatures

\- Moves detected files to a `quarantine` folder

\- Generates a detailed `scan\_report.txt`

\- Handles duplicate quarantine filenames safely



\## Technologies Used



\- Python 3

\- `hashlib`

\- `os`

\- `shutil`

\- `datetime`



\## Project Structure



```text

Basic-Antivirus-Simulation/

│

├── antivirus\_scanner.py

├── malware\_signatures.txt

├── scan\_report.txt

├── README.md

│

├── test\_files/

│   └── normal\_notes.txt

│

├── quarantine/

│   └── sample\_malware.txt

│

└── screenshots/

