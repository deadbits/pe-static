[![Say Thanks](https://img.shields.io/badge/Say%20Thanks-!-1EAEDB.svg?style=flat)](https://saythanks.io/to/deadbits)

# pe-static
Stand-alone Python script for static file analysis for PE files

Table of Contents
=================
* [Description](#description)
* [Features](#features)
* [Installation](#installation)

## Description
This project comes as a greatly updated version of [getstatic-mini.py](https://github.com/deadbits/malware-analysis-scripts/blob/master/getstatic-mini.py). The output provides a quick statis analysis of a single PE file or an entire directory of files to stdout or optionally saved into a specified output directory. 

I personally use this script almost daily during personal and professional research to quickly extract important information to determine if further analysis is needed, such as sandboxing, unpacking, or dynamic analysis. Sometimes the report is just the information I need and can start writing my report or blog or signature. Hopefully it helps you do the same!

## Features
Execution displays a prettytable formatted report of the following (items marked with * are optional):
- File name
- File size
- File hashes (MD5, SHA1, SHA256, SSDeep, peHash, imphash)
- Compilation Time
   - Is this time in the distant past or a future data?
- Entry Point
- Start Address
- PE Sections
    - Name
    - Size
    - Address
    - Entropy
- Security Features *
    - SEH
    - ASLR
    - DEP
- Extract suspicious strings *
    - URLs
    - Domain names
    - IP Addresses
    - Email Addresses
- Suspicious Imports *
    - Imports commonly used in malware
- Check if PE is likely packed
- Embedded Files *
   - Leverages hachoir-subfile
- Yara Signatures *
   - Handful of common built-in signatures
   - Supply your own signature set
- VirusTotal
   - Get report from VirusTotal for files (requires public API key)
   - Submit file to VirusTotal
       - You can re-run the script against the same file to retrieve the report once VT has analyzed it

## Installation
1. git clone https://github.com/deadbits/pe-static
2. cp pe-static/pe-static.py /usr/local/sbin/pe-static && chmod +x /usr/local/sbin/pe-static
3. run it!
