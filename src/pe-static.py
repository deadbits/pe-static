#!/usr/bin/env python
##
# get-static.py (2018 updated version of getstatic-mini.py)
# https://github.com/deadbits
# author: adam m. swanda
#
# Description:
#   Quickly perform static analysis of PE files for a individual file or
#   an entire directory of samples. The output is displayed to stdout in
#   a nicely formatted way that I use in my research workflow and sometimes
#   directly in malware analysis reports.
#
# Analysis Provided:
#   file:         name, type, size, compiled time, compiled architecture, entropy
#                 entry point, start address, PE sections (names, sizes, address),
#
#   hash:         md5, sha1, sha256, ssdeep, peHash, imphash
#
#   interesting:  strings (urls, filenames, email addresses),
#                 suspicious imports, sections entropy,
#                 embedded files (via hachoir-subfile)
#
# Installation & Usage:
#   Save this file to /usr/local/sbin as "get-static" and run "chmod +x /usr/local/sbin/get-static"
#   Assuming /usr/local/sbin is in your shells PATH, you can now simply run this script from anywhere
#
#   show detailed help information
#   $ get-static --help
#
#   scan a single file or entire directory with default options
#   $ get-static -f sample.exe
#   $ get-static -d ~/malware/samples/2018/hancitor/
#
#   scan a single file or entry directory with all the features
#   $ get-static -f sample.exe --subfile --interesting
##

import os
import re
import bz2
import sys
import json
import time
# import math
import string
import hashlib
import argparse
import commands
import platform
import requests
import bitstring

from datetime import datetime

from collections import OrderedDict

from prettytable import PrettyTable

try:
    import pefile
except ImportError:
    print 'error: python library pefile is required\nrun `pip install pefile` to install.'
    sys.exit(1)

try:
    import yara
except ImportError:
    print 'error: python library yara is required\nrun `pip install yara` to install.'
    sys.exit(1)


def exit_error(message):
    print '[fatal] %s'
    sys.exit(1)


def check_path(file_path):
    # make sure we are looking at a valid file before doing anything else
    if not os.path.exists(file_path):
        exit_error('[error] path %s does not exist. you had one job!' % path)
    if not os.path.isfile(file_path):
        exit_error('[error] path %s is not even a file... what is it you\'re trying to do here?' % path)
    if os.path.getsize(file_path) == 0:
        exit_error('[error] path %s has a size of zero. why are you making me analyze this?' % path)


def get_hash(file_path, hash_type):
    # return hash of file path by given type
    fin = open(file_path, 'rb')
    if hash_type == 'md5':
        m = hashlib.md5()
    elif hash_type == 'sha1':
        m = hashlib.sha1()
    elif hash_type == 'sha256':
        m = hashlib.sha256()
    while True:
        data = fin.read(8192)
        if not data:
            break
        m.update(data)
    return m.hexdigest()


class VT(object):
    def __init__(self, api_key, file_hash):
        self.report_url = 'https://www.virustotal.com/vtapi/v2/file/report'
        self.api_key = api_key
        self.file_hash = file_hash


    def get_report(self):
        results = {}

        try:
            req = requests.post(self.report_url, data={'resource': self.file_hash, 'apikey': self.api_key})
            if req.status_code == 200:
                jdata = req.json()
            else:
                return results
        except Exception as err:
            print '[error] failed to retrieve VT report (status: %s) (hash: %s) (error: %s)' % (req.status_code, self.file_hash, str(err))
            return results

        if not jdata.get('response_code'):
            results['results'] = {'error': 'file has not yet been scanned by VirusTotal'}
        else:
            results['results'] = {
                'scan_date': jdata.get('scan_date'),
                'permalink': jdata.get('permalink'),
                'positives': jdata.get('positives', 0),
                'scans': []
            }

            for av_engine, sig in jdata.get('scans', {}).items():
                results['scans'][av_engine.replace('.', '_')] = sig

        return results



class Static(object):
    def __init__(self, file_name, subfile=False, sections=False, strings=False, scan_yara=False, outfile=None):
        self.file_name = file_name
        self.pe = pefile.PE(self.file_name)
        self.output_file = outfile
        self.results = None
        self.actions = {
            'subfile': subfile,
            'sections': sections,
            'strings': strings,
            'yara': scan_yara
        }


    def is_executable(self):
        # really poor way to check if a file is a PE file
        # @todo: change this to use magic, Yara or TrID... anything but this.
        out = commands.getoutput('file -b %s' % file_name)
        if 'PE' in out and 'executable' in out:
            return True
        return False

    def get_subfile(self):
        # parse hachoir-subfile output to check for embedded files
        out = commands.getoutput('hachoir-subfile %s' % self.file_name)
        if len(out.splitlines()) > 5:
            for l in out.splitlines():
                if 'File at' in l:
                    if 'File at 0 size=' not in l:
                        self.results['Subfile'] = l
                        print '** hachoir-subfile **'


    def get_ssdeep(self):
        # try to return the ssdeep hash of file
        try:
            from ssdeep import ssdeep
            ss = ssdeep()
            return ss.hash_file(self.file_name)
        except ImportError:
            try:
                import ssdeep
                self.results['SSDeep'] = ssdeep.hash_from_file(self.file_name)
            except ImportError:
                print '[error] no library `ssdeep` available for import! this feature will not be available.'
                pass


    def grep_saddress(self):
        # parse objdump output to get start address of file
        out = commands.getoutput('%s -x %s | grep "start address"' % (objdump, self.file_name))
        if out != '\n':
            try:
                self.results['Start Address'] = out.split('start address')[1]
            except IndexError:
                pass
        self.results['Start Address'] = 'Not Found'


    def get_interesting_strings(self):
        # return dictionary of interesting strings found in file
        url_re = ur'(?i)\b((?:http[s]?:(?:/{1,3}|[a-z0-9%])|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:\'".,<>?«»“”‘’]))'
        file_re = r'\b([\w,%-.]+\.[A-Za-z]{3,4})\b'
        email_re = r'((?:(?:[A-Za-z0-9]+_+)|(?:[A-Za-z0-9]+\-+)|(?:[A-Za-z0-9]+\.+)|(?:[A-Za-z0-9]+\++))*[A-Za-z0-9]+@(?:(?:\w+\-+)|(?:\w+\.))*\w{1,63}\.[a-zA-Z]{2,6})'
        out = commands.getoutput('strings %s' % self.file_name)
        if out != '\n':
            url_p = re.compile(url_re, re.IGNORECASE)
            file_p = re.compile(file_re, re.IGNORECASE)
            email_p = re.compile(email_re, re.IGNORECASE)

            try:
                self.results['Interesting Strings'] = {'URLs': url_p.findall(out)}
                self.results['Interesting Strings'] = {'Files': file_p.findall(out)}
                self.results['Interesting Strings'] = {'Emails': email_p.findall(out)}
            except Exception as err:
                print '[error] caught exception parsing strings (%s)' % str(err)
                pass


    def get_pehash(self):
        # compute peHash (https://www.usenix.org/legacy/events/leet09/tech/full_papers/wicherski/wicherski_html/index.html)
        img_chars = bitstring.BitArray(hex(self.pe.FILE_HEADER.Characteristics))
        img_chars = bitstring.BitArray(bytes=img_chars.tobytes())
        img_chars_xor = img_chars[0:8] ^ img_chars[8:16]
        pehash_bin = bitstring.BitArray(img_chars_xor)

        sub_chars = bitstring.BitArray(hex(self.pe.FILE_HEADER.Machine))
        sub_chars = bitstring.BitArray(bytes=sub_chars.tobytes())
        sub_chars_xor = sub_chars[0:8] ^ sub_chars[8:16]
        pehash_bin.append(sub_chars_xor)

        stk_size = bitstring.BitArray(hex(self.pe.OPTIONAL_HEADER.SizeOfStackCommit))
        stk_size_bits = string.zfill(stk_size.bin, 32)
        stk_size = bitstring.BitArray(bin=stk_size_bits)
        stk_size_xor = stk_size[8:16] ^ stk_size[16:24] ^ stk_size[24:32]
        stk_size_xor = bitstring.BitArray(bytes=stk_size_xor.tobytes())
        pehash_bin.append(stk_size_xor)

        hp_size = bitstring.BitArray(hex(self.pe.OPTIONAL_HEADER.SizeOfHeapCommit))
        hp_size_bits = string.zfill(hp_size.bin, 32)
        hp_size = bitstring.BitArray(bin=hp_size_bits)
        hp_size_xor = hp_size[8:16] ^ hp_size[16:24] ^ hp_size[24:32]
        hp_size_xor = bitstring.BitArray(bytes=hp_size_xor.tobytes())
        pehash_bin.append(hp_size_xor)

        for section in self.pe.sections:
            sect_va = bitstring.BitArray(hex(section.VirtualAddress))
            sect_va = bitstring.BitArray(bytes=sect_va.tobytes())
            sect_va_bits = sect_va[8:32]
            pehash_bin.append(sect_va_bits)

            sect_rs = bitstring.BitArray(hex(section.SizeOfRawData))
            sect_rs = bitstring.BitArray(bytes=sect_rs.tobytes())
            sect_rs_bits = string.zfill(sect_rs.bin, 32)
            sect_rs = bitstring.BitArray(bin=sect_rs_bits)
            sect_rs = bitstring.BitArray(bytes=sect_rs.tobytes())
            sect_rs_bits = sect_rs[8:32]
            pehash_bin.append(sect_rs_bits)

            sect_chars = bitstring.BitArray(hex(section.Characteristics))
            sect_chars = bitstring.BitArray(bytes=sect_chars.tobytes())
            sect_chars_xor = sect_chars[16:24] ^ sect_chars[24:32]
            pehash_bin.append(sect_chars_xor)

            address = section.VirtualAddress
            size = section.SizeOfRawData
            raw = self.pe.write()[address + size:]

            if size == 0:
                kc = bitstring.BitArray(float=1, length=32)
                pehash_bin.append(kc[0:8])
                continue

            bz2_raw = bz2.compress(raw)
            bz2_size = len(bz2_raw)

            k = bz2_size / size
            kc = bitstring.BitArray(float=k, length=32)
            pehash_bin.append(kc[0:8])

        m = hashlib.sha1()
        m.update(pehash_bin.tobytes())

        self.results['peHash'] = m.hexdigest()


    def get_sections(self):
        # get all section names, address, and size of data
        self.results['Sections'] = [{
            'Name': section.Name.replace('\x00', ''),
            'Address': hex(section.VirtualAddress),
            'Virtual Size': hex(section.Misc_VirtualSize),
            'Raw Data Size': section.SizeOfRawData} for section in self.pe.sections]

        # for section in self.pe.sections:
        #    self.results['Sections'] = []
        #
        #    append(
        #        (section.Name.replace('\x00', ''),
        #        hex(section.VirtualAddress),
        #        hex(section.Misc_VirtualSize),
        #        section.SizeOfRawData)
        #    )


    def get_tls_sections(self):
        # check for TLS sections and return the number found
        ct = 0

        if not hasattr(self.pe, 'DIRECTORY_ENTRY_TLS') and not self.pe.DIRECTORY_ENTRY_TLS:
            return ct

        if self.pe.DIRECTORY_ENTRY_TLS.struct and self.pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks:
            callback_array_rva = self.pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks - self.pe.OPTIONAL_HEADER.ImageBase

            while True:
                func = self.pe.get_dword_from_data(self.pe.get_data(callback_array_rva + 4 * ct, 4), 0)
                if func == 0:
                    break
                ct += 1

        self.results['TLS Sections'] = ct


    def get_timestamp(self):
        suspicious = ''
        timestamp = self.pe.FILE_HEADER.TimeDateStamp

        if timestamp == 0:
            return 'Not Found'

        timestamp_fmt = datetime.utcfromtimestamp(int(timestamp)).strftime('%Y-%m-%d %H:%M:%S')
        if (timestamp_fmt < 946692000):
            suspicious = '(Suspicious: Old timestamp)'
        elif (timestamp_fmt > time.time()):
            suspicious = '(Suspicious: Future timestamp)'

        answer = '%s %s' % (datetime.fromtimestamp(timestamp), suspicious)
        self.results['Compiled'] = answer


    def get_security(self):
        # check file for ASLR, DEP, and SEH features
        features = []

        if self.pe.OPTIONAL_HEADER.DllCharacteristics > 0:
            if self.pe.OPTIONAL_HEADER.DllCharacteristics & 0x0040:
                features.append('ASLR')

            if self.pe.OPTIONAL_HEADER.DllCharacteristics & 0x0100:
                features.append('DEP')

            if (self.pe.OPTIONAL_HEADER.DllCharacteristics & 0x0400 or (hasattr(self.pe, "DIRECTORY_ENTRY_LOAD_CONFIG") and
                    self.pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.SEHandlerCount > 0 and
                    self.pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.SEHandlerTable != 0) or
                    self.pe.FILE_HEADER.Machine == 0x8664):
                features.append('SEH')

        self.results['Security'] = ' '.join(features)


    def scan(self):
        # start analysis with basic info
        self.results = OrderedDict([
            ('MD5', get_hash(self.file_name, 'md5')),
            ('SHA1', get_hash(self.file_name, 'sha1')),
            ('SHA256', get_hash(self.file_name, 'sha256')),
            ('Type', commands.getoutput('file -b %s' % self.file_name)),
            ('Size', (os.path.getsize(self.file_name)) / 1000),
            ('SSDeep', self.get_ssdeep(self.file_name)),
            ('PEHash', self.get_pehash(self.pe)),
            ('ImpHash', self.pe.get_imphash()),
            ('Arch', pefile.MACHINE_TYPE[self.pe.FILE_HEADER.Machine]),
            ('Entry Point', hex(self.pe.OPTIONAL_HEADER.AddressOfEntryPoint)),
            ('Sections', self.pe.FILE_HEADER.NumberOfSections),
            ('TLS Sections', self.get_tls_sections(self.pe)),
            ('Security', self.get_security(self.pe)),
            ('Compiled', self.get_timestamp(self.pe)),
            ('Start Address', self.grep_saddress(self.file_name))
        ])

        if self.actions['subfile']:
            print '\n'
            self.results['Subfile'] = self.check_subfile(file_name)

        if self.actions['interesting']:
            self.results['Strings'] = self.get_interesting_strings(self.file_name)

        if self.actions['yara']:
            pass


def create_output(file_path):
    if not os.path.exists(file_path):
        try:
            os.makedirs(file_path)
        except OSError as err:
            exit_error('failed to create output directory %s (%s)' % (file_path, str(err)))
        except Exception as err:
            exit_error('failed to create output directory %s (%s)' % (file_path, str(err)))


def print_output(results):
    pass


def store_output(results, output_path):
    pass


def main(data, actions, output):
    results = Static(actions)

    if output['type'] == 'stdout':
        print_output(results)

    elif output['type'] == 'text':
        store_output(results, output['path'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='perform static analysis against an individual executable or an entire directory of executables')

    parser.add_argument('-f', '--file',
        help='individual file name to assess',
        action='store')

    parser.add_argument('-d', '--dir',
        help='scan every file in directory',
        action='store')

    parser.add_argument('--yara',
        help='scan file with built-in yara rules',
        action='store_true',
        default=False)

    parser.add_argument('--yaracustom',
        help='scan file with custom yara rules in this path',
        action='store')

    parser.add_argument('--subfile',
        help='run hachoir-subfile',
        action='store_true',
        default=False)

    parser.add_argument('-s', '--sections',
        help='display section names with address and size',
        action='store_true',
        default=False)

    parser.add_argument('-i', '--interesting',
        help='search strings for URLs, filenames, and email addresses',
        action='store_true',
        default=False)

    parser.add_argument('--vtreport',
        help='retrieve virustotal report if available',
        action='store_true',
        default=False)

    parser.add_argument('--vtsubmit',
        help='submit file to virustotal (requires API key in ~/.vtapi)',
        action='store_true',
        default=False)

    parser.add_argument('-o', '--output',
        help='select output type of "stdout" or "text" (default to stdout)',
        action='store',
        default='stdout')

    parser.add_argument('-o', '--outpath',
        help='if using --output text, you must specify a file path to save results',
        action='store',
        default='./static_%s.txt' % datetime.utcfromtimestamp(time.time()).strftime('%d-%M-%y_%H:%M:%S'))

    args = parser.parse_args()

    if platform.system() == 'Darwin':
        objdump = 'gobjdump'
    elif platform.system() == 'Linux':
        objdump = 'objdump'
    else:
        exit_error('script only runs on macOS or Linux')

    get_sections = args.sections
    get_interesting = args.interesting

    string_msg = 'output file for strings already exists. choose another filename.'
    output_file = args.savestrings if not os.path.exists(args.savestrings) else exit_error(string_msg)

    if args.dir:
        if args.file:
            exit_error('the flags --file and --dir may not be used together.\nwhy would you even try that?')
            sys.exit(1)

        check_path(args.dir)

        dir_name = (args.dir).rstrip('/')
        expanded = os.listdir(dir_name)

        for path in expanded:
            full_path = dir_name + '/' + path

            scan(full_path, args.subfile, get_interesting, output_file, get_sections)

    if args.file:
        file_name = args.file
        check_path(file_name)
        scan(full_path, args.subfile, get_interesting, output_file, get_sections)

    print '\nHappy reversing!'
