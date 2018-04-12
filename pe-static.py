#!/usr/bin/env python
import os
import re
import bz2
import sys
import json
import time
import yara
import pefile
import string
import peutils
import hashlib
import argparse
import commands
import requests
import platform
import bitstring

from datetime import datetime


def error(msg, exit=False):
    print('[error] %s' % msg)
    if exit:
        sys.exit(1)


def check_path(file_path):
    # make sure we are looking at a valid file before doing anything else
    if not os.path.exists(file_path):
        error('path %s does not exist' % file_path, True)
    if not os.path.isfile(file_path):
        error('path %s is not a file' % file_path, True)
    if os.path.getsize(file_path) == 0:
        error('path %s has a size of zero' % file_path, True)


def get_vt_report(self, api_key, md5_hash):
    params = {'apikey': api_key, 'resource': md5_hash}
    headers = {'Accept-Encoding': 'gzip, deflate', 'User-Agent': 'pe-static v1.0'}

    try:
        resp = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params, headers=headers)
        jdata = resp.json()

        if jdata['response_code'] == 1:
            return jdata
    except:
        pass

    return None


class Static(object):
    def __init__(self, file_name, rules=None, virustotal=False):
        self.results = {}
        self.file_name = file_name
        self.yara_rules = rules
        self.check_vt = virustotal
        self.raw_data = None

        if self._is_valid_executable(self.file_name):
            self.pe = self._load_pe()
            self.raw_data = self.pe.__data__
        else:
            raise AttributeError('file is invalid and cannot be analyzed (%s)' % self.file_name)

        self.url_re = ur'(?i)\b((?:http[s]?:(?:/{1,3}|[a-z0-9%])|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:\'".,<>?\'\']))'
        self.file_re = r'\b([\w,%-.]+\.[A-Za-z]{3,4})\b'
        self.email_re = r'((?:(?:[A-Za-z0-9]+_+)|(?:[A-Za-z0-9]+\-+)|(?:[A-Za-z0-9]+\.+)|(?:[A-Za-z0-9]+\++))*[A-Za-z0-9]+@(?:(?:\w+\-+)|(?:\w+\.))*\w{1,63}\.[a-zA-Z]{2,6})'
        self.suspicious_apis = {
            'Internet':
                ['HttpSendRequest', 'InternetReadFile', 'InternetConnect'],
            'Anti-Debugging':
                ['IsDebuggerPresent', 'GetTickCount', 'OutputDebugString',
                 'CheckRemoteDebuggerPresent', 'DbgBreakPoint'],
            'Process Manipulation':
                ['VirtualAllocEx', 'CreateProcess',
                 'WriteProcessMemory', 'OpenProcess',
                 'ReadProcessMemory', 'CreateRemoteThread'],
            'Process Execution':
                ['WinExec', 'ShellExecute',
                 'CreateService', 'StartService']
        }


    def _load_pe(self):
        return pefile.PE(self.file_name)


    def _is_valid_executable(self, file_name):
        if os.path.exists(file_name) and os.path.isfile(file_name) and \
                os.path.getsize(file_name) > 0:

            out = commands.getoutput('file -b %s' % file_name)
            if 'PE' in out and 'executable' in out:
                return True

        return False


    def _current_path(self):
        return os.path.abspath(os.path.dirname(__file__))


    def get_ssdeep(self):
        # try to return the ssdeep hash of file
        try:
            from ssdeep import ssdeep
            ss = ssdeep()
            return ss.hash_file(self.file_name)
        except ImportError:
            try:
                import ssdeep
                return ssdeep.hash_from_file(self.file_name)
            except ImportError:
                print '[error] no library `ssdeep` available for import! this feature will not be available.'


    def get_start_address(self):
        # parse objdump output to get start address of file
        out = commands.getoutput('%s -x %s | grep "start address"' % (objdump, self.file_name))
        if out != '\n':
            try:
                return out.split('start address')[1]
            except IndexError:
                pass

        return 'Not Found'


    def get_interesting_strings(self):
        # return dictionary of interesting strings found in file
        results = {}
        out = commands.getoutput('strings %s' % self.file_name)

        if out != '\n':
            urls = re.compile(self.url_re, re.IGNORECASE)
            files = re.compile(self.file_re, re.IGNORECASE)
            emails = re.compile(self.email_re, re.IGNORECASE)

            try:
                results['URLs'] = urls.findall(out)
                results['Files'] = files.findall(out)
                results['Emails'] = emails.findall(out)
            except Exception as err:
                print '[error] caught exception parsing strings (%s)' % str(err)
                pass

        return results


    def get_entrypoint(self):
        try:
            entrypt = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
            position = 0

            for section in self.pe.sections:
                if (entrypt >= section.VirtualAddress) and \
                   (entrypt < (section.VirtualAddress + section.Misc_VirtualSize)):
                    result = section.Name.replace('\x00', '')
                    break
                else:
                    position += 1
            return (entrypt, result, position)
        except:
            return None


    def get_sections(self):
        # get all section names, address, and size of data
        results = []
        results.append([{
            'Name': section.Name.replace('\x00', ''),
            'Address': hex(section.VirtualAddress),
            'Virtual Size': hex(section.Misc_VirtualSize),
            'Raw Data Size': section.SizeOfRawData} for section in self.pe.sections])
        return results


    def get_suspicious_imports(self):
        results = []

        if not hasattr(self.pe, 'DIRECTORY_ENTRY_RESOURCE'):
            return

        for library in self.pe.DIRECTORY_ENTRY_IMPORT:
            for imp, suspicious in zip(library.imports, self.suspicious_apis):
                if imp.name is None and imp.name != '':
                    if imp.name.startswith(suspicious):
                        results.append(imp.name)

        return results


    def get_timestamp(self):
        try:
            timestamp = self.pe.FILE_HEADER.TimeDateStamp
        except:
            return 'Not found'

        if timestamp == 0:
            return 'Not Found'

        timestamp_fmt = datetime.utcfromtimestamp(int(timestamp)).strftime('%Y-%m-%d %H:%M:%S')
        if (timestamp_fmt < 946692000):
            suspicious = '[Suspicious] Old timestamp)'
        elif (timestamp_fmt > time.time()):
            suspicious = '[Suspicious] Future timestamp)'

        answer = '%s %s' % (datetime.fromtimestamp(timestamp), suspicious)
        return answer


    def get_security(self):
        # check file for ASLR, DEP, and SEH features
        features = []

        try:
            if self.pe.OPTIONAL_HEADER.DllCharacteristics > 0:
                if self.pe.OPTIONAL_HEADER.DllCharacteristics & 0x0040:
                    features.append('ASLR')

                if self.pe.OPTIONAL_HEADER.DllCharacteristics & 0x0100:
                    features.append('DEP')

                if (self.pe.OPTIONAL_HEADER.DllCharacteristics & 0x0400 or
                        (hasattr(self.pe, "DIRECTORY_ENTRY_LOAD_CONFIG") and
                        self.pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.SEHandlerCount > 0 and
                        self.pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.SEHandlerTable != 0) or
                        self.pe.FILE_HEADER.Machine == 0x8664):
                    features.append('SEH')

            return ' '.join(features)
        except:
            pass

        return features


    def get_imports(self):
        imps = {}

        try:
            for module in self.pe.DIRECTORY_ENTRY_IMPORT:
                if module.imports.name is not None and module.imports.name != '':
                    if module.dll in imps.keys():
                        imps[module.dll].append(module.imports.name)
                    else:
                        imps[module.dll] = [module.imports.name]
        except:
            pass

        return imps


    def get_hashes(self):
        """ calculate hashes from file """
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        s256 = hashlib.sha256()
        md5.update(self.raw_data)
        sha1.update(self.raw_data)
        s256.update(self.raw_data)

        results = {
            'md5': md5.hexdigest(),
            'sha1': sha1.hexdigest(),
            'sha256': s256.hexdigest(),
            'peHash': self.get_pehash()
        }

        return results


    def get_pehash(self):
        # compute PEHash (https://www.usenix.org/legacy/events/leet09/tech/full_papers/wicherski/wicherski_html/index.html)
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

        return m.hexdigest()


    def scan(self):
        hashes = self.get_hashes()

        self.results = {
            'MD5': hashes['md5'],
            'SHA1': hashes['sha1'],
            'SHA256': hashes['sha256'],
            'PEHash': hashes['peHash'],
            'ImpHash': self.pe.get_imphash(),
            'SSDeep': self.get_ssdeep(),
            'Type': commands.getoutput('file -b %s' % self.file_name),
            'Size': (os.path.getsize(self.file_name) / 1000),
            'Packed': peutils.is_probably_packed(self.pe),

            'Arch': pefile.MACHINE_TYPE[self.pe.FILE_HEADER.Machine],
            'Entry Point': hex(self.pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            'Compiled': self.get_timestamp(),
            'Start Address': self.get_start_address(),
            'Sections': self.get_sections(),
            'Security': self.get_security(),
            'Suspicious Imports': self.get_suspicious_imports(),
            'Interesting Strings': self.get_interesting_strings()
        }

        if self.yara_rules is not None:
            tags, hits = [], []

            all_rules = os.listdir(self.yara_rules)
            for _file in all_rules:
                path = all_rules + '/' + _file
                rule = yara.compile(path)

                matches = rule.match(data=open(self.file_name, 'rb').read())
                for m in matches:
                    if m.rule not in hits:
                        hits.append(m.rule)
                    for tag in m.tags:
                        if tag not in tags:
                            tags.append(tag)

            self.results['Yara'] = {'Matces': hits, 'Tags': tags}

        if self.vt_key is not None:
            self.results['VirusTotal'] = get_vt_report(self.vt_key, self.results['md5'])

        return self.results


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='perform static analysis against an individual executable or an entire directory of executables')

    parser.add_argument('-f', '--file',
        help='individual file name to assess',
        action='store')

    parser.add_argument('-d', '--dir',
        help='scan every file in directory',
        action='store')

    parser.add_argument('-r', '--rules',
        help='scan file with custom yara rules in this path',
        action='store')

    parser.add_argument('-v', '--virustotal_key',
        help='retrieve virustotal report with API key',
        action='store')

    parser.add_argument('-o', '--output',
        help='save results as JSON to file',
        action='store',
        default='./static_%s.txt' % datetime.utcfromtimestamp(time.time()).strftime('%d-%M-%y_%H:%M:%S'))

    args = parser.parse_args()

    if platform.system() == 'Darwin':
        objdump = 'gobjdump'
    elif platform.system() == 'Linux':
        objdump = 'objdump'
    else:
        error('script only runs on macOS or Linux', True)

    output_err = 'output file already exists. choose another filename.'
    output_file = args.outpath if not os.path.exists(args.outpath) else error(output_err, True)

    yara_rules = None
    if args.rules:
        yara_rules = args.rules

    vt_key = None
    if args.virustotal:
        vt_key = args.virustotal

    if args.dir:
        if args.file:
            error('the flags --file and --dir may not be used together', True)

        check_path(args.dir)

        dir_name = (args.dir).rstrip('/')
        expanded = os.listdir(dir_name)

        for path in expanded:
            full_path = dir_name + '/' + path

            scan_results = Static(full_path, yara_rules, vt_key).scan()

    if args.file:
        file_name = args.file
        check_path(file_name)
        scan_results = Static(file_name, yara_rules, vt_key).scan()

    else:
        error('must specify either --file or --dir for analysis', True)

    if args.output:
        if not os.path.exists(args.output):
            with open(args.output, 'a+') as fp:
                json.dump(scan_results, fp, indent=2)
