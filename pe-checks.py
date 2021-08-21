import pefile
import argparse
import datetime
import hashlib
import os
from pathlib import Path
from helpers import get_default_root
from capa_helpers import mainowar
from pydefendercheck import DefenderScanner

parser = argparse.ArgumentParser(description='PE informations')
parser.add_argument(dest='filenames',metavar='filename', nargs='*')
parser.add_argument('-s', '--scan', dest='scan', action='store_true', help='perform a defender engine scan (WARNING:before lauching that scan you need to adjust Defender settings to: Defender ON, Submission OFF)')
parser.add_argument('-v', dest='verbose', action='store_true', help='verbose mode')
args = parser.parse_args()

def SingleFileInfo(filename):
    try:
        pe = pefile.PE(filename)
    except (FileNotFoundError, pefile.PEFormatError) as e:
        print(f"file {filename} does not exist or is not a PE file")
        return

    raw = pe.write()
    rich_headers = pe.parse_rich_header()
    print(f"---- PE Infos")
    print(f"-- Basic properties")

    # import ipdb;ipdb.set_trace()
    print(f'{"Magic":<15} {pe.DOS_HEADER.e_magic:}')
    print(f'{"Magic2":<15} {pe.OPTIONAL_HEADER.Magic:}')
    print(f'{"Imphash":<15} {pe.get_imphash()}')
    print(f'{"Sha256":<15} {hashlib.sha256(raw).hexdigest()}')
    print(f'{"Entropy":<15} {pe.sections[0].entropy_H(raw)} (Min=0.0, Max=8.0)')
    print(f'{"File Size":<15} {pe.OPTIONAL_HEADER.SizeOfImage/1000} KB ({pe.OPTIONAL_HEADER.SizeOfImage} bytes)')
    if args.verbose:
        print(f'{"Headers Size":<15} {pe.OPTIONAL_HEADER.SizeOfHeaders}')

    print()
    print(f"-- Headers")
    print(f'{"Compilation Timestamp:":<25} {datetime.datetime.utcfromtimestamp(pe.FILE_HEADER.TimeDateStamp)} (utc)')
    print(f'{"Machine:":<25} 0x{pe.FILE_HEADER.Machine:x}')
    print(f'{"Entry Point:":<25} {pe.OPTIONAL_HEADER.AddressOfEntryPoint}')

    print()
    print(f"-- Sections")
    print(f'{"Name":<8} {"Virtual Address":<17} {"Virtual Size":<14} {"Raw Size":<10} {"MD5":<35} {"Entropy (Min=0.0, Max=8.0)"}')
    for section in pe.sections:
        name = section.Name.decode()
        virtual_address = section.VirtualAddress
        virtual_size = section.Misc_VirtualSize
        raw_size = section.SizeOfRawData
        md5 = section.get_hash_md5()
        entropy = section.get_entropy()
        print(f"{name:<8} {virtual_address:<17} {virtual_size:<14} {raw_size:<10} {md5:<35} {entropy}")

    if args.verbose:
        print()
        print(f"-- Imports")
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                print(f"{entry.dll.decode()}.{imp.name.decode():50}[{hex(imp.address)}]")
            print()


def CapaReport(filename):
    capa_rules_path = os.path.join(get_default_root(), "capa-rules")
    request = [filename]
    if args.verbose:
        request.append('-v')
    request.append('-r')
    request.append(capa_rules_path)
    request.append('-s')
    request.append(capa_rules_path)

    mainowar(request)

def main():
    for filename in args.filenames:
        print(f'{"==================================================":<50} {"File informations":^20} {"==================================================":>50}')
        SingleFileInfo(filename)
        print()
        print(f'{"==================================================":<50} {"Capa analysis":^20} {"==================================================":>50}')
        CapaReport(filename)
        if args.scan:
            print()
            print(f'{"==================================================":<50} {"Defender scan":^20} {"==================================================":>50}')
            scanner = DefenderScanner(Path(filename))
            print(scanner.result)

main()
