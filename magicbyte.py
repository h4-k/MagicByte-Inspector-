import sys

def magic_number(filename):
    try:
        with open(filename, "rb") as f:  
            header = f.read(20)
            if header:
                print(f"First 20 bytes of {filename}:")
                print(f"Hex: {header.hex()}")
                print(f"ASCII: {header}\n\n")
                return header  
            else:
                print(f"File {filename} is empty or could not be read.")
                return None
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
        return None
    except PermissionError:
        print(f"Error: Permission denied for file '{filename}'.")
        return None
    except Exception as e:
        print(f"Error: {e}")
        return None
    


def detect_file(header):
    if not header:
        print("[-] No header to analyze")
        return
    
    common_magic_numbers = {
        # Images
        "FFD8FF": "JPEG/JFIF Image",
        "FFD8FFE0": "JPEG/JFIF Image",
        "FFD8FFE1": "JPEG/Exif Image",
        "FFD8FFE2": "JPEG/Canon EOS",
        "89504E47": "PNG Image",
        "47494638": "GIF Image (87a/89a)",
        "49492A00": "TIFF Image (little-endian)",
        "4D4D002A": "TIFF Image (big-endian)",
        "424D": "BMP Image",
        "38425053": "Photoshop Document (PSD)",
        "00000100": "ICO Icon",
        "00000200": "CUR Cursor",
        "57454250": "WebP Image",
        "52494646": "AVIF Image (RIFF header)",
        
        # Archives & Compression
        "504B0304": "ZIP Archive",
        "504B0506": "ZIP Archive (empty)",
        "504B0708": "ZIP Archive (spanned)",
        "1F8B08": "GZIP Compressed",
        "425A68": "BZIP2 Compressed",
        "FD377A585A00": "XZ Compressed (LZMA)",
        "377ABCAF271C": "7-Zip Archive",
        "526172211A07": "RAR Archive (v4)",
        "526172211A0700": "RAR Archive (v5+)",
        "1F9D": "TAR.Z (compress)",
        "1FA0": "TAR.Z (lzh)",
        "7573746172": "TAR Archive (ustar)",
        
        # Documents
        "25504446": "PDF Document",
        "D0CF11E0A1B11AE1": "Microsoft Compound Document (DOC, XLS, PPT)",
        "504B0304": "Office Open XML (DOCX, XLSX, PPTX) - same as ZIP",
        "504B030414000600": "Microsoft Office 2007+ (OOXML)",
        "0D444F43": "WordPerfect Document",
        "5B41445D": "Lotus Ami Pro",
        
        # Executables
        "4D5A": "DOS/Windows EXE/DLL",
        "7F454C46": "ELF Executable/Library",
        "CECAFEED": "Mach-O Binary (32-bit)",
        "FEEDFACE": "Mach-O Binary (32-bit, alternative)",
        "CEFAEDFE": "Mach-O Binary (little-endian)",
        "FEEDFACF": "Mach-O Binary (64-bit)",
        "CAFEBABE": "Java Class File",
        "CAFED00D": "Java Pack200",
        "4A415241": "JAR Archive",
        "504B0304": "APK File (Android) - same as ZIP",
        
        # Audio
        "494433": "MP3 with ID3 tag",
        "FFFB": "MP3 without ID3 (MPEG frame sync)",
        "FFF3": "MP3 without ID3 (alternative)",
        "FFF2": "MP3 without ID3 (alternative)",
        "4F676753": "Ogg Vorbis/Theora",
        "664C6143": "FLAC Audio",
        "52494646": "WAV Audio (RIFF header)",
        "4D546864": "MIDI File",
        "2E524D46": "RealMedia",
        "4D344120": "M4A Audio",
        "000001BA": "MPEG-PS (Program Stream)",
        "000001B3": "MPEG Video",
        
        # Video
        "0000001866747970": "MP4 Video",
        "0000002066747970": "MP4 Video (alternative)",
        "1A45DFA3": "Matroska (MKV/WebM)",
        "3026B2758E66CF11": "WMV/ASF Video",
        "464C5601": "FLV Video",
        "4D564833": "MVC Video",
        "000001B3": "MPEG Video",
        
        # Disk Images
        "444F53": "Floppy Disk Image (DOS)",
        "4B444D": "QEMU QCOW Image",
        "514649": "QEMU QCOW2 Image",
        "564D444B": "VirtualBox Disk Image",
        "436F6E6563746978": "VHDX Image",
        "767873": "VMDK (VMware)",
        "234458": "ISO Image",
        
        # Database
        "53514C69746520666F726D61742033": "SQLite Database",
        "00": "InterBase/Firebird Database",
        "4F52434C": "Oracle Database",
        "0F0F0F0F": "DB2 Database",
        
        # Fonts
        "4F54544F": "OpenType Font",
        "74727565": "TrueType Font",
        "00010000": "TrueType Font (alternative)",
        "774F4646": "WOFF Font",
        "774F4632": "WOFF2 Font",
        
        # Virtualization/Containers
        "5155AA55": "QEMU Snapshot",
        "667479706F736978": "POSIX Tar",
        "7801730D626260": "Docker Layer",
        
        # Cryptography
        "2D2D2D2D2D424547494E": "PEM Certificate (-----BEGIN)",
        "3082": "DER Certificate (X.509)",
        "4D534346": "Microsoft Certificate Store",
        "4B444D": "LUKS Encrypted Disk",
        
        # Scripts/Text
        "2321": "Shell Script (starts with #!)",
        "3C3F786D6C": "XML Document",
        "3C21444F4354": "HTML Document",
        "EFBBBF": "UTF-8 with BOM",
        "FEFF": "UTF-16 Big Endian",
        "FFFE": "UTF-16 Little Endian",
        
        # Email
        "46726F6D20": "Email (From: header)",
        "52657475726E2D506174683A": "Email (Return-Path:)",
        "52656365697665643A": "Email (Received:)",
        
        # Network/Protocols
        "474554": "HTTP GET",
        "504F5354": "HTTP POST",
        "FFFE": "UTF-16 Unicode",
        
        # Other
        "4C01": "Windows Shortcut (LNK)",
        "4B44": "KDE Config File",
        "213C617263683E": "Debian Package (.deb)",
        "EDABEEDB": "RPM Package",
        "1F9D": "Compress Archive",
        "1FA0": "LZH Archive",
        "75737461722020": "UStar Tar Archive",
        "4F626A01": "Flash Video",
        "465753": "Flash Shockwave",
        "5A4D": "MS-DOS EXE (alternative)",
        "4C4E0200": "Windows Event Log",
        "5041434B": "PAK Archive (Quake)",
        "5354454C": "Stellarium Landscape",
        "4D5A9000": "DOS MZ Executable",
        "5A4D": "MS-DOS EXE",
        
        # Apple/iOS
        "62706C697374": "Apple Binary PList",
        "494F53": "Apple iOS App",
        "494F5354": "iOS App Store Package",
        
        # Game Files
        "574144": "Doom WAD File",
        "474F424C": "Go Blank",
        "514649": "Quake PAK",
        
        # Virtual Machine
        "4B444D56": "KVM QCOW",
        "564D444B": "VMware VMDK",
        "434F5744": "Xen COW",
        
        # BIOS/UEFI
        "5AA5F00F": "ACPI Table",
        "55AA": "Boot Sector Signature",
        
        # Windows Specific
        "4D534654": "Microsoft Cabinet (CAB)",
        "4D534346": "Microsoft Compound File",
        "4D5A": "Windows Executable",
        "5A4D": "MS-DOS Executable",
        
        # Linux Specific
        "7F454C46": "ELF Binary",
        "42494E": "Linux Kernel Image",
        "414F5353": "Android OTA",
        
        # Database Dumps
        "2D2D204D7953514C": "MySQL Dump (-- MySQL)",
        "504F535447524553": "PostgreSQL Dump",
        
        # Configuration
        "5B": "INI File (starts with '[')",
        "230A": "Config File (starts with '#\\n')",
        "3B": "Config File (starts with ';')",
        
        # Development
        "3C3F706870": "PHP Script",
        "76617220": "JavaScript (var )",
        "696D706F727420": "Python (import )",
        "7061636B61676520": "Java (package )",
        
        # Security/Certificates
        "2D2D2D2D2D424547494E204345525449464943415445": "PEM Certificate",
        "2D2D2D2D2D424547494E205253412050524956415445204B4559": "RSA Private Key",
    }
    
    hex_header = header.hex().upper()
    
    
    
    for magic, name in common_magic_numbers.items():
        if hex_header.startswith(magic):
            print(f"[+] Matching Found: {name} (magic: {magic})")
            found = True
    
    if not found:
        print("[-] No matching magic number found")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: python3 {sys.argv[0]} <filename>")
        sys.exit(1)
    
    print("==== MagicByte Inspector =====\n\n")
    file = sys.argv[1]
    header = magic_number(file)  
    if header:
        detect_file(header)  

