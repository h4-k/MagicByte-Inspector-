# MagicByte Inspector 🔍

A lightweight Python tool for detecting file formats by analyzing magic numbers (file signatures) from binary headers.

## 📌 Features

- **Magic Number Detection**: Identifies 100+ file formats from their binary signatures
- **Hex & ASCII Display**: Shows first 20 bytes in both hex and ASCII formats
- **Error Handling**: Gracefully handles missing files, permissions, and empty files
- **Extensible Database**: Easy to add new file signatures
- **Zero Dependencies**: Pure Python - no external libraries required

## 📁 Supported Formats

|     Category     |               Formats Detected              |
|------------------|---------------------------------------------|
| **Images**       | JPEG, PNG, GIF, BMP, TIFF, WebP, PSD, ICO   |
| **Archives**     | ZIP, RAR, 7-Zip, GZIP, BZIP2, TAR           |
| **Documents**    | PDF, DOC/XLS/PPT, DOCX, OOXML               |
| **Executables**  | Windows EXE, ELF, Mach-O, Java Class        |
| **Audio/Video**  | MP3, WAV, FLAC, MP4, MKV, AVI, FLV          |
| **System Files** | Disk images, databases, fonts, certificates |

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/yourusername/magicbyte-inspector.git
```

-# Developed by H4K

# Run the detector
python magicbyte.py <filename>
