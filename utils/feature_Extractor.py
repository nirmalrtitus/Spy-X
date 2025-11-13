# utils/feature_Extractor.py
from pathlib import Path
import pefile

FEATURE_NAMES = [
    "AddressOfEntryPoint",
    "MajorLinkerVersion",
    "MajorImageVersion",
    "MajorOperatingSystemVersion",
    "DllCharacteristics",
    "SizeOfStackReserve",
    "NumberOfSections",
    "ResourceSize",
]

PE_CANDIDATE_EXTS = {".exe", ".dll", ".sys", ".scr", ".ocx"}

def is_pe_file(filepath: str) -> bool:
    p = Path(filepath)
    try:
        if p.suffix.lower() not in PE_CANDIDATE_EXTS:
            return False
        with open(filepath, "rb") as f:
            sig = f.read(2)
        return sig == b"MZ"
    except Exception:
        return False

def _resource_size_from_pe(pe: "pefile.PE") -> int:
    try:
        return pe.DIRECTORY_ENTRY_RESOURCE.struct.Size
    except Exception:
        try:
            rsrc = next((s for s in pe.sections if b".rsrc" in s.Name), None)
            return int(rsrc.SizeOfRawData) if rsrc else 0
        except Exception:
            return 0

def extract_pe_features_dict(filepath: str) -> dict:
    if not is_pe_file(filepath):
        raise ValueError("Not a PE file")
    try:
        pe = pefile.PE(filepath, fast_load=True)
        feats = {
            "AddressOfEntryPoint": int(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            "MajorLinkerVersion": int(pe.OPTIONAL_HEADER.MajorLinkerVersion),
            "MajorImageVersion": int(pe.OPTIONAL_HEADER.MajorImageVersion),
            "MajorOperatingSystemVersion": int(pe.OPTIONAL_HEADER.MajorOperatingSystemVersion),
            "DllCharacteristics": int(pe.OPTIONAL_HEADER.DllCharacteristics),
            "SizeOfStackReserve": int(pe.OPTIONAL_HEADER.SizeOfStackReserve),
            "NumberOfSections": int(len(pe.sections)),
            "ResourceSize": int(_resource_size_from_pe(pe)),
        }
        return feats
    except pefile.PEFormatError as e:
        raise ValueError(f"PE parse error: {e}") from e
    except Exception as e:
        raise ValueError(f"Unhandled PE error: {e}") from e

def extract_pe_features_vector(filepath: str):
    feats = extract_pe_features_dict(filepath)
    return [feats[name] for name in FEATURE_NAMES]
