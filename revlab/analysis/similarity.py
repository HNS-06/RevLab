"""
Binary Comparison & Similarity Diffing Engine
"""
from typing import Dict, Any
from ..parsers.common import BinaryObject
from .hashes import calculate_hashes
from .entropy import calculate_shannon_entropy
from .strings import extract_strings

def compare_binaries(bin1: BinaryObject, bin2: BinaryObject) -> Dict[str, Any]:
    """Compares two binaries and calculates similarity score (0.0 to 100.0%)."""
    h1 = calculate_hashes(bin1)
    h2 = calculate_hashes(bin2)

    is_identical = h1["sha256"] == h2["sha256"]
    
    # 1. File Size Delta
    size_ratio = min(bin1.filesize, bin2.filesize) / max(bin1.filesize, bin2.filesize)

    # 2. Entropy Delta
    e1 = calculate_shannon_entropy(bin1.raw_bytes)
    e2 = calculate_shannon_entropy(bin2.raw_bytes)
    entropy_diff = abs(e1 - e2)

    # 3. Import Jaccard Similarity
    imps1 = {f"{imp.library}:{imp.function_name}" for imp in bin1.imports}
    imps2 = {f"{imp.library}:{imp.function_name}" for imp in bin2.imports}
    
    if imps1 or imps2:
        import_similarity = len(imps1 & imps2) / len(imps1 | imps2)
    else:
        import_similarity = 1.0

    # 4. String Set Jaccard Similarity
    str_data1 = extract_strings(bin1, min_len=6)
    str_data2 = extract_strings(bin2, min_len=6)
    s1 = {s.value for s in str_data1["all_strings"]}
    s2 = {s.value for s in str_data2["all_strings"]}
    
    if s1 or s2:
        string_similarity = len(s1 & s2) / len(s1 | s2)
    else:
        string_similarity = 1.0

    # Weighted Overall Similarity Score
    overall_score = (
        (1.0 if is_identical else 0.0) * 40.0 +
        import_similarity * 30.0 +
        string_similarity * 20.0 +
        size_ratio * 10.0
    )

    diff_summary = {
        "bin1_name": bin1.filename,
        "bin2_name": bin2.filename,
        "is_identical": is_identical,
        "similarity_score": round(overall_score, 2),
        "size_diff": bin2.filesize - bin1.filesize,
        "entropy_diff": round(entropy_diff, 4),
        "import_similarity_pct": round(import_similarity * 100, 2),
        "string_similarity_pct": round(string_similarity * 100, 2),
        "shared_imports_count": len(imps1 & imps2),
        "unique_imports_bin1": list(imps1 - imps2)[:10],
        "unique_imports_bin2": list(imps2 - imps1)[:10],
        "shared_strings_count": len(s1 & s2),
    }

    return diff_summary
