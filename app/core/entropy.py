
import math
from collections import Counter
from pathlib import Path


def calculate_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy of binary data.

    Returns:
        Entropy value between 0 and 8 bits per byte.
    """

    if not data:
        return 0.0

    byte_counts = Counter(data)
    total_bytes = len(data)

    entropy = 0.0

    for count in byte_counts.values():
        probability = count / total_bytes
        entropy -= probability * math.log2(probability)

    return entropy


def calculate_file_entropy(
    file_path: str,
    sample_size: int = 65536
) -> float:
    """
    Calculate entropy using the first sample_size bytes
    of a file.
    """

    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(
            f"File not found: {path}"
        )

    if not path.is_file():
        raise ValueError(
            f"Path is not a file: {path}"
        )

    if sample_size <= 0:
        raise ValueError(
            "Sample size must be greater than zero."
        )

    with path.open("rb") as file:
        data = file.read(sample_size)

    return calculate_entropy(data)
