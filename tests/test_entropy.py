
import os
import pytest

from app.core.entropy import (
    calculate_entropy,
    calculate_file_entropy
)


def test_empty_data():
    assert calculate_entropy(b"") == 0.0


def test_repeated_bytes():
    assert calculate_entropy(b"AAAAAAAA") == 0.0


def test_uniform_byte_distribution():
    assert calculate_entropy(bytes(range(256))) == pytest.approx(8.0)


def test_random_data():
    data = os.urandom(65536)
    entropy = calculate_entropy(data)

    assert 7.9 < entropy <= 8.0


def test_file_entropy(tmp_path):
    file_path = tmp_path / "test.txt"
    file_path.write_bytes(b"AAAAAAAA")

    assert calculate_file_entropy(str(file_path)) == 0.0


def test_missing_file():
    with pytest.raises(FileNotFoundError):
        calculate_file_entropy("nonexistent_file.txt")


def test_invalid_sample_size(tmp_path):
    file_path = tmp_path / "test.txt"
    file_path.write_bytes(b"AAAAAAAA")

    with pytest.raises(ValueError):
        calculate_file_entropy(str(file_path), sample_size=0)
