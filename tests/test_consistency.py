"""
    Basic tests for the consistency() function and related components.
"""

import json
import pytest
from supply_chain_rekor_monitor.main import consistency
from supply_chain_rekor_monitor.merkle_proof import RootMismatchError


def test_consistency_with_real_checkpoint():
    """
    Test the consistency function with a real checkpoint.json file to ensure
    it does not fail.
    """
    checkpoint_file_path = "supply_chain_rekor_monitor/checkpoint.json"

    try:
        with open(checkpoint_file_path, "r", encoding="UTF-8") as file:
            prev_checkpoint = json.load(file)

        consistency(prev_checkpoint, debug=True)
        print("Consistency verification completed successfully with real data.")
    except ValueError:
        pytest.fail("Consistency verification failed with real checkpoint data.")


def test_consistency_with_fake_checkpoint():
    """
    Test the consistency function with a fake checkpoint.json file to ensure
    it does not fail.
    """
    faulty_checkpoint = "tests/faulty_checkpoint.json"
    try:
        with open(faulty_checkpoint, "r", encoding="UTF-8") as file:
            prev_checkpoint = json.load(file)

        consistency(prev_checkpoint, debug=True)
        pytest.fail("Consistency verification success with fake checkpoint data.")
    except RootMismatchError:
        print("Passed: expected failure occurred upon fake checkpoint")
