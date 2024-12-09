import pytest
import json
from supply_chain_rekor_monitor.main import consistency


def test_consistency_with_real_checkpoint():
    """
    Test the consistency function with a real checkpoint.json file to ensure
    it does not fail.
    """
    checkpoint_file_path = "../checkpoint.json"

    try:
        with open(checkpoint_file_path, "r", encoding="UTF-8") as file:
            prev_checkpoint = json.load(file)

        consistency(prev_checkpoint, debug=True)
        print("Consistency verification completed successfully with real data.")

    except Exception:
        pytest.fail("Consistency verification failed with real checkpoint data.")


def test_consistency_with_fake_checkpoint():
    """
    Test the consistency function with a fake checkpoint.json file to ensure
    it does not fail.
    """
    faulty_checkpoint = "faulty_checkpoint.json"
    try:
        with open(faulty_checkpoint, "r") as file:
            prev_checkpoint = json.load(file)

        consistency(prev_checkpoint, debug=True)
        pytest.fail("Consistency verification success with fake checkpoint data.")

    except Exception:
        print("Failure upon fake checkpoint")
