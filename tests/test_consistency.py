import pytest
import json
from main import *

def test_consistency_with_real_checkpoint():
    """
    Test the consistency function with a real checkpoint.json file to ensure it does not fail.
    """
    checkpoint_file_path = "../checkpoint.json"  # Ensure this file exists with valid data

    try:
        with open(checkpoint_file_path, "r") as file:
            prev_checkpoint = json.load(file)

        consistency(prev_checkpoint, debug=True)
        print("Consistency verification completed successfully with real data.")

    except Exception as e:
        pytest.fail(f"Consistency verification failed with real checkpoint data: {e}")


def test_consistency_with_fake_checkpoint():
    """
    Test the consistency function with a fake checkpoint.json file to ensure it does not fail.
    """
    faulty_checkpoint = "faulty_checkpoint.json" 
    try:
        with open(faulty_checkpoint, "r") as file:
            prev_checkpoint = json.load(file)

        consistency(prev_checkpoint, debug=True)
        pytest.fail(f"Consistency verification success with fake checkpoint data: {e}")

    except Exception as e:
        print("Failure upon fake checkpoint")