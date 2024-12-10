"""
    Basic tests for the inclusion() function and related components.
"""

import shutil
import subprocess  # nosec
import pytest
from jsonschema import validate
from supply_chain_rekor_monitor.main import get_log_entry, inclusion

python_path = shutil.which("python3")


def test_get_log_entry_schema():
    """
    Test that the output of get_log_entry() conforms to the expected schema.
    """
    schema = {
        "type": "object",
        "patternProperties": {
            "^[a-fA-F0-9]+$": {
                "type": "object",
                "properties": {
                    "body": {"type": "string"},
                    "integratedTime": {"type": "integer"},
                    "logID": {"type": "string"},
                    "logIndex": {"type": "integer"},
                    "verification": {
                        "type": "object",
                        "properties": {
                            "inclusionProof": {
                                "type": "object",
                                "properties": {
                                    "checkpoint": {"type": "string"},
                                    "hashes": {
                                        "type": "array",
                                        "items": {"type": "string"},
                                    },
                                    "logIndex": {"type": "integer"},
                                    "rootHash": {"type": "string"},
                                    "treeSize": {"type": "integer"},
                                },
                                "required": [
                                    "checkpoint",
                                    "hashes",
                                    "logIndex",
                                    "rootHash",
                                    "treeSize",
                                ],
                            },
                            "signedEntryTimestamp": {"type": "string"},
                        },
                        "required": ["inclusionProof", "signedEntryTimestamp"],
                    },
                },
                "required": [
                    "body",
                    "integratedTime",
                    "logID",
                    "logIndex",
                    "verification",
                ],
            }
        },
        "additionalProperties": False,
    }
    log_entry = get_log_entry(129028977)  # example ID
    validate(instance=log_entry, schema=schema)


def test_get_log_entry_with_invalid_id():
    """
    Test the get log entry functionality with an invalid id
    """
    log_entry = get_log_entry(999999999999)  # invalid ID
    if log_entry:
        pytest.fail("Expect None with Invalid ID in get_log_entry()")


def test_inclusion_real():
    """
    Test the inclusion functionality with real, correct arguments and data.
    """
    log_index = 133597043
    artifact_filepath = "./supply_chain_rekor_monitor/artifact.md"

    try:
        inclusion(log_index, artifact_filepath, debug=True)
        print("Inclusion verified with real data.")
    except AssertionError as e:
        pytest.fail(f"Inclusion verification failed with real data: {e}")


def test_inclusion_with_invalid_log_index():
    """
    Test the inclusion functionality with an invalid log index to
    ensure it fails.
    """
    invalid_log_index = 9999999  # Invalid (does not exist)
    artifact_filepath = "../artifact.md"

    with pytest.raises(Exception):
        inclusion(invalid_log_index, artifact_filepath, debug=False)


def test_inclusion_with_incorrect_log_index():
    """
    Test the inclusion functionality with an incorrect log index
    (one that exists but is different) to ensure it fails.
    """
    invalid_log_index = 133597042  # Exists but is incorrect
    artifact_filepath = "../artifact.md"

    with pytest.raises(Exception):
        inclusion(invalid_log_index, artifact_filepath, debug=False)


def test_inclusion_real_subprocess():
    """
    Test the inclusion functionality using subprocess with a real, correct
    log index and artifact.
    """
    log_index = "133597043"
    artifact_filepath = "supply_chain_rekor_monitor/artifact.md"

    result = subprocess.run(
        [
            python_path,
            "-m",
            "supply_chain_rekor_monitor.main",
            "--inclusion",
            log_index,
            "--artifact",
            artifact_filepath,
            "--debug",
        ], #nosec
        capture_output=True,
        text=True,
        check=True,
    )

    if result.returncode != 0:
        raise RuntimeError(f"Checkpoint retrieval failed: {result.stderr}")

    if "Inclusion verified" not in result.stdout:
        raise ValueError("Inclusion verification failed")
