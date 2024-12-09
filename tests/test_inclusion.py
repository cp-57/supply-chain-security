import subprocess
import pytest
from jsonschema import validate

from supply_chain_rekor_monitor.main import get_log_entry, inclusion


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

    log_entry = get_log_entry(999999999999)  # invalid ID
    if log_entry:
        pytest.fail("Expect None with Invalid ID in get_log_entry()")


def test_inclusion_real():
    """
    Test the inclusion functionality with real, correct arguments and data.
    """
    log_index = 133597043
    artifact_filepath = "../artifact.md"

    try:
        inclusion(log_index, artifact_filepath, debug=True)
        print("Inclusion verified with real data.")
    except Exception as e:
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
    artifact_filepath = "../artifact.md"

    result = subprocess.run(
        [
            "python3",
            "../main.py",
            "--inclusion",
            log_index,
            "--artifact",
            artifact_filepath,
            "--debug",
        ],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, f"Inclusion verification failed: {result.stderr}"
    assert "Inclusion verified" in result.stdout
