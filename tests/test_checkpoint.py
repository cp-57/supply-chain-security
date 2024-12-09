import subprocess
import pytest
from jsonschema import validate, ValidationError
import json
from supply_chain_rekor_monitor.main import get_latest_checkpoint


def test_get_latest_checkpoint():
    """
    Test that the output of test_get_latest_checkpoint() conforms to
    the expected schema.
    """
    schema = {
        "type": "string",
        "properties": {
            "inactiveShards": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "rootHash": {"type": "string"},
                        "signedTreeHead": {"type": "string"},
                        "treeID": {"type": "string"},
                        "treeSize": {"type": "integer"},
                    },
                    "required": ["rootHash", "signedTreeHead", "treeID", "treeSize"],
                },
            },
            "rootHash": {"type": "string"},
            "signedTreeHead": {"type": "string"},
            "treeID": {"type": "string"},
            "treeSize": {"type": "integer"},
        },
        "required": [
            "inactiveShards",
            "rootHash",
            "signedTreeHead",
            "treeID",
            "treeSize",
        ],
    }

    checkpoint = get_latest_checkpoint()
    data = str(checkpoint)
    validate(instance=data, schema=schema)


def test_get_latest_checkpoint_subprocess():
    """
    Test the get_latest_checkpoint functionality using subprocess with the
    --checkpoint argument to ensure it retrieves and outputs data that conforms
    to the expected schema.
    """
    # Define the schema for the checkpoint data
    schema = {
        "type": "object",
        "properties": {
            "inactiveShards": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "rootHash": {"type": "string"},
                        "signedTreeHead": {"type": "string"},
                        "treeID": {"type": "string"},
                        "treeSize": {"type": "integer"},
                    },
                    "required": ["rootHash", "signedTreeHead", "treeID", "treeSize"],
                },
            },
            "rootHash": {"type": "string"},
            "signedTreeHead": {"type": "string"},
            "treeID": {"type": "string"},
            "treeSize": {"type": "integer"},
        },
        "required": [
            "inactiveShards",
            "rootHash",
            "signedTreeHead",
            "treeID",
            "treeSize",
        ],
    }

    result = subprocess.run(
        ["python3", "../main.py", "--checkpoint"], capture_output=True, text=True
    )

    assert result.returncode == 0, f"Checkpoint retrieval failed: {result.stderr}"

    try:
        checkpoint_data = json.loads(result.stdout)
        validate(instance=checkpoint_data, schema=schema)
        print("Checkpoint data conforms to the schema.")
    except json.JSONDecodeError as json_err:
        pytest.fail(f"Failed to parse JSON from checkpoint output: {json_err}")
    except ValidationError as schema_err:
        pytest.fail(f"Checkpoint data does not conform to schema: {schema_err}")
