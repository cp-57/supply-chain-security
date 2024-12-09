"""
Rekor Verification Module

This module provides functions to interact with the Rekor transparency log. It includes:
- Fetching log entries and checkpoints from Rekor
- Verifying inclusion and consistency of entries in the log
- Verifying artifact signatures using public keys

Functions:
    - get_log_entry(log_index, debug=False): Fetch a specific log entry from Rekor
    - get_verification_proof(log_index, debug=False): Fetch verification proof
      for a log entry
    - inclusion(log_index, artifact_filepath, debug=False):
        Verify inclusion of an entry in the Rekor log
    - get_latest_checkpoint(debug=False):
        Fetch the latest checkpoint from Rekor
    - get_consistency_data(prev_checkpoint, current_tree_size, debug=False):
        Fetch consistency proof data
    - consistency(prev_checkpoint, debug=False): Verify the consistency
      between two checkpoints
    - main(): Parses command-line arguments and runs the appropriate
      verification operations

External Dependencies:
    - argparse: For parsing command-line arguments
    - cryptography: For handling public key extraction and signature verification
    - requests: For interacting with Rekor's API

Command-Line Arguments:
    - --debug: Enables debug mode, which prints additional information during execution
    - --checkpoint: Fetch and display latest checkpoint from Rekor
    - --inclusion:
        Verify inclusion of an entry in the Rekor log using log index and artifact file
    - --artifact: Filepath to the artifact
    - --consistency: Verify consistency between provided checkpoint
      and the latest checkpoint
    - --tree-id: Tree ID of the previous checkpoint for consistency proof
    - --tree-size: Tree size of the previous checkpoint for consistency proof
    - --root-hash: Root hash of the previous checkpoint for consistency proof

Usage:
    1. To verify the inclusion of an entry:
        python main.py --inclusion <log_index> --artifact <artifact_filepath>

    2. To verify the consistency of two checkpoints:
    python main.py --consistency --tree-id <tree_id> --tree-size <tree_size>
      --root-hash <root_hash>

    3. To fetch the latest checkpoint:
        python main.py --checkpoint

Exceptions:
    - requests.Timeout: Raised when request to Rekor times out
    - requests.HTTPError: Raised when Rekor responds with an HTTP error code
      (e.g., 404, 500)
    - requests.RequestException: Catches all other requests-related errors

Example:
    To verify inclusion with log index 126574567 and artifact "artifact_file":

    $ python script.py --inclusion 126574567 --artifact artifact_file

Author:
    Cristian Panaro
"""

import argparse
import base64
from dataclasses import dataclass
import json
from typing import List
import requests
from requests.exceptions import Timeout, HTTPError, RequestException
from supply_chain_rekor_monitor.util import (
    extract_public_key,
    verify_artifact_signature,
)
from supply_chain_rekor_monitor.merkle_proof import (
    DefaultHasher,
    verify_consistency,
    verify_inclusion,
    compute_leaf_hash,
)


@dataclass
class MerkleProof:
    """
    Data structure to hold Merkle proof data for consistency and inclusion verification

    Attributes:
        size1 (int): Size of the first tree
        size2 (int): Size of the second tree
        proof (list): Proof hashes (hex)
        root1 (str): First root hash (hex)
        root2 (str): Second root hash (hex)
    """

    size1: int
    size2: int
    proof: list
    root1: str
    root2: str


@dataclass
class InclusionProof:
    """
    Data structure to hold inclusion proof data for Merkle tree verification

    Attributes:
        index (int): Index of the leaf in the tree
        size (int): Size of the Merkle tree
        leaf_hash (str): Hex-encoded hash of the leaf
        proof (List[str]): List of hex-encoded inclusion proof hashes
        root (str): The expected root hash of the Merkle tree (hex-encoded)
    """

    index: int
    size: int
    leaf_hash: str
    proof: List[str]
    root: str


def get_log_entry(log_index, debug=False):
    """_summary_

    Args:
        log_index (int, optional): Log index of desired entry. Defaults to None.
        debug (bool, optional): _description_. Defaults to False.


    Returns:
        dict: The JSON response containing the consistency proof hashes

    Raises:
        requests.Timeout: If there is a timeout with the requests response
        requests.HTTPError: When the response is an error code (e.g. 403,404)
        requests.RequestException: Catches any other requests library exceptions
    """
    try:
        if debug:
            print(f"Fetching log index {log_index}")
        response = requests.get(
            f"https://rekor.sigstore.dev/api/v1/log/entries?logIndex={log_index}",
            timeout=5,
        )

        response.raise_for_status()
        return response.json()
    except Timeout:
        print("Request timed out.")
    except HTTPError as http_err:
        print(f"HTTP error occurred: {http_err}")
    except RequestException as req_err:
        print(f"Request error occurred: {req_err}")

    return None


def get_verification_proof(log_index, debug=False):
    """
    Fetch the verification proof for a specific log entry.

    Args:
        log_index (int): The index of the log entry to verify.
        debug (bool, optional): If True, enables debug mode. Defaults to False.

    Returns:
        tuple: A tuple containing the log index, tree size, leaf hash,
        inclusion proof hashes, and root hash.
    """
    if debug:
        print(f"Fetching verification proof for log entry {log_index}")
    data = get_log_entry(log_index)
    entry = next(iter(data))
    data = data[entry]

    leaf_hash = compute_leaf_hash(data["body"])

    hashes = data["verification"]["inclusionProof"]["hashes"]
    root_hash = data["verification"]["inclusionProof"]["rootHash"]
    tree_size = data["verification"]["inclusionProof"]["treeSize"]
    tree_size = int(tree_size)
    index = data["verification"]["inclusionProof"]["logIndex"]

    return (index, tree_size, leaf_hash, hashes, root_hash)


def inclusion(log_index, artifact_filepath, debug=False):
    """
    Verify the inclusion of an entry in the Rekor Transparency Log.

    This function verifies whether a specific log entry is included in the
    transparency log, using the specified log index and artifact file.

    Args:
        log_index (int): The index of the log entry to verify.
        artifact_filepath (str): The file path of the artifact used for
          signature verification.
        debug (bool, optional): If True, enables debug mode. Defaults to False.
    """

    # verify that log index and artifact filepath values are sane
    data = get_log_entry(log_index)
    # extract initial body for the purposes of signature and public key
    entry = next(iter(data))
    data = data[entry]

    decoded_data = base64.b64decode(data["body"])
    decoded_data = decoded_data.decode("utf-8")
    decoded_data = json.loads(decoded_data)
    certificate = decoded_data["spec"]["signature"]["publicKey"]["content"]
    # extract bytes and pass to function
    certificate = base64.b64decode(certificate)
    public_key = extract_public_key(certificate)

    signature = decoded_data["spec"]["signature"]["content"]
    # extract bytes from signature and pass to the function
    signature = base64.b64decode(signature)
    try:
        verify_artifact_signature(signature, public_key, artifact_filepath)
        print("Inclusion verified.")
    except Exception:
        print("Validation failed")
        return

    index, tree_size, leaf_hash, hashes, root_hash = get_verification_proof(log_index)

    inclusion_object = InclusionProof(index, tree_size, leaf_hash, hashes, root_hash)
    try:
        verify_inclusion(DefaultHasher, inclusion_object, debug)
        print("Inclusion verified.")
    except Exception:
        print("Validation failed")


def get_latest_checkpoint(debug=False):
    """
    Fetches the latest checkpoint from the Rekor transparency log.

    Args:
        debug (bool, optional): _description_. Defaults to False.


    Returns:
        dict: The JSON response containing the consistency proof hashes

    Raises:
        requests.Timeout: If there is a timeout with the requests response
        requests.HTTPError: When the response is an error code (e.g. 403,404)
        requests.RequestException: Catches any other requests library exceptions
    """
    try:
        if debug:
            print("Fetching the latest checkpoint from the Rekor server...")
        response = requests.get("https://rekor.sigstore.dev/api/v1/log", timeout=5)
        response.raise_for_status()
        return response.json()
    except Timeout:
        print("Request timed out.")
    except HTTPError as http_err:
        print(f"HTTP error occurred: {http_err}")
    except RequestException as req_err:
        print(f"Request error occurred: {req_err}")

    return None


def get_consistency_data(prev_checkpoint, current_tree_size, debug):
    """
    Fetches data from /api/v1/log/proof which provides hashes for a consistency proof.

    Args:
        prev_checkpoint (dict, required)
        current_tree_size (int, required)

    Returns:
        dict: The JSON response containing the consistency proof hashes

    Raises:
        requests.Timeout: If there is a timeout with the requests response
        requests.HTTPError: When the response is an error code (e.g. 403,404)
        requests.RequestException: Catches any other requests library exceptions
    """
    try:
        if debug:
            print("Gathering consistency data")
        response = requests.get(
            f"https://rekor.sigstore.dev/api/v1/log/proof?firstSize={prev_checkpoint['treeSize']}"
            f"&lastSize={current_tree_size}&treeID={prev_checkpoint['treeID']}",
            timeout=5,
        )
        response.raise_for_status()
    except Timeout:
        print("Request timed out.")
    except HTTPError as http_err:
        print(f"HTTP error occurred: {http_err}")
    except RequestException as req_err:
        print(f"Request error occurred: {req_err}")

    return response.json()


def consistency(prev_checkpoint, debug=False):
    """
    Verify the consistency between two checkpoints.

    Args:
        prev_checkpoint (dict): The previous checkpoint data.
        debug (bool, optional): If True, enables debug mode. Defaults to False.
    """
    current_checkpoint = get_latest_checkpoint()
    current_tree_size = current_checkpoint["treeSize"]
    root_hash = current_checkpoint["rootHash"]

    consistency_data = get_consistency_data(prev_checkpoint, current_tree_size, debug)
    if debug:
        print("Hashes for consistency proof:")
        print(json.dumps(consistency_data, indent=4))
    hashes = consistency_data["hashes"]

    merkle_proof = MerkleProof(
        size1=prev_checkpoint["treeSize"],
        size2=current_tree_size,
        proof=hashes,
        root1=prev_checkpoint["rootHash"],
        root2=root_hash,
    )

    verify_consistency(DefaultHasher, merkle_proof)
    print("Consistency verification successful.")


def main():
    """
    Parses command-line arguments and executes operations to perform verification
        operations with the Rekor log.

    """
    debug = False
    parser = argparse.ArgumentParser(description="Rekor Verifier")
    parser.add_argument(
        "-d", "--debug", help="Debug mode", required=False, action="store_true"
    )  # Default false
    parser.add_argument(
        "-c",
        "--checkpoint",
        help="Obtain latest checkpoint\
                        from Rekor Server public instance",
        required=False,
        action="store_true",
    )
    parser.add_argument(
        "--inclusion",
        help="Verify inclusion of an\
                        entry in the Rekor Transparency Log using log index\
                        and artifact filename.\
                        Usage: --inclusion 126574567",
        required=False,
        type=int,
    )
    parser.add_argument(
        "--artifact",
        help="Artifact filepath for verifying\
                        signature",
        required=False,
    )
    parser.add_argument(
        "--consistency",
        help="Verify consistency of a given\
                        checkpoint with the latest checkpoint.",
        action="store_true",
    )
    parser.add_argument(
        "--tree-id", help="Tree ID for consistency proof", required=False
    )
    parser.add_argument(
        "--tree-size", help="Tree size for consistency proof", required=False, type=int
    )
    parser.add_argument(
        "--root-hash", help="Root hash for consistency proof", required=False
    )
    args = parser.parse_args()
    if args.debug:
        debug = True
        print("enabled debug mode")
    if args.checkpoint:
        # get and print latest checkpoint from server
        # if debug is enabled, store it in a file checkpoint.json
        checkpoint = get_latest_checkpoint(debug)
        with open("checkpoint.json", "w", encoding="utf-8") as json_file:
            json.dump(checkpoint, json_file, indent=4)
        print(json.dumps(checkpoint, indent=4))
    if args.inclusion:
        inclusion(args.inclusion, args.artifact, debug)
    if args.consistency:
        if not args.tree_id:
            print("please specify tree id for prev checkpoint")
            return
        if not args.tree_size:
            print("please specify tree size for prev checkpoint")
            return
        if not args.root_hash:
            print("please specify root hash for prev checkpoint")
            return

        prev_checkpoint = {}
        prev_checkpoint["treeID"] = args.tree_id
        prev_checkpoint["treeSize"] = args.tree_size
        prev_checkpoint["rootHash"] = args.root_hash

        consistency(prev_checkpoint, debug)


if __name__ == "__main__":
    main()
