import argparse
import base64
import json
from util import extract_public_key, verify_artifact_signature
from merkle_proof import DefaultHasher, verify_consistency, verify_inclusion, compute_leaf_hash
import requests

def get_log_entry(log_index=None, debug=False):
    """_summary_

    Args:
        log_index (_type_, optional): _description_. Defaults to None.
        debug (bool, optional): _description_. Defaults to False.

    Returns:
        _type_: _description_
    """    
    try:
        # return current checkpoint if no log_index specified
        # otherwise return the log entry at that specifified index
        if not log_index:
            data = requests.get("https://rekor.sigstore.dev/api/v1/log")
        else:
            data = requests.get(f"https://rekor.sigstore.dev/api/v1/log/entries?logIndex={log_index}")
    except:
        print("Fetch error.")
    
    return data.json()


def get_verification_proof(log_index, debug=False):
    # verify that log index value is sane
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
    # verify that log index and artifact filepath values are sane
    data = get_log_entry(log_index)
    """
    BODY
    """
    # extract initial body for the purposes of signature and public key
    entry = next(iter(data))
    data = data[entry]

    decoded_data = base64.b64decode(data['body'])
    decoded_data = decoded_data.decode('utf-8')
    decoded_data = json.loads(decoded_data)
    """
    CERTIFICATE
    """
    certificate = decoded_data["spec"]["signature"]["publicKey"]["content"]
    # extract bytes and pass to function
    certificate = base64.b64decode(certificate)
    public_key = extract_public_key(certificate) 
    """
    SIGNATURE
    """
    signature = decoded_data["spec"]["signature"]["content"]
    # extract bytes from signature and pass to the function
    signature = base64.b64decode(signature)

    verify_artifact_signature(signature, public_key, artifact_filepath)

    index, tree_size, leaf_hash, hashes, root_hash = get_verification_proof(log_index)

    verify_inclusion(DefaultHasher, index, tree_size, leaf_hash, hashes, root_hash, debug)
    print("Inclusion verified.")


def get_latest_checkpoint(debug=False):
    data = get_log_entry(None)
    return data

def get_consistency_data(prev_checkpoint, current_tree_size):
    """
    Returns data from /api/v1/log/proof which provides hashes for a consistency proof.
    """
    try:
        data = requests.get(f"https://rekor.sigstore.dev/api/v1/log/proof?firstSize={prev_checkpoint['treeSize']}&lastSize={current_tree_size}&treeID={prev_checkpoint['treeID']}")
    except:
        print("Fetch error in consistency hash function.")
    
    return data.json()

def consistency(prev_checkpoint, debug=False):

    current_checkpoint = get_latest_checkpoint()
    current_tree_size = current_checkpoint["treeSize"]
    root_hash = current_checkpoint["rootHash"]
    
    consistency_data = get_consistency_data(prev_checkpoint, current_tree_size)
    if debug:
        print("Hashes for consistency proof:")
        print(json.dumps(consistency_data, indent=4))
    hashes = consistency_data["hashes"]

    verify_consistency(DefaultHasher, prev_checkpoint["treeSize"], current_tree_size, hashes, prev_checkpoint["rootHash"],root_hash)
    print("Consistency verification successful.")

def main():
    debug = False
    parser = argparse.ArgumentParser(description="Rekor Verifier")
    parser.add_argument('-d', '--debug', help='Debug mode',
                        required=False, action='store_true') # Default false
    parser.add_argument('-c', '--checkpoint', help='Obtain latest checkpoint\
                        from Rekor Server public instance',
                        required=False, action='store_true')
    parser.add_argument('--inclusion', help='Verify inclusion of an\
                        entry in the Rekor Transparency Log using log index\
                        and artifact filename.\
                        Usage: --inclusion 126574567',
                        required=False, type=int)
    parser.add_argument('--artifact', help='Artifact filepath for verifying\
                        signature',
                        required=False)
    parser.add_argument('--consistency', help='Verify consistency of a given\
                        checkpoint with the latest checkpoint.',
                        action='store_true')
    parser.add_argument('--tree-id', help='Tree ID for consistency proof',
                        required=False)
    parser.add_argument('--tree-size', help='Tree size for consistency proof',
                        required=False, type=int)
    parser.add_argument('--root-hash', help='Root hash for consistency proof',
                        required=False)
    args = parser.parse_args()
    if args.debug:
        debug = True
        print("enabled debug mode")
    if args.checkpoint:
        # get and print latest checkpoint from server
        # if debug is enabled, store it in a file checkpoint.json
        checkpoint = get_latest_checkpoint(debug)
        with open('checkpoint.json', 'w') as json_file:
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