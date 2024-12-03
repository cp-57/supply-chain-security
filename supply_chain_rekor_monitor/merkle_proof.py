"""
Merkle Proof Verification Module

This module provides functions to verify Merkle proof consistency and inclusion.

Functions:
    - verify_consistency: Verifies consistency between two Merkle tree roots
    - verify_inclusion: Verifies inclusion of a leaf in a Merkle tree
    - compute_leaf_hash: Computes leaf hash for an entry
"""
import hashlib
import binascii
import base64

# domain separation prefixes according to the RFC
RFC6962_LEAF_HASH_PREFIX = 0
RFC6962_NODE_HASH_PREFIX = 1


class Hasher:
    """
    A class for hashing leaf and node data using the specified hash function.
    Supports domain separation for leaf and node hashes as per RFC 6962.
    """

    def __init__(self, hash_func=hashlib.sha256):
        """
        Initialize the Hasher with a given hash function.

        Args:
            hash_func (function, optional): The hashing function to use. Defaults to hashlib.sha256.
        """
        self.hash_func = hash_func

    def new(self):
        """
        Create a new hash object using the initialized hash function.

        Returns:
            hash: A new hash object.
        """
        return self.hash_func()

    def empty_root(self):
        """
        Generate a hash of an empty root.

        Returns:
            bytes: The hash of an empty root.
        """
        return self.new().digest()

    def hash_leaf(self, leaf):
        """
        Hash a leaf node using the RFC 6962 leaf hash prefix.

        Args:
            leaf (bytes): The leaf data to hash.

        Returns:
            bytes: The hash of the leaf node.
        """
        h = self.new()
        h.update(bytes([RFC6962_LEAF_HASH_PREFIX]))
        h.update(leaf)
        return h.digest()

    def hash_children(self, left, right):
        """
        Hash two child nodes (left and right) together using node hash prefix.

        Args:
            left (bytes): The left child node hash.
            right (bytes): The right child node hash.

        Returns:
            bytes: The combined hash of the two child nodes.
        """
        h = self.new()
        b = bytes([RFC6962_NODE_HASH_PREFIX]) + left + right
        h.update(b)
        return h.digest()

    def size(self):
        """
        Find the size of the hash produced by hashing function.

        Returns:
            int: Size of the produced digest
        """
        return self.new().digest_size


# DefaultHasher is a SHA256 based LogHasher
DefaultHasher = Hasher(hashlib.sha256)

def verify_consistency(hasher, merkle_proof):
    """
    Verify the consistency between two Merkle tree root hashes.

    Args:
        hasher (Hasher): Hashing object used for verification
        merkle_proof (MerkleProof): MerkleProof object containing proof data, including:
            - size1 (int): Size of the first tree
            - size2 (int): Size of the second tree
            - proof (list): Consistency proof hashes
            - root1 (str): Root hash of the first tree (hex string)
            - root2 (str): Root hash of the second tree (hex string)

    Raises:
        ValueError: If the proof is invalid or sizes are inconsistent.
    """
    root1 = bytes.fromhex(merkle_proof.root1)
    root2 = bytes.fromhex(merkle_proof.root2)

    bytearray_proof = [bytes.fromhex(elem) for elem in merkle_proof.proof]

    if merkle_proof.size2 < merkle_proof.size1:
        raise ValueError(f"size2 ({merkle_proof.size2}) < size1 ({merkle_proof.size1})")

    if merkle_proof.size1 == merkle_proof.size2:
        if bytearray_proof:
            raise ValueError("size1=size2, but proof is not empty")
        verify_match(root1, root2)
        return

    if merkle_proof.size1 == 0:
        if bytearray_proof:
            raise ValueError(
                f"expected empty proof, but got {len(bytearray_proof)} components"
            )
        return

    if not bytearray_proof:
        raise ValueError("empty proof")

    inner, border = decomp_incl_proof(merkle_proof.size1 - 1, merkle_proof.size2)
    shift = (merkle_proof.size1 & -merkle_proof.size1).bit_length() - 1
    inner -= shift

    if merkle_proof.size1 == 1 << shift:
        seed, start = root1, 0
    else:
        seed, start = bytearray_proof[0], 1

    if len(bytearray_proof) != start + inner + border:
        raise ValueError(
            f"wrong proof size {len(bytearray_proof)}, want {start + inner + border}"
        )

    bytearray_proof = bytearray_proof[start:]

    mask = (merkle_proof.size1 - 1) >> shift

    hash1 = chain_inner_right(hasher, seed, bytearray_proof[:inner], mask)
    hash1 = chain_border_right(hasher, hash1, bytearray_proof[inner:])
    verify_match(hash1, root1)

    hash2 = chain_inner(hasher, seed, bytearray_proof[:inner], mask)
    hash2 = chain_border_right(hasher, hash2, bytearray_proof[inner:])
    verify_match(hash2, root2)



def verify_match(calculated, expected):
    """
    Verify that two root hashes match.

    Args:
        calculated (bytes): The calculated root hash
        expected (bytes): The expected root hash

    Raises:
        RootMismatchError: If the calculated and expected roots do not match.
    """
    if calculated != expected:
        raise RootMismatchError(expected, calculated)


def decomp_incl_proof(index, size):
    """
    Break an inclusion proof into its inner and border components.

    Args:
        index (int): The index of the leaf
        size (int): The size of the tree

    Returns:
        tuple: A tuple containing the number of inner and border proofs
    """
    inner = inner_proof_size(index, size)
    border = bin(index >> inner).count("1")
    return inner, border


def inner_proof_size(index, size):
    """
    Calculate size of the inner proof for an inclusion proof

    Args:
        index (int): The index of the leaf
        size (int): The size of the tree

    Returns:
        int: The size of the inner proof
    """
    return (index ^ (size - 1)).bit_length()


def chain_inner(hasher, seed, proof, index):
    """
    Hash the inner nodes in the proof chain.

    Args:
        hasher (Hasher): The hasher object used to compute hashes
        seed (bytes): The initial hash (usually the leaf hash)
        proof (list): The list of proof hashes
        index (int): The index of the leaf node

    Returns:
        bytes: The resulting hash after chaining through inner nodes
    """
    for i, h in enumerate(proof):
        if (index >> i) & 1 == 0:
            seed = hasher.hash_children(seed, h)
        else:
            seed = hasher.hash_children(h, seed)
    return seed


def chain_inner_right(hasher, seed, proof, index):
    """
    Chain inner right nodes in the proof

    Args:
        hasher (Hasher): The hasher object used to compute hashes
        seed (bytes): The initial hash
        proof (list): The list of proof hashes
        index (int): The index of the leaf node

    Returns:
        bytes: The resulting hash after chaining through right nodes
    """
    for i, h in enumerate(proof):
        if (index >> i) & 1 == 1:
            seed = hasher.hash_children(h, seed)
    return seed


def chain_border_right(hasher, seed, proof):
    """
    Chain the border nodes in the proof

    Args:
        hasher (Hasher): The hasher object used to compute hashes
        seed (bytes): The initial hash
        proof (list): The list of proof hashes

    Returns:
        bytes: The resulting hash after chaining through border nodes
    """
    for h in proof:
        seed = hasher.hash_children(h, seed)
    return seed


class RootMismatchError(Exception):
    """
    Raises when the calculated Merkle root does not match expected root
    """

    def __init__(self, expected_root, calculated_root):
        """
        Initialize RootMismatchError with expected and calculated root hashes

        Args:
            expected_root (bytes): Expected root hash
            calculated_root (bytes): Calculated root hash
        """
        self.expected_root = binascii.hexlify(bytearray(expected_root))
        self.calculated_root = binascii.hexlify(bytearray(calculated_root))

    def __str__(self):
        """
        String representation of the RootMisMatchError

        Returns:
            str: Message indicating the mismatch between the expected and calculated roots
        """
        return f"calculated root:\n{self.calculated_root}\n \
            does not match expected root:\n{self.expected_root}"


def root_from_inclusion_proof(hasher, index, size, leaf_hash, proof):
    """
    Calculate root hash from inclusion proof

    Args:
        hasher (Hasher): Hashing object used for verification
        index (int): Index of the leaf
        size (int): Size of the tree
        leaf_hash (bytes): Hash of the leaf node
        proof (list): Inclusion proof hashes

    Returns:
        bytes: Calculated root hash

    Raises:
        ValueError: If index is beyond the size or if the proof size is incorrect
    """
    if index >= size:
        raise ValueError(f"index is beyond size: {index} >= {size}")

    if len(leaf_hash) != hasher.size():
        raise ValueError(
            f"leaf_hash has unexpected size {len(leaf_hash)}, want {hasher.size()}"
        )

    inner, border = decomp_incl_proof(index, size)
    if len(proof) != inner + border:
        raise ValueError(f"wrong proof size {len(proof)}, want {inner + border}")

    res = chain_inner(hasher, leaf_hash, proof[:inner], index)
    res = chain_border_right(hasher, res, proof[inner:])
    return res

def verify_inclusion(hasher, inclusion_proof, debug=False):
    """
    Verify inclusion of a leaf in a Merkle tree

    Args:
        hasher (Hasher): Hashing object used for verification
        inclusion_proof (InclusionProof): Dataclass containing inclusion proof data
        debug (bool, optional): If True, prints debug information. Defaults to False

    Raises:
        RootMismatchError: If calculated root does not match the expected root
    """
    bytearray_proof = [bytes.fromhex(elem) for elem in inclusion_proof.proof]
    bytearray_root = bytes.fromhex(inclusion_proof.root)
    bytearray_leaf = bytes.fromhex(inclusion_proof.leaf_hash)

    calc_root = root_from_inclusion_proof(
        hasher, inclusion_proof.index, inclusion_proof.size, bytearray_leaf, bytearray_proof
    )
    verify_match(calc_root, bytearray_root)

    if debug:
        print("Calculated root hash:", calc_root.hex())
        print("Given root hash:", bytearray_root.hex())


def compute_leaf_hash(body):
    """
    Compute the leaf hash for a log entry according to the RFC 6962 specification

    Args:
        body (str): Base64 encoded body of the log entry

    Returns:
        str: Hex representation of the leaf hash
    """
    entry_bytes = base64.b64decode(body)

    # create a new sha256 hash object
    h = hashlib.sha256()
    # write the leaf hash prefix
    h.update(bytes([RFC6962_LEAF_HASH_PREFIX]))

    # write the actual leaf data
    h.update(entry_bytes)

    # return the computed hash
    return h.hexdigest()
