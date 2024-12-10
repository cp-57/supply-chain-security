[![releases](https://github.com/cp-57/supply-chain-security/actions/workflows/ci.yaml/badge.svg)](https://github.com/cp-57/supply-chain-security/actions) [![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/cp-57/supply-chain-security/badge)](https://scorecard.dev/viewer/?uri=github.com/cp-57/supply-chain-security) [![OpenSSF Best Practices](https://www.bestpractices.dev/projects/9794/badge)](https://www.bestpractices.dev/projects/9794)

# Rekor Monitor

### Project Description
This program verifies inclusion of artifact entries in a public transparency log, Rekor. 
It also can verify that the correct signature is present in the transparency log or verify the consistency 
between older and latest checkpoints. 


### Usage Instructions
supply-chain-rekor-monitor -c

supply-chain-rekor-monitor --inclusion 123456789 --artifact artifact.md

supply-chain-rekor-monitor --consistency --tree-id TREE_ID --tree-size TREE_SIZE --root-hash ROOT_HASH

### Installation Steps
git clone https://github.com/cp-57/supply-chain-security.git

### Dependencies
This program relies on the following libraries:
- argparse: for parsing command-line arguments
- cryptography: for handling public key extraction and signature verification
- requests: for interacting with Rekor's api
