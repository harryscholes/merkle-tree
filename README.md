# merkle-tree

Rust library for building Merkle trees and generating and validating Merkle proofs.

## Usage

```rust
use merkle_tree::MerkleTree;

fn main() {
    // Create an empty Merkle tree
    let mut tree = MerkleTree::new(2);

    // Add some data to the tree
    let root_0 = tree.insert(0, "some string");

    let root_1 = tree.insert(1, 0x12345_i32.to_be_bytes());
    assert!(root_1 != root_0);

    let root_2 = tree.insert(2, ['c' as u8]);
    assert!(root_2 != root_1);

    let root_3 = tree.insert(3, 3.14159_f64.to_bits().to_be_bytes());
    assert!(root_3 != root_2);

    // Generate a proof that pi is in the Merkle tree
    let proof = tree.proof(3);

    // Proove that pi is in the Merkle tree
    assert!(tree.validate(3.14159_f64.to_bits().to_be_bytes(), proof));
}
```