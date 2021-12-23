use sha2::{Digest as Sha2DigestTrait, Sha256};
use std::collections::HashMap;

type Digest = [u8; 32];

const DEFAULT_LEAF: Digest = [0; 32];

pub struct MerkleTree {
    height: u32,
    values: HashMap<usize, Digest>,
    default_nodes: Vec<Digest>,
}

impl MerkleTree {
    pub fn new(height: u32) -> MerkleTree {
        MerkleTree::with_default_leaf(DEFAULT_LEAF, height)
    }

    pub fn with_default_leaf(default_leaf: Digest, height: u32) -> MerkleTree {
        let default_nodes = default_nodes(default_leaf, height);
        let default_root = default_nodes[height as usize];

        let mut values = HashMap::new();
        values.insert(1, default_root);

        MerkleTree {
            height,
            values,
            default_nodes,
        }
    }

    pub fn root(&self) -> Digest {
        *self.values.get(&1).unwrap()
    }

    pub fn insert(&mut self, index: usize, value: impl AsRef<[u8]>) -> Digest {
        let mut node_index = index_of(self.height, index);

        self.values.insert(node_index, hash(value));

        for h in 0..self.height as usize {
            let default_node = self.default_nodes[h];

            let (left_index, right_index) = if node_index % 2 == 0 {
                (node_index, node_index + 1)
            } else {
                (node_index - 1, node_index)
            };

            let left_node = *self.values.get(&left_index).unwrap_or(&default_node);
            let right_node = *self.values.get(&right_index).unwrap_or(&default_node);

            let node_hash = hash_pair(left_node, right_node);

            node_index /= 2;

            self.values.insert(node_index, node_hash);
        }

        self.root()
    }

    pub fn proof(&self, index: usize) -> Vec<Digest> {
        let mut node_index = index_of(self.height, index);

        let mut hashes = vec![];

        for h in 0..self.height as usize {
            let sibling_index = if node_index % 2 == 0 {
                node_index + 1
            } else {
                node_index - 1
            };

            let hash = *self
                .values
                .get(&sibling_index)
                .unwrap_or(&self.default_nodes[h]);

            hashes.push(hash);

            node_index /= 2;
        }

        hashes
    }

    pub fn validate(&self, value: impl AsRef<[u8]>, proof: Vec<Digest>) -> bool {
        let proof_root = proof
            .into_iter()
            .fold(hash(value), |node_hash, sibling_hash| {
                hash_pair(node_hash, sibling_hash)
            });
        proof_root == self.root()
    }
}

fn index_of(height: u32, index: usize) -> usize {
    let leaves_offset = 2usize.pow(height);
    leaves_offset + index
}

fn hash(x: impl AsRef<[u8]>) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(x.as_ref());
    hasher.finalize().into()
}

fn hash_pair<T>(x: T, y: T) -> Digest
where
    T: AsRef<[u8]> + Ord,
{
    let mut hasher = Sha256::new();

    if x < y {
        hasher.update(x.as_ref());
        hasher.update(y.as_ref());
    } else {
        hasher.update(y.as_ref());
        hasher.update(x.as_ref());
    }

    hasher.finalize().into()
}

fn default_nodes(default_leaf: Digest, height: u32) -> Vec<Digest> {
    let mut default_node = default_leaf;
    let mut default_nodes = vec![default_node];

    for _ in 0..height {
        default_node = hash_pair(default_node, default_node);
        default_nodes.push(default_node);
    }

    default_nodes
}

#[cfg(test)]
mod tests {
    use crate::*;

    #[test]
    fn default_nodes_height_0() {
        let nodes = default_nodes(DEFAULT_LEAF, 0);
        let expected_nodes = vec![DEFAULT_LEAF];
        assert_eq!(nodes, expected_nodes);
    }

    #[test]
    fn default_nodes_height_1() {
        let nodes = default_nodes(DEFAULT_LEAF, 1);
        let height_1_node = hash_pair(DEFAULT_LEAF, DEFAULT_LEAF);
        let expected_nodes = vec![DEFAULT_LEAF, height_1_node];
        assert_eq!(nodes, expected_nodes);
    }

    #[test]
    fn default_nodes_height_2() {
        let nodes = default_nodes(DEFAULT_LEAF, 2);
        let height_1_node = hash_pair(DEFAULT_LEAF, DEFAULT_LEAF);
        let height_2_node = hash_pair(height_1_node, height_1_node);
        let expected_nodes = vec![DEFAULT_LEAF, height_1_node, height_2_node];
        assert_eq!(nodes, expected_nodes);
    }

    #[test]
    fn empty_tree_height_0() {
        let tree = MerkleTree::new(0);
        let root = tree.root();
        let expected_root = default_nodes(DEFAULT_LEAF, 0).pop().unwrap();
        assert_eq!(root, expected_root);
    }

    #[test]
    fn empty_tree_height_1() {
        let tree = MerkleTree::new(1);
        let root = tree.root();
        let expected_root = default_nodes(DEFAULT_LEAF, 1).pop().unwrap();
        assert_eq!(root, expected_root);
    }

    #[test]
    fn empty_tree_height_32() {
        let tree = MerkleTree::new(32);
        let root = tree.root();
        let expected_root = default_nodes(DEFAULT_LEAF, 32).pop().unwrap();
        assert_eq!(root, expected_root);
    }

    #[test]
    fn root_height_0() {
        let mut tree = MerkleTree::new(0);
        let root = tree.insert(0, "a");
        let expected_root = hash("a");
        assert_eq!(root, expected_root);
    }

    #[test]
    fn root_height_1() {
        let mut tree = MerkleTree::new(1);

        let root = tree.insert(0, "a");
        let expected_root = hash_pair(hash("a"), DEFAULT_LEAF);
        assert_eq!(root, expected_root);

        let root = tree.insert(1, "b");
        let expected_root = hash_pair(hash("a"), hash("b"));
        assert_eq!(root, expected_root);
    }

    #[test]
    fn root_height_2() {
        let mut tree = MerkleTree::new(2);

        let root = tree.insert(0, "a");
        let height_1_node_0 = hash_pair(hash("a"), DEFAULT_LEAF);
        let height_1_node_1 = hash_pair(DEFAULT_LEAF, DEFAULT_LEAF);
        let expected_root = hash_pair(height_1_node_0, height_1_node_1);
        assert_eq!(root, expected_root);

        let root = tree.insert(1, "b");
        let height_1_node_0 = hash_pair(hash("a"), hash("b"));
        let height_1_node_1 = hash_pair(DEFAULT_LEAF, DEFAULT_LEAF);
        let expected_root = hash_pair(height_1_node_0, height_1_node_1);
        assert_eq!(root, expected_root);

        let root = tree.insert(2, "c");
        let height_1_node_0 = hash_pair(hash("a"), hash("b"));
        let height_1_node_1 = hash_pair(hash("c"), DEFAULT_LEAF);
        let expected_root = hash_pair(height_1_node_0, height_1_node_1);
        assert_eq!(root, expected_root);

        let root = tree.insert(3, "d");
        let height_1_node_0 = hash_pair(hash("a"), hash("b"));
        let height_1_node_1 = hash_pair(hash("c"), hash("d"));
        let expected_root = hash_pair(height_1_node_0, height_1_node_1);
        assert_eq!(root, expected_root);
    }

    #[test]
    fn proof_height_1() {
        let mut tree = MerkleTree::new(1);

        tree.insert(0, "a");
        let proof = tree.proof(0);
        let expected_proof = vec![DEFAULT_LEAF];
        assert_eq!(proof, expected_proof);
        assert!(tree.validate("a", proof));

        tree.insert(1, "b");
        let proof = tree.proof(1);
        let expected_proof = vec![hash("a")];
        assert_eq!(proof, expected_proof);
        assert!(tree.validate("b", proof));
    }

    #[test]
    fn proof_height_2() {
        let mut tree = MerkleTree::new(2);

        tree.insert(3, "d");
        let proof = tree.proof(3);
        let expected_proof = vec![DEFAULT_LEAF, hash_pair(DEFAULT_LEAF, DEFAULT_LEAF)];
        assert_eq!(proof, expected_proof);
        assert!(tree.validate("d", proof));

        tree.insert(1, "b");
        let proof = tree.proof(1);
        let expected_proof = vec![DEFAULT_LEAF, hash_pair(DEFAULT_LEAF, hash("d"))];
        assert_eq!(proof, expected_proof);
        assert!(tree.validate("b", proof));

        tree.insert(2, "c");
        let proof = tree.proof(2);
        let expected_proof = vec![hash("d"), hash_pair(DEFAULT_LEAF, hash("b"))];
        assert_eq!(proof, expected_proof);
        assert!(tree.validate("c", proof));

        tree.insert(0, "a");
        let proof = tree.proof(0);
        let expected_proof = vec![hash("b"), hash_pair(hash("c"), hash("d"))];
        assert_eq!(proof, expected_proof);
        assert!(tree.validate("a", proof));
    }
}
