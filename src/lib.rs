use sha2::{Digest as Sha2DigestTrait, Sha256};
use snafu::Snafu;
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

    pub fn insert(
        &mut self,
        index: usize,
        value: impl AsRef<[u8]>,
    ) -> Result<Digest, MerkleTreeError> {
        bounds_check(self.height, index)?;

        let leaf_index = index_of(self.height, index);
        let node = hash(value);
        self.values.insert(leaf_index, node);

        let root = (0..self.height).into_iter().fold(node, |node, h| {
            let node_index = leaf_index / 2usize.pow(h);

            let sibling_index = if node_index % 2 == 0 {
                node_index + 1
            } else {
                node_index - 1
            };

            let sibling = *self
                .values
                .get(&sibling_index)
                .unwrap_or(&self.default_nodes[h as usize]);

            let parent_index = node_index / 2;
            let parent = hash_pair(node, sibling);
            self.values.insert(parent_index, parent);

            parent
        });

        Ok(root)
    }

    pub fn proof(&self, index: usize) -> Result<Vec<Digest>, MerkleTreeError> {
        bounds_check(self.height, index)?;

        let leaf_index = index_of(self.height, index);

        let nodes = (0..self.height)
            .map(|h| {
                let node_index = leaf_index / 2usize.pow(h);

                let sibling_index = if node_index % 2 == 0 {
                    node_index + 1
                } else {
                    node_index - 1
                };

                *self
                    .values
                    .get(&sibling_index)
                    .unwrap_or(&self.default_nodes[h as usize])
            })
            .collect();

        Ok(nodes)
    }

    pub fn validate(
        &self,
        value: impl AsRef<[u8]>,
        proof: Vec<Digest>,
    ) -> Result<bool, MerkleTreeError> {
        if proof.len() != self.height as usize {
            return Err(MerkleTreeError::ProofLengthIncorrect {
                len: proof.len(),
                height: self.height as usize,
            });
        }

        let proof_root = proof.into_iter().fold(hash(value), |node, sibling| {
            hash_pair(node, sibling) // parent
        });

        Ok(proof_root == self.root())
    }

    pub fn indexes_of(&self, value: impl AsRef<[u8]>) -> Option<Vec<usize>> {
        let value_hash = hash(value);

        let first_index = index_of(self.height, 0);

        let mut indexes = self
            .values
            .iter()
            .filter(|(k, v)| **k > first_index && **v == value_hash)
            .map(|(k, _)| *k - first_index)
            .collect::<Vec<usize>>();

        indexes.sort();

        if indexes.len() != 0 {
            Some(indexes)
        } else {
            None
        }
    }

    pub fn contains(&self, value: impl AsRef<[u8]>) -> bool {
        match self.indexes_of(value) {
            Some(..) => true,
            None => false,
        }
    }
}

fn bounds_check(height: u32, index: usize) -> Result<(), MerkleTreeError> {
    let len = 2usize.pow(height);

    if index >= len {
        return Err(MerkleTreeError::IndexOutOfBounds { len, index });
    } else {
        Ok(())
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

#[derive(Debug, Snafu, PartialEq)]
pub enum MerkleTreeError {
    #[snafu(display("index out of bounds: the len is {} but the index is {}", len, index))]
    IndexOutOfBounds { len: usize, index: usize },

    #[snafu(display(
        "proof length incorrect: the len is {} but the height is {}",
        len,
        height
    ))]
    ProofLengthIncorrect { len: usize, height: usize },
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
        let root = tree.insert(0, "a").unwrap();
        let expected_root = hash("a");
        assert_eq!(root, expected_root);
    }

    #[test]
    fn root_height_1() {
        let mut tree = MerkleTree::new(1);

        let root = tree.insert(0, "a").unwrap();
        let expected_root = hash_pair(hash("a"), DEFAULT_LEAF);
        assert_eq!(root, expected_root);

        let root = tree.insert(1, "b").unwrap();
        let expected_root = hash_pair(hash("a"), hash("b"));
        assert_eq!(root, expected_root);
    }

    #[test]
    fn root_height_2() {
        let mut tree = MerkleTree::new(2);

        let root = tree.insert(0, "a").unwrap();
        let height_1_node_0 = hash_pair(hash("a"), DEFAULT_LEAF);
        let height_1_node_1 = hash_pair(DEFAULT_LEAF, DEFAULT_LEAF);
        let expected_root = hash_pair(height_1_node_0, height_1_node_1);
        assert_eq!(root, expected_root);

        let root = tree.insert(1, "b").unwrap();
        let height_1_node_0 = hash_pair(hash("a"), hash("b"));
        let height_1_node_1 = hash_pair(DEFAULT_LEAF, DEFAULT_LEAF);
        let expected_root = hash_pair(height_1_node_0, height_1_node_1);
        assert_eq!(root, expected_root);

        let root = tree.insert(2, "c").unwrap();
        let height_1_node_0 = hash_pair(hash("a"), hash("b"));
        let height_1_node_1 = hash_pair(hash("c"), DEFAULT_LEAF);
        let expected_root = hash_pair(height_1_node_0, height_1_node_1);
        assert_eq!(root, expected_root);

        let root = tree.insert(3, "d").unwrap();
        let height_1_node_0 = hash_pair(hash("a"), hash("b"));
        let height_1_node_1 = hash_pair(hash("c"), hash("d"));
        let expected_root = hash_pair(height_1_node_0, height_1_node_1);
        assert_eq!(root, expected_root);
    }

    #[test]
    fn tree_index_bounds_check() {
        assert_eq!(
            MerkleTree::new(1).insert(2, "should_error").unwrap_err(),
            MerkleTreeError::IndexOutOfBounds { len: 2, index: 2 }
        );

        assert_eq!(
            MerkleTree::new(2).insert(4, "should_error").unwrap_err(),
            MerkleTreeError::IndexOutOfBounds { len: 4, index: 4 }
        );
    }

    #[test]
    fn proof_height_1() {
        let mut tree = MerkleTree::new(1);

        tree.insert(0, "a").unwrap();
        let proof = tree.proof(0).unwrap();
        let expected_proof = vec![DEFAULT_LEAF];
        assert_eq!(proof, expected_proof);
        assert!(tree.validate("a", proof).unwrap());

        tree.insert(1, "b").unwrap();
        let proof = tree.proof(1).unwrap();
        let expected_proof = vec![hash("a")];
        assert_eq!(proof, expected_proof);
        assert!(tree.validate("b", proof).unwrap());
    }

    #[test]
    fn proof_height_2() {
        let mut tree = MerkleTree::new(2);

        tree.insert(3, "d").unwrap();
        let proof = tree.proof(3).unwrap();
        let expected_proof = vec![DEFAULT_LEAF, hash_pair(DEFAULT_LEAF, DEFAULT_LEAF)];
        assert_eq!(proof, expected_proof);
        assert!(tree.validate("d", proof).unwrap());

        tree.insert(1, "b").unwrap();
        let proof = tree.proof(1).unwrap();
        let expected_proof = vec![DEFAULT_LEAF, hash_pair(DEFAULT_LEAF, hash("d"))];
        assert_eq!(proof, expected_proof);
        assert!(tree.validate("b", proof).unwrap());

        tree.insert(2, "c").unwrap();
        let proof = tree.proof(2).unwrap();
        let expected_proof = vec![hash("d"), hash_pair(DEFAULT_LEAF, hash("b"))];
        assert_eq!(proof, expected_proof);
        assert!(tree.validate("c", proof).unwrap());

        tree.insert(0, "a").unwrap();
        let proof = tree.proof(0).unwrap();
        let expected_proof = vec![hash("b"), hash_pair(hash("c"), hash("d"))];
        assert_eq!(proof, expected_proof);
        assert!(tree.validate("a", proof).unwrap());
    }

    #[test]
    fn proof_bounds_check() {
        assert_eq!(
            MerkleTree::new(1).proof(2).unwrap_err(),
            MerkleTreeError::IndexOutOfBounds { len: 2, index: 2 }
        );

        assert_eq!(
            MerkleTree::new(2).proof(4).unwrap_err(),
            MerkleTreeError::IndexOutOfBounds { len: 4, index: 4 }
        );
    }

    #[test]
    fn proof_length_check() {
        assert_eq!(
            MerkleTree::new(1)
                .validate("empty_proof", vec![])
                .unwrap_err(),
            MerkleTreeError::ProofLengthIncorrect { len: 0, height: 1 }
        );

        assert_eq!(
            MerkleTree::new(1)
                .validate("empty_proof", vec![DEFAULT_LEAF, DEFAULT_LEAF])
                .unwrap_err(),
            MerkleTreeError::ProofLengthIncorrect { len: 2, height: 1 }
        );
    }

    #[test]
    fn indexes_of() {
        let mut tree = MerkleTree::new(2);

        tree.insert(1, "a").unwrap();
        let indexes = tree.indexes_of("a").unwrap();
        let expected_indexes = vec![1];
        assert_eq!(indexes, expected_indexes);

        tree.insert(3, "a").unwrap();
        let indexes = tree.indexes_of("a").unwrap();
        let expected_indexes = vec![1, 3];
        assert_eq!(indexes, expected_indexes);

        assert!(tree.indexes_of("not_in").is_none());
    }

    #[test]
    fn contains() {
        let mut tree = MerkleTree::new(2);

        assert!(!tree.contains("a"));

        tree.insert(3, "a").unwrap();
        assert!(tree.contains("a"));

        tree.insert(0, "a").unwrap();
        assert!(tree.contains("a"));
    }
}
