use sha2::{Digest, Sha256};

const POS_LEFT: u8 = 0;
const POS_RIGHT: u8 = 1;

type Hash = [u8; 32];

#[derive(Debug)]
pub struct MerkleProofStep {
    position: u8,
    hash: Hash,
}

#[derive(Debug)]
pub struct MerkleTree<T: AsBytes> {
    pub values: Vec<T>,
    // TODO use a more efficient data structure
    tree: Vec<Vec<Hash>>,
}

impl<T: AsBytes> MerkleTree<T> {
    // TODO potentially prefix leaves and internal nodes
    pub fn build(values: Vec<T>) -> Self {
        assert!(values.len() > 0, "Merkle tree must have at least one value");

        let leaves: Vec<Hash> = values
            .iter()
            .map(|x| {
                let mut hasher = Sha256::new();
                hasher.update(x.as_bytes());
                hasher.finalize().try_into().unwrap()
            })
            .collect();

        let mut tree = vec![leaves];
        while tree.last().unwrap().len() > 1 {
            let mut level = vec![];
            for idx in (0..tree.last().unwrap().len()).step_by(2) {
                let mut hasher = Sha256::new();
                let left = tree.last().unwrap()[idx];
                // hash the value with itself if there is no right value
                let right = tree.last().unwrap().get(idx + 1).unwrap_or(&left);
                hasher.update(left);
                hasher.update(right);
                let hash = hasher.finalize().try_into().unwrap();
                level.push(hash);
            }
            tree.push(level);
        }

        Self { values, tree }
    }

    pub fn root(&self) -> Hash {
        self.tree.last().unwrap().first().unwrap().clone()
    }

    pub fn leaves(&self) -> Vec<Hash> {
        self.tree.first().unwrap().clone()
    }

    pub fn proof(&self, val: T) -> Vec<MerkleProofStep> {
        let mut hasher = Sha256::new();
        hasher.update(val.as_bytes());
        let hash: Hash = hasher.finalize().try_into().unwrap();
        let leaf_idx = self.leaves().iter().position(|x| *x == hash).unwrap();

        let mut proof: Vec<MerkleProofStep> = vec![];

        proof.push(MerkleProofStep {
            position: if leaf_idx % 2 == 0 {
                POS_LEFT
            } else {
                POS_RIGHT
            },
            hash,
        });

        let mut node_idx = leaf_idx;
        for level_idx in 0..self.tree.len() - 1 {
            let sibling_idx = if node_idx % 2 == 0 {
                node_idx + 1
            } else {
                node_idx - 1
            };
            let sibling = self.tree[level_idx].get(sibling_idx).unwrap();
            let position = if sibling_idx % 2 == 0 {
                POS_LEFT
            } else {
                POS_RIGHT
            };
            proof.push(MerkleProofStep {
                position,
                hash: sibling.clone(),
            });
            node_idx = node_idx / 2;
        }

        proof
    }
}

pub fn verify_proof<T: AsBytes>(proof: Vec<MerkleProofStep>, value: T, root_hash: Hash) -> bool {
    if proof.len() == 0 {
        panic!("Proof cannot be empty.");
    }

    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    let value_hash: Hash = hasher.finalize().try_into().unwrap();

    if value_hash != proof.first().unwrap().hash {
        return false;
    }

    let mut last = value_hash;
    for step in proof.iter().skip(1) {
        let mut hasher = Sha256::new();

        match step.position {
            POS_LEFT => {
                hasher.update(step.hash);
                hasher.update(last);
            }
            POS_RIGHT => {
                hasher.update(last);
                hasher.update(step.hash);
            }
            _ => panic!("Invalid proof step position."),
        }
        last = hasher.finalize().try_into().unwrap();
    }

    last == root_hash
}

pub trait AsBytes {
    fn as_bytes(&self) -> &[u8];
}

impl<'a> AsBytes for &'a str {
    fn as_bytes(&self) -> &[u8] {
        str::as_bytes(self)
    }
}

impl AsBytes for String {
    fn as_bytes(&self) -> &[u8] {
        String::as_bytes(self)
    }
}

impl<'a> AsBytes for &'a [u8] {
    fn as_bytes(&self) -> &[u8] {
        *self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    #[test]
    fn it_saves_values() {
        let seq = vec!["1", "2", "3", "4"];
        let tree = MerkleTree::build(seq.clone());
        assert_eq!(seq, tree.values);
        assert_eq!(tree.values.len(), tree.leaves().len());
    }

    #[test]
    fn it_generates_tree() {
        let tree_even = MerkleTree::build(vec!["1", "2", "3", "4"]);
        assert_eq!(tree_even.tree.len(), 3);

        let tree_odd = MerkleTree::build(vec!["1", "2", "3"]);
        assert_eq!(tree_odd.tree.len(), 3);

        let tree_one = MerkleTree::build(vec!["1"]);
        assert_eq!(tree_one.tree.len(), 1);
    }

    #[test]
    fn it_returns_correct_root() {
        let seq = vec!["a", "b", "c", "d", "e", "f"];
        let expected_root_hex = "44205acec5156114821f1f71d87c72e0de395633cd1589def6d4444cc79f8103";
        let tree = MerkleTree::build(seq.clone());
        assert_eq!(hex::decode(expected_root_hex).unwrap(), tree.root());
    }

    #[test]
    fn it_generates_proof() {
        let tree = MerkleTree::build(vec!["1", "2", "3", "4"]);
        let proof = tree.proof("1");
        assert_eq!(proof.len(), 3);
    }

    #[test]
    fn it_verifies_a_valid_proof() {
        let tree = MerkleTree::build(vec!["1", "2", "3", "4"]);
        let proof = tree.proof("1");
        assert!(verify_proof(proof, "1", tree.root()));

        let proof_2 = tree.proof("2");
        assert!(verify_proof(proof_2, "2", tree.root()));
    }

    #[test]
    fn it_fails_an_invalid_proof() {
        let tree = MerkleTree::build(vec!["1", "2", "3", "4"]);
        let proof = tree.proof("2");
        assert_eq!(false, verify_proof(proof, "1", tree.root()));
    }

    #[test]
    fn it_fails_an_invalid_root() {
        let tree = MerkleTree::build(vec!["1", "2", "3", "4"]);
        let proof = tree.proof("2");
        assert_eq!(false, verify_proof(proof, "2", [0; 32]));
    }
}
