use sha2::{Digest, Sha256};

type Hash = [u8; 32];

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

    pub fn proof_for_index(&self, index: usize) -> Vec<Hash> {
        let value = self.values.get(index).unwrap();
        self.proof(value)
    }

    pub fn proof(&self, val: &T) -> Vec<Hash> {
        let mut hasher = Sha256::new();
        hasher.update(val.as_bytes());
        let hash: Hash = hasher.finalize().try_into().unwrap();
        let leaf_idx = self.leaves().iter().position(|x| *x == hash).unwrap();

        let mut proof: Vec<Hash> = vec![];

        proof.push(hash);

        let mut node_idx = leaf_idx;
        for level_idx in 0..self.tree.len() - 1 {
            let sibling_idx = if node_idx % 2 == 0 {
                node_idx + 1
            } else {
                node_idx - 1
            };
            let sibling = self.tree[level_idx].get(sibling_idx).unwrap();
            proof.push(sibling.clone());
            node_idx = node_idx / 2;
        }

        proof
    }
}

pub fn verify_proof<T: AsBytes>(
    proof: Vec<Hash>,
    value: &T,
    index: usize,
    root_hash: Hash,
) -> bool {
    if proof.len() == 0 {
        panic!("Proof cannot be empty.");
    }

    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    let value_hash: Hash = hasher.finalize().try_into().unwrap();

    if value_hash != *proof.first().unwrap() {
        return false;
    }

    let mut last_hash = value_hash;
    let mut last_idx = index;
    for witness in proof.iter().skip(1) {
        let mut hasher = Sha256::new();

        match last_idx % 2 {
            0 => {
                hasher.update(last_hash);
                hasher.update(witness);
            }
            1 => {
                hasher.update(witness);
                hasher.update(last_hash);
            }
            _ => unreachable!(),
        }
        last_hash = hasher.finalize().try_into().unwrap();
        last_idx /= 2;
    }

    last_hash == root_hash
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

impl AsBytes for Vec<u8> {
    fn as_bytes(&self) -> &[u8] {
        self.as_slice()
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
    fn it_generates_proof_for_index() {
        let tree = MerkleTree::build(vec!["1", "2", "3", "4"]);
        let proof = tree.proof_for_index(0);
        assert_eq!(proof.len(), 3);
    }

    #[test]
    fn it_generates_proof() {
        let tree = MerkleTree::build(vec!["1", "2", "3", "4"]);
        let proof = tree.proof(&"1");
        assert_eq!(proof.len(), 3);
    }

    #[test]
    fn it_returns_correct_proof() {
        let seq = vec!["a", "b", "c", "d", "e", "f"];
        let tree = MerkleTree::build(seq.clone());
        let proof = tree.proof_for_index(0);

        let expected_proof = [
            "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
            "3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d",
            "bffe0b34dba16bc6fac17c08bac55d676cded5a4ade41fe2c9924a5dde8f3e5b",
            "20644c0eb539e6f0efb9569a8aa45429a44f3c769c5cc9a69ef0901a4a05e49d",
        ];
        let expected_proof_bytes: Vec<Hash> = expected_proof
            .into_iter()
            .map(|x| hex::decode(x).unwrap().try_into().unwrap())
            .collect();

        assert_eq!(proof, expected_proof_bytes);
    }

    #[test]
    fn it_verifies_a_valid_proof() {
        let tree = MerkleTree::build(vec!["1", "2", "3", "4"]);
        let proof = tree.proof(&"1");
        assert!(verify_proof(proof, &"1", 0, tree.root()));

        let proof_2 = tree.proof(&"2");
        assert!(verify_proof(proof_2, &"2", 1, tree.root()));
    }

    #[test]
    fn it_fails_an_invalid_proof() {
        let tree = MerkleTree::build(vec!["1", "2", "3", "4"]);
        let proof = tree.proof(&"2");
        assert_eq!(false, verify_proof(proof, &"1", 0, tree.root()));
    }

    #[test]
    fn it_fails_an_invalid_index() {
        let tree = MerkleTree::build(vec!["1", "2", "3", "4"]);
        let proof = tree.proof(&"3");
        assert_eq!(false, verify_proof(proof, &"3", 3, tree.root()));
    }

    #[test]
    fn it_fails_an_invalid_root() {
        let tree = MerkleTree::build(vec!["1", "2", "3", "4"]);
        let proof = tree.proof(&"2");
        assert_eq!(false, verify_proof(proof, &"2", 1, [0; 32]));
    }

    #[test]
    fn it_fails_a_shorter_proof() {
        let seq = vec!["a", "b", "c", "d", "e", "f"];
        let tree = MerkleTree::build(seq.clone());

        // original proof
        // "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
        // "3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d",
        // "bffe0b34dba16bc6fac17c08bac55d676cded5a4ade41fe2c9924a5dde8f3e5b",
        // "20644c0eb539e6f0efb9569a8aa45429a44f3c769c5cc9a69ef0901a4a05e49d",
        let mut proof = tree.proof_for_index(0);
        proof.remove(0);
        proof.remove(0);
        let inter: [u8; 32] =
            hex::decode("e5a01fee14e0ed5c48714f22180f25ad8365b53f9779f79dc4a3d7e93963f94a")
                .unwrap()
                .try_into()
                .unwrap();
        proof.insert(0, inter);
        // modified, shorter proof
        // "e5a01fee14e0ed5c48714f22180f25ad8365b53f9779f79dc4a3d7e93963f94a",
        // "bffe0b34dba16bc6fac17c08bac55d676cded5a4ade41fe2c9924a5dde8f3e5b",
        // "20644c0eb539e6f0efb9569a8aa45429a44f3c769c5cc9a69ef0901a4a05e49d",

        // we concat two previous hashes and present as the leaf value
        // ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb
        // 3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d
        let value = hex::decode("ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d")
            .unwrap();

        assert_eq!(false, verify_proof(proof, &value, 0, tree.root()));
    }
}
