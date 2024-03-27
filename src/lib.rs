use sha2::{Digest, Sha256};

type Hash = [u8; 32];

#[derive(Debug)]
pub struct MerkleTree<T: AsBytes> {
    pub values: Vec<T>,
    // TODO use a more efficient data structure
    tree: Vec<Vec<Hash>>,
}

fn hash_leaf(input: &[u8]) -> Hash {
    let hash = |bs: &[u8]| -> Hash {
        let mut hasher = Sha256::new();
        hasher.update(bs);
        hasher.finalize().try_into().unwrap()
    };

    return hash(&hash(input));
}

impl<T: AsBytes> MerkleTree<T> {
    // TODO potentially prefix leaves and internal nodes
    pub fn build(values: Vec<T>) -> Self {
        assert!(values.len() > 0, "Merkle tree must have at least one value");

        let leaves: Vec<Hash> = values.iter().map(|x| hash_leaf(x.as_bytes())).collect();

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
        let hash = hash_leaf(val.as_bytes());
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
            let sibling = match self.tree[level_idx].get(sibling_idx) {
                Some(s) => s,
                None => self.tree[level_idx].get(node_idx).unwrap(),
            };
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

    let value_hash = hash_leaf(value.as_bytes());
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
        let expected_root_hex = "feb77f593c70b7ed78a91ca560cbb22bbd59a57435347f3a13e6cfe8cd1cd3b4";
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
            "bf5d3affb73efd2ec6c36ad3112dd933efed63c4e1cbffcfa88e2759c144f2d8",
            "39361160903c6695c6804b7157c7bd10013e9ba89b1f954243bc8e3990b08db9",
            "ea0e26f7cde803d8090cf15c25d7842a1adc46a390405bcd7bb158258774e270",
            "a92b7d95b0924513886d25cd20da9a2493a42d7e14b6b1032420f2440399f986",
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
    fn it_verifies_an_odd_leaf() {
        let seq = vec!["a", "b", "c"];
        let tree = MerkleTree::build(seq.clone());
        let proof = tree.proof_for_index(2);
        assert!(verify_proof(proof, &seq[2], 2, tree.root()));
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
        // "bf5d3affb73efd2ec6c36ad3112dd933efed63c4e1cbffcfa88e2759c144f2d8",
        // "39361160903c6695c6804b7157c7bd10013e9ba89b1f954243bc8e3990b08db9",
        // "ea0e26f7cde803d8090cf15c25d7842a1adc46a390405bcd7bb158258774e270",
        // "a92b7d95b0924513886d25cd20da9a2493a42d7e14b6b1032420f2440399f986",
        let mut proof = tree.proof_for_index(0);

        // first verify the proof is valid
        assert_eq!(true, verify_proof(proof.clone(), &seq[0], 0, tree.root()));

        let one = proof.remove(0);
        let two = proof.remove(0);

        // concat first two hashes and present as the leaf value
        // bf5d3affb73efd2ec6c36ad3112dd933efed63c4e1cbffcfa88e2759c144f2d8
        // 39361160903c6695c6804b7157c7bd10013e9ba89b1f954243bc8e3990b08db9
        let mut value: Vec<u8> = (0..64).collect();
        value[..32].clone_from_slice(&one);
        value[32..].clone_from_slice(&two);

        // hash the concatenated value as if was a leaf
        // and add it to the proof
        let inter = hash_leaf(value.as_bytes());
        // b767a3a12f5f8bb1949d163c51f9a42e6bda8dcd02d50353717f73d4338b1bf0
        proof.insert(0, inter);

        // modified, shorter proof
        // "b767a3a12f5f8bb1949d163c51f9a42e6bda8dcd02d50353717f73d4338b1bf0",
        // "ea0e26f7cde803d8090cf15c25d7842a1adc46a390405bcd7bb158258774e270",
        // "a92b7d95b0924513886d25cd20da9a2493a42d7e14b6b1032420f2440399f986",

        assert_eq!(false, verify_proof(proof, &value, 0, tree.root()));
    }

    #[test]
    fn it_fails_invalid_value_single_leaf() {
        let seq = vec!["a"];
        let tree = MerkleTree::build(seq.clone());
        let proof = tree.proof_for_index(0);
        assert_eq!(false, verify_proof(proof.clone(), &"b", 0, tree.root()));
    }

    #[test]
    fn it_fails_invalid_index_single_leaf() {
        let seq = vec!["a"];
        let tree = MerkleTree::build(seq.clone());
        let proof = tree.proof_for_index(0);
        assert_eq!(false, verify_proof(proof.clone(), &seq[0], 1, tree.root()));
    }
}
