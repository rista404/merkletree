use sha2::{Digest, Sha256};

pub struct MerkleTree<T: std::fmt::Binary> {
    pub values: Vec<T>,
    tree: Vec<Vec<[u8; 32]>>,
}

impl<T: std::fmt::Binary> MerkleTree<T> {
    pub fn build(values: Vec<T>) -> Self {
        let leaves: Vec<[u8; 32]> = values
            .iter()
            .map(|x| {
                let mut hasher = Sha256::new();
                hasher.update(format!("{:b}", x));
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

    pub fn leaves(&self) -> Vec<[u8; 32]> {
        self.tree.first().unwrap().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_saves_sequence() {
        let seq = vec![1, 2, 3, 4];
        let tree = MerkleTree::build(seq.clone());
        assert_eq!(seq, tree.values);
        assert_eq!(tree.values.len(), tree.leaves().len());
    }

    #[test]
    fn it_generates_tree() {
        let tree_even = MerkleTree::build(vec![1, 2, 3, 4]);
        assert_eq!(tree_even.tree.len(), 3);

        let tree_odd = MerkleTree::build(vec![1, 2, 3]);
        assert_eq!(tree_odd.tree.len(), 3);

        let tree_one = MerkleTree::build(vec![1]);
        assert_eq!(tree_one.tree.len(), 1);

        println!("{:x?}", tree_one.leaves().first().unwrap());
    }
}
