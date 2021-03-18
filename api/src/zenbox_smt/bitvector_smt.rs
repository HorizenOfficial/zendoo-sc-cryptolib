////////////BITVECTOR SPARSE MERKLE TREE

use primitives::{BigMerkleTree, Coord};
use crate::ginger_calls::{GingerMerkleTreeParameters, Error, FieldElement, GingerMHTPath, restore_ginger_smt, new_ginger_smt};
use algebra::fields::mnt6753::FqParameters;
use algebra::{FpParameters, ToBits};
use std::path::Path;

pub type BitvectorSMT = BigMerkleTree<GingerMerkleTreeParameters>;

// Computes floor(log2(x))
const fn log2(x: u64) -> usize {
    std::mem::size_of::<u64>() * 8 - x.leading_zeros() as usize - 1usize
}

// Size of a BVT leaf in bits
pub const BVT_LEAF_SIZE: u64 = FqParameters::CAPACITY as u64;
pub const BVT_LEAF_SIZE_LOG2: usize = log2(BVT_LEAF_SIZE);

pub fn get_bvt(height: usize, db_path: &str) -> Result<BitvectorSMT, Error>{
    // If at least the leaves database is available, we can restore the tree
    if Path::new(db_path).exists() {
        restore_ginger_smt(height, db_path)
    } else { // Otherwise we need to create a new tree
        new_ginger_smt(height, db_path)
    }
}

pub fn flush_bvt(tree: &mut BitvectorSMT) {
    tree.flush()
}

pub fn set_bvt_persistency(tree: &mut BitvectorSMT, persistency: bool) {
    tree.set_persistency(persistency)
}

pub fn get_bvt_root(tree: &BitvectorSMT) -> FieldElement {
    tree.get_root()
}

pub fn get_bvt_path(tree: &mut BitvectorSMT, bit_position: u64) -> GingerMHTPath {
    tree.get_merkle_path(Coord::new(0, (bit_position / BVT_LEAF_SIZE) as usize))
}

pub fn get_bvt_leaf(tree: &BitvectorSMT, bit_position: u64) -> Option<FieldElement> {
    get_bvt_leaf_by_index(tree, bit_position / BVT_LEAF_SIZE)
}

pub fn set_bvt_bit(tree: &mut BitvectorSMT, bit_position: u64){
    modify_bit_in_bvt(tree, bit_position, true)
}

pub fn reset_bvt_bit(tree: &mut BitvectorSMT, bit_position: u64){
    modify_bit_in_bvt(tree, bit_position, false)
}

pub fn get_bvt_bit(tree: &BitvectorSMT, bit_position: u64) -> bool {
    if let Some(leaf) = get_bvt_leaf(tree, bit_position) {
        let leaf_bits= leaf.write_bits();
        assert_eq!(BVT_LEAF_SIZE, (leaf_bits.len() - 1) as u64);
        // The LSB bits are at the MSB positions
        leaf_bits[(BVT_LEAF_SIZE - (bit_position % BVT_LEAF_SIZE)) as usize]
    } else { // leaf doesn't even exist, so the bit isn't set
        false
    }
}

fn get_bvt_leaf_by_index(tree: &BitvectorSMT, leaf_index: u64) -> Option<FieldElement> {
    tree.get_leaf(Coord::new(0, leaf_index as usize))
}

fn modify_bit_in_bvt(tree: &mut BitvectorSMT, bit_position: u64, bit_value: bool){
    use algebra::{Field, FromBits};

    let updated_leaf = FieldElement::read_bits(
        {
            let mut leaf_bits =
                if let Some(leaf) = get_bvt_leaf(tree, bit_position) {
                    leaf.write_bits()
                } else { // leaf doesn't exist, so create an empty leaf
                    FieldElement::zero().write_bits()
                };
            assert_eq!(BVT_LEAF_SIZE, (leaf_bits.len() - 1) as u64);
            // The LSB bits are at the MSB positions
            leaf_bits[(BVT_LEAF_SIZE - (bit_position % BVT_LEAF_SIZE)) as usize] = bit_value;
            leaf_bits
        }
    ).unwrap();

    let leaf_index = (bit_position / BVT_LEAF_SIZE) as usize;
    if !updated_leaf.is_zero() {
        // Write an updated leaf value
        tree.insert_leaf(Coord::new(0, leaf_index), updated_leaf);
    } else {
        // Don't store empty leafs to optimize SMT size
        tree.remove_leaf(Coord::new(0, leaf_index))
    }
}

#[cfg(test)]
mod test {
    use crate::zenbox_smt::bitvector_smt::{BVT_LEAF_SIZE, get_bvt, set_bvt_bit, get_bvt_bit, reset_bvt_bit, get_bvt_leaf_by_index, get_bvt_leaf, get_bvt_path, set_bvt_persistency};
    use algebra::ToBits;

    #[test]
    fn sample_calls_bitvector_tree(){
        // This test is specified for a 752-bit bitvectors, that corresponds to a 753-bit field elements
        // Here a bitvector is a sequential chunk of bits, that corresponds to one leaf of a field based SMT with 753-bit leafs.

        assert_eq!(BVT_LEAF_SIZE, 752);

        // Get BitvectorTree of height 4 to decrease time of the test run
        let mut bvt = get_bvt(4, "/tmp/temp_bvt_db").unwrap();

        // To make test run not too long the number of tested bits per leaf is at step = 47 times lesser
        let step = (BVT_LEAF_SIZE / 16) as usize;
        // Minimal step is 2. The fully filled leafs will be tested with such a step but it takes around 12 minutes to run this test
        // let step = 2;
        assert!(step >= 2);

        let bv_msb_offset = step as u64 - 1;

        // Maps position inside of a bitvector to a bit value
        let bit_by_position = |pos: u64| -> bool {
            (pos % step as u64 == 0) |                                                 // LSB of a bitvector
                ((pos >= bv_msb_offset) && ((pos - bv_msb_offset) % step as u64 == 0)) // MSB of a bitvector
        };

        // Setting bits in the first bitvector
        for pos in 0..BVT_LEAF_SIZE {
            if bit_by_position(pos) {
                set_bvt_bit(&mut bvt, pos);
            }
        }
        // Checking that corresponding bits in the first bitvector are set, while all the other bits are not set
        for pos in 0..BVT_LEAF_SIZE {
            assert_eq!(get_bvt_bit(&bvt, pos as u64), bit_by_position(pos));
        }

        // Setting bits in the second bitvector
        for pos in 0..BVT_LEAF_SIZE {
            if bit_by_position(pos) {
                set_bvt_bit(&mut bvt, BVT_LEAF_SIZE + pos);
            }
        }

        // Reseting the previously set bits in the first bitvector
        for pos in 0..BVT_LEAF_SIZE {
            if bit_by_position(pos) {
                reset_bvt_bit(&mut bvt, pos);
            }
        }

        //-------------------------------------
        // Checking the first bitvector
        //-------------------------------------
        // All bits in the first bitvector should be reset
        for pos in 0..BVT_LEAF_SIZE {
            assert_eq!(get_bvt_bit(&bvt, pos), false);
        }
        // Low-level check: First leaf should be absent due to a stored bitvector is empty
        assert_eq!(get_bvt_leaf_by_index(&bvt, 0), None);

        //-------------------------------------
        // Checking the second bitvector
        //-------------------------------------
        // Checking that corresponding bits in the second bitvector are set, while all the other bits are not set
        for pos in 0..BVT_LEAF_SIZE {
            assert_eq!(get_bvt_bit(&bvt, BVT_LEAF_SIZE + pos), bit_by_position(pos));
        }
        // Low-level check: parsing directly the leaf containing the second bitvector
        let second_leaf_bits = get_bvt_leaf_by_index(&bvt, 1).unwrap().write_bits();
        // Reversing bits due to a FieldElement is deserialized in the BigEndian format
        let second_bitvector: Vec<bool> = second_leaf_bits.iter().rev().take(BVT_LEAF_SIZE as usize).map(|b|*b).collect();
        for pos in 0..BVT_LEAF_SIZE {
            assert_eq!(second_bitvector[pos as usize], bit_by_position(pos));
        }

        let second_leaf_lsb_pos = BVT_LEAF_SIZE;

        // Checking that the bit position is correctly mapped to a BVT leaf position
        assert_eq!(get_bvt_leaf(&bvt, second_leaf_lsb_pos).unwrap(),
                   get_bvt_leaf_by_index(&bvt, 1).unwrap());

        // Checking that Merkle Paths are the same for bits from the same leafs
        assert_eq!(get_bvt_path(&mut bvt, 0),
                   get_bvt_path(&mut bvt, BVT_LEAF_SIZE - 1));
        assert_eq!(get_bvt_path(&mut bvt, second_leaf_lsb_pos),
                   get_bvt_path(&mut bvt, second_leaf_lsb_pos + BVT_LEAF_SIZE - 1));

        // Checking that Merkle Paths are different for bits from different leafs
        assert_ne!(get_bvt_path(&mut bvt, BVT_LEAF_SIZE - 1),
                   get_bvt_path(&mut bvt, BVT_LEAF_SIZE));

        //Deleting BVTs data
        set_bvt_persistency(&mut bvt, false);
    }
}
