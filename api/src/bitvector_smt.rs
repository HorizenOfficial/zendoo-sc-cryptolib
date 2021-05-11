use primitives::{BigMerkleTree, Coord, FieldBasedBinaryMHTPath};
use algebra::{ToBits, FromBits, FpParameters, Field};
use std::path::Path;
use demo_circuit::type_mapping::*;

use algebra::fields::tweedle::FrParameters;

// Bitvector Sparse Merkle Tree

pub type BitvectorSMT = BigMerkleTree<GingerMHTParams>;
pub type GingerMHTBinaryPath = FieldBasedBinaryMHTPath<GingerMHTParams>;
pub type FieldElementParameters = FrParameters;

// Computes floor(log2(x))
const fn log2(x: u64) -> usize {
    std::mem::size_of::<u64>() * 8 - x.leading_zeros() as usize - 1usize
}

// Computes a power of 2
fn pow2(power: usize) -> usize {
    1 << power
}

// Size of a BVT leaf in bits
pub const BVT_LEAF_SIZE: u64 = FieldElementParameters::CAPACITY as u64;
pub const BVT_LEAF_SIZE_LOG2: usize = log2(BVT_LEAF_SIZE);
const FIELD_ELEMENT_SIZE: u64 = FieldElementParameters::MODULUS_BITS as u64;

pub fn new_bvt(height: usize, db_path: &str) -> Result<BitvectorSMT, Error> {
    match BitvectorSMT::new(
        height,
        true,
        db_path.to_owned(),
    ) {
        Ok(tree) => Ok(tree),
        Err(e) => Err(Box::new(e))
    }
}

pub fn restore_bvt(height: usize, db_path: &str) -> Result<BitvectorSMT, Error>
{
    match BitvectorSMT::load_batch::<GingerMerkleTreeParameters>(
        height,
        true,
        db_path.to_owned(),
    ) {
        Ok(tree) => Ok(tree),
        Err(e) => Err(Box::new(e))
    }
}

pub fn get_bvt(height: usize, db_path: &str) -> Result<BitvectorSMT, Error>{
    // If at least the leaves database is available, we can restore the tree
    if Path::new(db_path).exists() {
        restore_bvt(height, db_path)
    } else { // Otherwise we need to create a new tree
        new_bvt(height, db_path)
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

pub fn get_bvt_path(tree: &mut BitvectorSMT, bit_position: u64) -> GingerMHTBinaryPath {
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
        // BV bits are contained in reverse order: the MSB bits of a BV are at the LSB positions of a FieldElement-leaf
        // This is to avoid usage of the bits which are over the (MODULUS_BITS - 1) size
        leaf_bits[((FIELD_ELEMENT_SIZE - 1) - (bit_position % BVT_LEAF_SIZE)) as usize]
    } else { // leaf doesn't even exist, so the bit isn't set
        false
    }
}

fn get_bvt_leaf_by_index(tree: &BitvectorSMT, leaf_index: u64) -> Option<FieldElement> {
    tree.get_leaf(Coord::new(0, leaf_index as usize))
}

fn modify_bit_in_bvt(tree: &mut BitvectorSMT, bit_position: u64, bit_value: bool){
    use algebra::Field;

    let updated_leaf = FieldElement::read_bits(
        {
            let mut leaf_bits =
                if let Some(leaf) = get_bvt_leaf(tree, bit_position) {
                    leaf.write_bits()
                } else { // leaf doesn't exist, so create an empty leaf
                    FieldElement::zero().write_bits()
                };
            assert_eq!(BVT_LEAF_SIZE, (leaf_bits.len() - 1) as u64);
            // BV bits are contained in reverse order: the MSB bits of a BV are at the LSB positions of a FieldElement-leaf
            // This is to avoid usage of the bits which are over the (MODULUS_BITS - 1) size
            leaf_bits[((FIELD_ELEMENT_SIZE - 1) - (bit_position % BVT_LEAF_SIZE)) as usize] = bit_value;
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

fn serialize_bvt(tree: &BitvectorSMT) -> Vec<u8> {
    let mut bits = Vec::<bool>::new();
    let leaves_num = 1usize << tree.height();

    // Read sequentially all bits from BVT in BigEndian ordering
    for pos in 0.. leaves_num {
        if let Some(leaf) = tree.get_leaf(Coord::new(0, pos)){
            leaf.write_bits().iter() // the LSB bits of a BV are at the MSB positions of the leaf_bits
                .rev()// re-ordering into BigEndian
                .take(BVT_LEAF_SIZE as usize) // take only the BV-related bits of a current leaf
                .for_each(|bit|bits.push(*bit));
        } else { // if a leaf doesn't exist assume it contains all zero bits
            bits.extend(&vec![false; BVT_LEAF_SIZE as usize])
        }
    }
    // Builds a byte from a BigEndian-ordered sequence of bits
    fn byte_from_bits(bits: &[bool]) -> u8 {
        let mut byte = 0u8;
        bits.iter().enumerate().for_each(|(i, bit)| if *bit {byte |= 0x80 >> i});
        byte
    }
    // Splitting a whole bits-sequence into bytes
    bits.chunks(8).map(
        |bits_chunk| byte_from_bits(bits_chunk)
    ).collect()
}

fn initialize_bvt(tree: &mut BitvectorSMT, bvt_bytes: Vec<u8>) -> Result<(), Error>{
    // Converts byte-array into a sequence of FieldElement-leaves
    fn bytes_to_leaves(bytes: &[u8], bvt_bit_len: usize) -> Result<Vec<FieldElement>, Error> {
        fn bytes_to_bits(bytes: &[u8]) -> Vec<bool> {
            let mut bits = Vec::new();
            for byte in bytes {
                for i in 0..8 {
                    bits.push(((0x80 >> i) & *byte) != 0)
                }
            }
            bits
        }
        fn bits_to_leaves(bits: &Vec<bool>) -> Result<Vec<FieldElement>, Error> {
            if bits.len() % BVT_LEAF_SIZE as usize == 0 {
                let leaves: Vec<FieldElement> = bits.chunks(BVT_LEAF_SIZE as usize)
                    .flat_map(|leaf_bits|{ // using flat_map to handle possible Error returned by FieldElement::read_bits
                        // Initializing FieldElement-leaf with re-ordered into LittleEndian bits of BV
                        FieldElement::read_bits(leaf_bits.to_vec().into_iter().rev().collect())
                    }).collect();
                // Checking that all leaves are built successfully
                if leaves.len() == bits.len() / BVT_LEAF_SIZE as usize {
                    Ok(leaves)
                } else {
                    Err("Insufficient number of leaves are built from the given bits".into())
                }
            } else {
                Err("bits.len() should be a multiple of BVT_LEAF_SIZE".into())
            }
        }
        // Removing padding zeroes by taking bvt_bit_len bits
        bits_to_leaves(&bytes_to_bits(bytes).into_iter().take(bvt_bit_len).collect())
    }

    // Number of leaves in a tree of corresponding to its height
    let leaves_num = pow2(tree.height());
    // Bit-size of a BV which is contained in a given tree
    let bvt_bit_len = BVT_LEAF_SIZE as usize * leaves_num;
    // Padding to a full byte length
    let padding = if bvt_bit_len % 8 != 0 { 8 - bvt_bit_len % 8 } else { 0 };

    // Checking size of a given byte-array
    if bvt_bytes.len() * 8 == (bvt_bit_len + padding) as usize {
        // Converting byte-array into a sequence of FieldElement-leaves
        let bvt_leaves = bytes_to_leaves(bvt_bytes.as_slice(), bvt_bit_len)?;
        // Sequentially inserting leaves into a tree
        for i in 0.. leaves_num {
            tree.insert_leaf(Coord::new(0, i), bvt_leaves[i]);
        }
        Ok(())
    } else {
        Err("Number of bytes is inconsistent with height of a tree".into())
    }
}

// #[cfg(test)]
// mod test {
//     use crate::zenbox_smt::bitvector_smt::{BVT_LEAF_SIZE, get_bvt, set_bvt_bit, get_bvt_bit, reset_bvt_bit, get_bvt_leaf_by_index, get_bvt_leaf, get_bvt_path, set_bvt_persistency, serialize_bvt, initialize_bvt, pow2};
//     use algebra::ToBits;
//
//     #[test]
//     fn bitvector_tree_serialization(){
//         let height = 2; // 4 leaves
//         let mut bvt = get_bvt(height, "/tmp/bvt_db_serialization").unwrap();
//
//         let mut bvt_bytes = serialize_bvt(&bvt);
//         // Initially empty bvt should consist of zeroes
//         bvt_bytes.iter().for_each(|byte| assert_eq!(*byte, 0u8));
//
//         let bvt_leaves_num = pow2(height) as u64;
//         let bvt_bit_len = BVT_LEAF_SIZE * bvt_leaves_num;
//         let padding = if bvt_bit_len % 8 != 0 { 8 - bvt_bit_len % 8 } else { 0 }; // padding to a full byte length
//         // Checking a length of a serialized bvt considering possible padding
//         assert_eq!(bvt_bytes.len() * 8, (bvt_bit_len + padding) as usize);
//
//         // The first bit of a first BVT-leaf
//         set_bvt_bit(&mut bvt, (BVT_LEAF_SIZE * 0) + 0);
//         // The last bit of a first BVT-leaf
//         set_bvt_bit(&mut bvt, (BVT_LEAF_SIZE * 0) + (BVT_LEAF_SIZE - 1));
//         // The first bit of a second BVT-leaf
//         set_bvt_bit(&mut bvt, (BVT_LEAF_SIZE * 1) + 0);
//         // The last bit of a second BVT-leaf
//         set_bvt_bit(&mut bvt, (BVT_LEAF_SIZE * 1) + (BVT_LEAF_SIZE - 1));
//         // The first bit of a last BVT-leaf
//         set_bvt_bit(&mut bvt, (BVT_LEAF_SIZE * (bvt_leaves_num - 1)) + 0);
//         // The last bit of a last BVT-leaf
//         set_bvt_bit(&mut bvt, (BVT_LEAF_SIZE * (bvt_leaves_num - 1)) + (BVT_LEAF_SIZE - 1));
//
//         bvt_bytes = serialize_bvt(&bvt);
//         // bvt_bytes.iter().for_each(|byte| print!("{:#04x}, ", byte));
//         let serialized_bvt = vec![0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
//         assert_eq!(bvt_bytes, serialized_bvt);
//
//         let mut bvt2 = get_bvt(height, "/tmp/bvt_db_serialization2").unwrap();
//         // Checking that BVT initialization from serialization bytes is successful
//         assert!(initialize_bvt(&mut bvt2, bvt_bytes).is_ok());
//         // Checking that BVT built from serialization bytes is the same as the initial one
//         assert_eq!(bvt.get_root(), bvt2.get_root());
//
//         // Deleting BVTs data
//         set_bvt_persistency(&mut bvt2, false);
//         set_bvt_persistency(&mut bvt, false);
//     }
//
//     #[test]
//     fn sample_calls_bitvector_tree(){
//         // This test is specified for a 752-bit bitvectors, that corresponds to a 753-bit field elements
//         // Here a bitvector is a sequential chunk of bits, that corresponds to one leaf of a FieldElement-based SMT with 753-bit leaves.
//
//         assert_eq!(BVT_LEAF_SIZE, 752);
//
//         // Get BitvectorTree of height 4 to decrease time of the test run
//         let mut bvt = get_bvt(4, "/tmp/bvt_db").unwrap();
//
//         // To make test run not too long the number of tested bits per leaf is at step = 47 times lesser
//         let step = (BVT_LEAF_SIZE / 16) as usize;
//         // Minimal step is 2. The fully filled leafs will be tested with such a step but it takes around 12 minutes to run this test
//         // let step = 2;
//         assert!(step >= 2);
//
//         let bv_msb_offset = step as u64 - 1;
//
//         // Maps position inside of a bitvector to a bit value
//         let bit_by_position = |pos: u64| -> bool {
//             (pos % step as u64 == 0) |                                                 // LSB of a bitvector
//                 ((pos >= bv_msb_offset) && ((pos - bv_msb_offset) % step as u64 == 0)) // MSB of a bitvector
//         };
//
//         // Setting bits in the first bitvector
//         for pos in 0..BVT_LEAF_SIZE {
//             if bit_by_position(pos) {
//                 set_bvt_bit(&mut bvt, pos);
//             }
//         }
//         // Checking that corresponding bits in the first bitvector are set, while all the other bits are not set
//         for pos in 0..BVT_LEAF_SIZE {
//             assert_eq!(get_bvt_bit(&bvt, pos as u64), bit_by_position(pos));
//         }
//
//         // Setting bits in the second bitvector
//         for pos in 0..BVT_LEAF_SIZE {
//             if bit_by_position(pos) {
//                 set_bvt_bit(&mut bvt, BVT_LEAF_SIZE + pos);
//             }
//         }
//
//         // Reseting the previously set bits in the first bitvector
//         for pos in 0..BVT_LEAF_SIZE {
//             if bit_by_position(pos) {
//                 reset_bvt_bit(&mut bvt, pos);
//             }
//         }
//
//         //-------------------------------------
//         // Checking the first bitvector
//         //-------------------------------------
//         // All bits in the first bitvector should be reset
//         for pos in 0..BVT_LEAF_SIZE {
//             assert_eq!(get_bvt_bit(&bvt, pos), false);
//         }
//         // Low-level check: First leaf should be absent due to a stored bitvector is empty
//         assert_eq!(get_bvt_leaf_by_index(&bvt, 0), None);
//
//         //-------------------------------------
//         // Checking the second bitvector
//         //-------------------------------------
//         // Checking that corresponding bits in the second bitvector are set, while all the other bits are not set
//         for pos in 0..BVT_LEAF_SIZE {
//             assert_eq!(get_bvt_bit(&bvt, BVT_LEAF_SIZE + pos), bit_by_position(pos));
//         }
//         // Low-level check: parsing directly the leaf containing the second bitvector
//         let second_leaf_bits = get_bvt_leaf_by_index(&bvt, 1).unwrap().write_bits();
//         // Reversing bits due to a FieldElement is deserialized in the BigEndian format
//         let second_bitvector: Vec<bool> = second_leaf_bits.iter().rev().take(BVT_LEAF_SIZE as usize).map(|b|*b).collect();
//         for pos in 0..BVT_LEAF_SIZE {
//             assert_eq!(second_bitvector[pos as usize], bit_by_position(pos));
//         }
//
//         let second_leaf_lsb_pos = BVT_LEAF_SIZE;
//
//         // Checking that the bit position is correctly mapped to a BVT leaf position
//         assert_eq!(get_bvt_leaf(&bvt, second_leaf_lsb_pos).unwrap(),
//                    get_bvt_leaf_by_index(&bvt, 1).unwrap());
//
//         // Checking that Merkle Paths are the same for bits from the same leafs
//         assert_eq!(get_bvt_path(&mut bvt, 0),
//                    get_bvt_path(&mut bvt, BVT_LEAF_SIZE - 1));
//         assert_eq!(get_bvt_path(&mut bvt, second_leaf_lsb_pos),
//                    get_bvt_path(&mut bvt, second_leaf_lsb_pos + BVT_LEAF_SIZE - 1));
//
//         // Checking that Merkle Paths are different for bits from different leafs
//         assert_ne!(get_bvt_path(&mut bvt, BVT_LEAF_SIZE - 1),
//                    get_bvt_path(&mut bvt, BVT_LEAF_SIZE));
//
//         //Deleting BVTs data
//         set_bvt_persistency(&mut bvt, false);
//     }
// }
