use crate::ginger_calls::{FieldElement, GingerSMT, GingerMHTPath, Error, get_ginger_smt, flush_ginger_smt, set_ginger_smt_persistency, get_position_in_ginger_smt, is_position_empty_in_ginger_smt, add_leaf_to_ginger_smt, remove_leaf_from_ginger_smt, get_ginger_smt_root, get_ginger_smt_path, get_leaf_from_ginger_smt};
use crate::zenbox_smt::bitvector_smt::*;

pub mod bitvector_smt;
pub mod jni_calls;

pub struct ZenBoxSMT{
    state_smt: GingerSMT,
    bitvector_smt: BitvectorSMT,
    base_path: String // base path to state_smt and bitvector_smt DBs directories
}

const BVT_PATH_SUFFIX: &str = "_bvt";

pub fn get_zenbox_smt(state_height: usize, db_path: &str) -> Result<ZenBoxSMT, Error> {
    if state_height > BVT_LEAF_SIZE_LOG2 {
        // Bitvector needs BVT_LEAF_SIZE times lesser capacity of MT than State
        let bvt_height = state_height - BVT_LEAF_SIZE_LOG2;
        Ok(
            ZenBoxSMT{
                state_smt: get_ginger_smt(state_height, db_path)?,
                bitvector_smt: get_bvt(bvt_height, &(db_path.to_owned() + BVT_PATH_SUFFIX))?,
                base_path: db_path.to_owned()
            }
        )
    } else {
        Err("Height should be bigger than BVT_LEAF_SIZE_LOG2".into())
    }
}

// Just removing existing BVT and creating the new empty one at the same filesystem location
pub fn reset_bitvector(mut tree: ZenBoxSMT) -> Result<ZenBoxSMT, Error> {
    let bvt_height = tree.bitvector_smt.height();
    // Deleting existing BVT DB
    set_bvt_persistency(&mut tree.bitvector_smt, false);
    drop(tree.bitvector_smt); // to trigger deletion of BVT-containing directories
    Ok(
        ZenBoxSMT{
            state_smt: tree.state_smt,
            bitvector_smt: get_bvt(bvt_height, &(tree.base_path.to_owned() + BVT_PATH_SUFFIX))?,
            base_path: tree.base_path
        }
    )
}

pub fn flush_zenbox_smt(tree: &mut ZenBoxSMT) {
    flush_ginger_smt(&mut tree.state_smt);
    flush_bvt(&mut tree.bitvector_smt)
}

pub fn set_zenbox_smt_persistency(tree: &mut ZenBoxSMT, persistency: bool) {
    set_ginger_smt_persistency(&mut tree.state_smt, persistency);
    set_bvt_persistency(&mut tree.bitvector_smt, persistency);
}

pub fn get_position_in_zenbox_smt(tree: &ZenBoxSMT, leaf: &FieldElement) -> u64 {
    get_position_in_ginger_smt(&tree.state_smt, leaf)
}

pub fn is_position_empty_in_zenbox_smt(tree: &ZenBoxSMT, position: u64) -> bool {
    is_position_empty_in_ginger_smt(&tree.state_smt, position)
}

pub fn is_box_spent(tree: &ZenBoxSMT, position: u64) -> bool {
    get_bvt_bit(&tree.bitvector_smt, position)
}

pub fn add_box_to_zenbox_smt(tree: &mut ZenBoxSMT, box_: &FieldElement, position: u64){
    // avoid overwriting already existing boxes
    if is_position_empty_in_ginger_smt(&tree.state_smt, position){
        // if corresponding bit in BVT is set, this means that current box has already been spent
        assert!(!get_bvt_bit(&tree.bitvector_smt, position));
        add_leaf_to_ginger_smt(&mut tree.state_smt, box_, position)
    }
}

pub fn remove_box_from_zenbox_smt(tree: &mut ZenBoxSMT, position: u64){
    // update BVT only if leaf has been really removed
    if !is_position_empty_in_ginger_smt(&tree.state_smt, position){
        remove_leaf_from_ginger_smt(&mut tree.state_smt, position);
        // if corresponding bit in BVT is set, this means, that box on the same position is going to be removed twice
        assert!(!get_bvt_bit(&tree.bitvector_smt, position));
        set_bvt_bit(&mut tree.bitvector_smt, position)
    }
}

pub fn get_box_from_zenbox_smt(tree: &ZenBoxSMT, position: u64) -> Option<FieldElement> {
    get_leaf_from_ginger_smt(&tree.state_smt, position)
}

pub fn get_state_root(tree: &ZenBoxSMT) -> FieldElement {
    get_ginger_smt_root(&tree.state_smt)
}

pub fn get_bitvector_root(tree: &ZenBoxSMT) -> FieldElement {
    get_bvt_root(&tree.bitvector_smt)
}

pub fn get_state_path(tree: &mut ZenBoxSMT, position: u64) -> GingerMHTPath {
    get_ginger_smt_path(&mut tree.state_smt, position)
}

pub fn get_bitvector_path(tree: &mut ZenBoxSMT, position: u64) -> GingerMHTPath {
    get_bvt_path(&mut tree.bitvector_smt, position)
}

#[cfg(test)]
mod test {
    use crate::zenbox_smt::{get_zenbox_smt, get_position_in_zenbox_smt, is_position_empty_in_zenbox_smt, add_box_to_zenbox_smt, get_bitvector_root, remove_box_from_zenbox_smt, get_state_root, is_box_spent, reset_bitvector, set_zenbox_smt_persistency, get_box_from_zenbox_smt, get_state_path, get_bitvector_path};
    use rand::rngs::OsRng;
    use crate::ginger_calls::FieldElement;
    use algebra::UniformRand;

    #[test]
    fn sample_calls_zenbox_smt(){

        let mut zbt = get_zenbox_smt(10, "/tmp/zbt_db").unwrap();
        let mut rng = OsRng;

        let mut boxes = vec![];
        let mut positions = vec![];

        let boxes_num = 8;

        // Add random boxes to ZenBoxSMT
        for _ in 0..boxes_num as usize {
            loop {
                let rand_box = FieldElement::rand(&mut rng);
                let position = get_position_in_zenbox_smt(&zbt, &rand_box);
                if is_position_empty_in_zenbox_smt(&zbt, position) {
                    boxes.push(rand_box);
                    positions.push(position);
                    add_box_to_zenbox_smt(&mut zbt, &rand_box, position as u64);
                    break;
                }
            }
        }

        let empty_bvt_root = get_bitvector_root(&zbt);

        //Remove first and last leaves
        remove_box_from_zenbox_smt(&mut zbt, positions[0]);
        remove_box_from_zenbox_smt(&mut zbt, positions[boxes_num - 1]);

        let state_root = get_state_root(&zbt);

        // Check that the deleted boxes are marked as spent
        assert!(is_box_spent(&zbt, positions[0]));
        assert!(is_box_spent(&zbt, positions[boxes_num - 1]));

        zbt = reset_bitvector(zbt).unwrap();

        // Check that the deleted boxes are marked as unspent due to BVT is reset
        assert!(!is_box_spent(&zbt, positions[0]));
        assert!(!is_box_spent(&zbt, positions[boxes_num - 1]));

        // Check that State tree remains the same as before BVT resetting
        assert_eq!(state_root, get_state_root(&zbt));
        // Check that BVT is empty after resetting
        assert_eq!(empty_bvt_root, get_bitvector_root(&zbt));

        //Delete ZB_SMTs data
        set_zenbox_smt_persistency(&mut zbt, false);
    }

    #[test]
    fn internal_state_zenbox_smt(){

        let mut zbt = get_zenbox_smt(12, "/tmp/zbt_db_").unwrap();
        let mut rng = OsRng;

        let rand_box = FieldElement::rand(&mut rng);
        let position0 = 0;

        let rand_box_ = FieldElement::rand(&mut rng);
        let position800 = 800; // uses the second leaf of BVT due to there are `BVT_LEAF_SIZE = 752` bits per leaf

        add_box_to_zenbox_smt(&mut zbt, &rand_box, position0);
        assert_eq!(get_box_from_zenbox_smt(&zbt, position0).unwrap(), rand_box);

        let state_root0 = get_state_root(&zbt);
        let bvt_root0 = get_bitvector_root(&zbt);

        let state_path0 = get_state_path(&mut zbt, position0);
        let bvt_path0 = get_bitvector_path(&mut zbt, position0);

        // trying to push another box into the position with existing box
        add_box_to_zenbox_smt(&mut zbt, &rand_box_, position0);
        // box should remain the same as was pushed the first time
        assert_eq!(get_box_from_zenbox_smt(&zbt, position0).unwrap(), rand_box);
        // state root and BVT root should remain unchanged
        assert_eq!(state_root0, get_state_root(&zbt));
        assert_eq!(bvt_root0, get_bitvector_root(&zbt));

        // state path and BVT path for the box at position0 should remain unchanged
        assert_eq!(state_path0, get_state_path(&mut zbt, position0));
        assert_eq!(bvt_path0, get_bitvector_path(&mut zbt, position0));

        // trying to remove nonexisting box
        remove_box_from_zenbox_smt(&mut zbt, position800);
        // state root and BVT root should remain unchanged
        assert_eq!(state_root0, get_state_root(&zbt));
        assert_eq!(bvt_root0, get_bitvector_root(&zbt));

        // state path and BVT path for the box at position0 should remain unchanged
        assert_eq!(state_path0, get_state_path(&mut zbt, position0));
        assert_eq!(bvt_path0, get_bitvector_path(&mut zbt, position0));

        add_box_to_zenbox_smt(&mut zbt, &rand_box_, position800);
        assert_eq!(get_box_from_zenbox_smt(&zbt, position800).unwrap(), rand_box_);
        // state root should have a new value
        assert_ne!(state_root0, get_state_root(&zbt));
        // BVT root should remain unchanged
        assert_eq!(bvt_root0, get_bitvector_root(&zbt));

        // state path for the box at position0 should have a new value
        assert_ne!(state_path0, get_state_path(&mut zbt, position0));
        // BVT path for the box at position0 should remain unchanged
        assert_eq!(bvt_path0, get_bitvector_path(&mut zbt, position0));

        remove_box_from_zenbox_smt(&mut zbt, position800);
        assert_eq!(get_box_from_zenbox_smt(&zbt, position800), None);
        // state root should have a previous value
        assert_eq!(state_root0, get_state_root(&zbt));
        // BVT root should have a new value
        assert_ne!(bvt_root0, get_bitvector_root(&zbt));

        // state path for the box at position0 should have a previous value
        assert_eq!(state_path0, get_state_path(&mut zbt, position0));
        // BVT path for the box at position0 should have a new value
        assert_ne!(bvt_path0, get_bitvector_path(&mut zbt, position0));

        //Delete ZB_SMTs data
        set_zenbox_smt_persistency(&mut zbt, false);
    }
}
