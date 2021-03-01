pub const BITVECTOR_SIZE:usize = 4000000;
pub const BTV_LEAF_SIZE:usize =  253;   //n.b. current leaf size limit is 254 bits
pub const BTV_TREE_DEPTH:usize =  14;
pub const LEAF_BIT_COUNTER_LEN:usize =  2;

use std::fs;
use std::io::Read;
//use std::io::Write; 

use bzip2::Compression;
use bzip2::read::{BzEncoder, BzDecoder};
use flate2::Compression as GzipCompression;
use flate2::write::ZlibEncoder;
use std::io;
use std::io::prelude::*;


#[derive(Default)]
pub struct BitVector {
    pub c_last_byte: u8,
    pub n_last_byte_size:u32,
    pub b_finalized: bool,
    pub bitstream: Vec<u8>,
}

impl BitVector {
    pub fn append_bits(&mut self, word: u32, mut n_bits_to_append: u32)
    {
        if self.b_finalized==true
        { 
            assert!(false);
            return;
        }
        let mask:u32;
        mask = (1 << n_bits_to_append) - 1;
        assert!((word & mask) == word);
        assert!(n_bits_to_append <= 16);
        //take only the n_bits_to_append content, cropping unwanted bits
        let mut word = word << (16 - n_bits_to_append);
        while n_bits_to_append > 0
        {
            //concatenate to c_last_byte
            self.c_last_byte |= (word >> (8 + self.n_last_byte_size)) as u8;
            word = word << (8 - self.n_last_byte_size);
            if (self.n_last_byte_size + n_bits_to_append) >= 8
            {
                n_bits_to_append -= 8 - self.n_last_byte_size;
                self.bitstream.push(self.c_last_byte);
                self.c_last_byte = 0;
                self.n_last_byte_size = 0;
            }
            else {
                self.n_last_byte_size += n_bits_to_append;
                n_bits_to_append = 0;
            }
        }
    }
    pub fn get_size(&self) -> i32 {
        if self.b_finalized == false
        {
            assert!(false);
            -1
        }
        else
        {
            self.bitstream.len() as i32
        }
    }
    pub fn get_current_bits_size(&self) -> u32 {
        (self.bitstream.len() as u32)*8 + self.n_last_byte_size
    }
    pub fn finalize(&mut self) 
    {
        if self.b_finalized == false
        {
            if self.n_last_byte_size > 0
            {
                self.bitstream.push(self.c_last_byte);
            }
            self.b_finalized = true;
        }
    }
    pub fn truncate(&mut self,n_max_bit_length: i32) -> bool
    {
        if self.b_finalized == false
        {
            assert!(false);
            false
        }
        else
        {
            self.bitstream.truncate((n_max_bit_length / 8) as usize);
            true
        }
    }

}

pub fn compress_bitvector(bitvector: &Vec<u8>) -> BitVector
{
    let mut n_stats_code_nval:i32 = 0;
    let mut n_stats_code_listval :i32= 0;
    let mut n_stats_code_uncompressed:i32 = 0;
    let mut n_num_active_bits:i32 = 0;
    let mut n_empty_leaves:i32 = 0;

    let mut n_curr_pos:usize = 0;       //0-based position of current bit
    let mut n_curr_pos_byte:usize = 0;
    let mut n_curr_leaf_num:i32;
    let mut n_last_leaf_num:i32 = -1;
    let mut bitvect_compressed = BitVector::default();

    let mut n:usize;
    let mut c_curr_byte:u8;
    let mut mask_byte:u8;
    let mut mask:i32;
    let n_bv_size:usize=bitvector.len();
    assert!(n_bv_size*8==BITVECTOR_SIZE);
    assert!(BITVECTOR_SIZE<(usize::pow(2,BTV_TREE_DEPTH as u32)*BTV_LEAF_SIZE));
    while n_curr_pos_byte < n_bv_size
    {
        //looking for the first active bit
        mask_byte = ((1 << (8 - (n_curr_pos % 8))) - 1) as u8;
        if (bitvector[n_curr_pos_byte] & mask_byte) == 0
        {
            n_curr_pos_byte+=1;
            n_curr_pos = n_curr_pos_byte * 8;
        }
        else
        {
            n = 0;
            while (((bitvector[n_curr_pos_byte] & mask_byte) << (n + (n_curr_pos % 8))) & 0b10000000) == 0
            {
                n+=1;
            }
            n_curr_pos += n;
            //get leaf number for the current position
            n_curr_leaf_num = (n_curr_pos / BTV_LEAF_SIZE) as i32 ;
            if n_curr_leaf_num==n_last_leaf_num+1
            {
                //write out the 0 bit code (=consecutive)
                bitvect_compressed.append_bits(0, 1);
            }
            else
            {
                //write out the 1 bit code (=jump to address)
                bitvect_compressed.append_bits(1, 1);
                //write out the 14 bit address (BTV_TREE_DEPTH)
                bitvect_compressed.append_bits(n_curr_leaf_num as u32, BTV_TREE_DEPTH as u32);
            }
            n_empty_leaves += n_curr_leaf_num - n_last_leaf_num - 1;
            n_last_leaf_num = n_curr_leaf_num;
            let mut list_pos: Vec<u8> = Vec::new();
            //check number of active position
            //n.b optimizable: check here for 32bits https://stackoverflow.com/questions/109023/how-to-count-the-number-of-set-bits-in-a-32-bit-integer
            let mut i=n_curr_pos;
            while (i<(n_curr_leaf_num as usize + 1)*BTV_LEAF_SIZE) && (i<BITVECTOR_SIZE)
            {
                while (i<BITVECTOR_SIZE) && ((i % 8) == 0) && (bitvector[i / 8] == 0) && (i < (n_curr_leaf_num as usize + 1) * BTV_LEAF_SIZE) //skip the byte
                {
                    i += 8;
                } 
                
                if (i < BITVECTOR_SIZE) && (((bitvector[i / 8] << i % 8) & 0b10000000) == 0b10000000) && (i < (n_curr_leaf_num as usize + 1) * BTV_LEAF_SIZE)
                {
                    list_pos.push((i % BTV_LEAF_SIZE) as u8);
                }
                i+=1;
            }
            assert!(list_pos.len() > 0);
            n_num_active_bits += list_pos.len() as i32;
            if list_pos.len() <= ((1<< LEAF_BIT_COUNTER_LEN)-2)
            {
                n_stats_code_nval+=1;
                //write code enconding the number of positions
                bitvect_compressed.append_bits((list_pos.len()-1) as u32, LEAF_BIT_COUNTER_LEN as u32);
                for i in 0..list_pos.len()
                {
                    //write out the position in the leaf, 8 bits
                    bitvect_compressed.append_bits(list_pos[i] as u32, 8);
                }
            }
            if list_pos.len() > ((1 << LEAF_BIT_COUNTER_LEN) - 2)
            {
                //add position list with terminator "255"
                if list_pos.len() < 32
                {
                    n_stats_code_listval+=1;
                    //write code 
                    bitvect_compressed.append_bits((1 << LEAF_BIT_COUNTER_LEN) - 2, LEAF_BIT_COUNTER_LEN as u32);
                    //write out all the positions, 8 bits per position
                    for i in 0..list_pos.len()
                    {
                        bitvect_compressed.append_bits(list_pos[i] as u32, 8);
                    }
                    //write out the terminator code
                    bitvect_compressed.append_bits(255, 8);
                }
                else //write 32 bytes bitmask
                {
                    n_stats_code_uncompressed+=1;
                    //write code uncompressed
                    bitvect_compressed.append_bits((1 << LEAF_BIT_COUNTER_LEN)-1, LEAF_BIT_COUNTER_LEN as u32);
                    //write out all all the bits of the leaf, without compression
                    for i in (n_curr_leaf_num*(BTV_LEAF_SIZE as i32)..(n_curr_leaf_num+1)*(BTV_LEAF_SIZE as i32)).step_by(8)
                    {
                        mask = ((1 << 8) - 1) << (8 - (i % 8));
                        if i<BITVECTOR_SIZE as i32
                        {
                            if i+8<BITVECTOR_SIZE as i32
                            {
                                c_curr_byte = (((((bitvector[(i / 8) as usize] as i32) << 8) | (bitvector[(i / 8) as usize + 1] as i32)) & mask) >> (8 - (i % 8))) as u8;    
                            }
                            else
                            {
                                c_curr_byte = ((((bitvector[(i / 8) as usize] as i32) << 8) & mask) >> (8 - (i % 8))) as u8;    
                            }
                        }
                        else
                        {
                            c_curr_byte=0;
                        }
                        if i + 8 >= (n_curr_leaf_num + 1) * BTV_LEAF_SIZE as i32
                        {
                            //add last bits
                            bitvect_compressed.append_bits((c_curr_byte as u32) >> (8 - (BTV_LEAF_SIZE % 8)), BTV_LEAF_SIZE as u32 % 8);
                        }
                        else
                        {
                            bitvect_compressed.append_bits(c_curr_byte as u32, 8);
                        }    
                    }
                    
                }
            }
            //jump to next leaf
            n_curr_pos = (n_curr_leaf_num as usize+ 1) * BTV_LEAF_SIZE;
            n_curr_pos_byte = n_curr_pos / 8;
        }
    }
    n_empty_leaves += ((BITVECTOR_SIZE/BTV_LEAF_SIZE)+1) as i32 - n_last_leaf_num - 1;

    //add last bits and close the compression
    bitvect_compressed.finalize();
    print!("Original size: {}; ", n_bv_size);
    print!("final size: {}; ", bitvect_compressed.get_size());
    print!("num active bits: {}; ", n_num_active_bits);
    print!("num empty leaves: {}; ", n_empty_leaves);
    print!("leaves with N fixed values: {}; ", n_stats_code_nval);
    print!("leaves with list values: {}; ", n_stats_code_listval);
    println!("leaves uncompressed: {}; ", n_stats_code_uncompressed);

    bitvect_compressed
}

pub fn decompress_bitvector(bitvector: &Vec<u8>) -> BitVector
{
    let mut bitvect_decompressed=BitVector::default();

    let mut n_curr_pos:usize = 0;
    let mut n_curr_byte:i32;
    let mut n_last_byte:i32;
    let mut n_curr_leaf_num:i32;
    let mut n_last_leaf_num:i32 = -1;
    let mut mask:i32;
    let mut num_bits_to_append:i32;
    let mut code:u8;
    let n_bv_size:usize=bitvector.len();

    while n_curr_pos < ((n_bv_size-1) * 8)
    {

        assert!((bitvect_decompressed.get_current_bits_size() % BTV_LEAF_SIZE as u32) == 0);

        //check the first bit
        if ((bitvector[n_curr_pos / 8] << (n_curr_pos % 8)) & 0b10000000) == 0
        {
            n_curr_pos+=1;
            n_curr_leaf_num = n_last_leaf_num + 1;
            n_last_leaf_num = n_curr_leaf_num;
        }
        else
        {
            n_curr_pos+=1;
            mask = ((1 << BTV_TREE_DEPTH) - 1) << (24 - BTV_TREE_DEPTH - (n_curr_pos % 8));
            assert!(n_curr_pos/8<n_bv_size-2);
            n_curr_leaf_num = ((((bitvector[(n_curr_pos / 8)] as i32) << 16) | ((bitvector[(n_curr_pos / 8) + 1] as i32) << 8) | ((bitvector[(n_curr_pos / 8) + 2] as i32))) & (mask as i32)) >> (24 - BTV_TREE_DEPTH - (n_curr_pos % 8));
            n_curr_pos += BTV_TREE_DEPTH;
            for _i in n_last_leaf_num+1..n_curr_leaf_num
            {
                num_bits_to_append = BTV_LEAF_SIZE as i32;
                while num_bits_to_append > 0
                {
                    if num_bits_to_append >= 16
                    {
                        bitvect_decompressed.append_bits(0, 16);
                    }
                    else
                    {
                        bitvect_decompressed.append_bits(0, num_bits_to_append as u32);
                    }
                    num_bits_to_append -= 16;
                }
            }
            n_last_leaf_num = n_curr_leaf_num;
        }
        //read the next LEAF_BIT_COUNTER_LEN bits
        code = 0;
        for _i in 0..LEAF_BIT_COUNTER_LEN
        {
            code <<= 1;
            code |= (((bitvector[n_curr_pos / 8] << (n_curr_pos % 8)) & 0b10000000) != 0) as u8;
            n_curr_pos+=1;
        }
        if code < ((1 << LEAF_BIT_COUNTER_LEN) - 2)
        {
            //only "code" positions, 8 bits per pos
            //list of positions with terminator 255, 8 bits per position
            n_curr_byte = -1;
            let mut num_pos = (code+1) as i32;
            while (num_pos)>0
            {
                num_pos-=1;
                n_last_byte = n_curr_byte;
                mask = ((1 << 8) - 1) << (8 - (n_curr_pos % 8));
                assert!(n_curr_pos/8<n_bv_size);
                if n_curr_pos/8<n_bv_size-1
                {
                    n_curr_byte = ((((bitvector[(n_curr_pos / 8)] as i32) << 8) | (bitvector[(n_curr_pos / 8) + 1] as i32)) & mask) >> (8 - (n_curr_pos % 8));                    
                }
                else
                {
                    n_curr_byte = (((bitvector[(n_curr_pos / 8)] as i32) << 8) & mask) >> (8 - (n_curr_pos % 8));                    
                }
                n_curr_pos += 8;
                num_bits_to_append = n_curr_byte - n_last_byte - 1;
                while num_bits_to_append > 0
                {
                    if num_bits_to_append >= 16
                    {
                        bitvect_decompressed.append_bits(0, 16);
                    }
                    else
                    {
                        bitvect_decompressed.append_bits(0, num_bits_to_append as u32);
                    }
                    num_bits_to_append -= 16;
                }
                bitvect_decompressed.append_bits(1, 1);
            }
            num_bits_to_append = BTV_LEAF_SIZE as i32 - n_curr_byte - 1;
            while num_bits_to_append > 0
            {
                if num_bits_to_append >= 16
                {
                    bitvect_decompressed.append_bits(0, 16);
                }
                else
                {
                    bitvect_decompressed.append_bits(0, num_bits_to_append as u32);
                }
                num_bits_to_append -= 16;
            }
        }
        else if code == ((1 << LEAF_BIT_COUNTER_LEN) - 2)
        {
            //list of positions with terminator 255, 8 bits per position
            n_curr_byte = -1;
            loop
            {
                n_last_byte = n_curr_byte;
                mask = ((1 << 8) - 1) << (8 - (n_curr_pos % 8));
                assert!(n_curr_pos/8<n_bv_size);
                if n_curr_pos/8<n_bv_size-1
                {
                    n_curr_byte = ((((bitvector[(n_curr_pos / 8)] as i32) << 8) | (bitvector[(n_curr_pos / 8) + 1] as i32)) & mask) >> (8 - (n_curr_pos % 8));
                }
                else
                {
                    n_curr_byte = (((bitvector[(n_curr_pos / 8)] as i32) << 8) & mask) >> (8 - (n_curr_pos % 8));                    
                }
                n_curr_pos += 8;
                if n_curr_byte == 255
                {
                    num_bits_to_append = BTV_LEAF_SIZE as i32 - n_last_byte - 1;
                    while num_bits_to_append > 0
                    {
                        if num_bits_to_append >= 16
                        {
                            bitvect_decompressed.append_bits(0, 16);
                        }
                        else
                        {
                            bitvect_decompressed.append_bits(0, num_bits_to_append as u32);
                        }
                        num_bits_to_append -= 16;
                    }
                    break;
                }
                num_bits_to_append = n_curr_byte - n_last_byte - 1;
                while num_bits_to_append > 0
                {
                    if num_bits_to_append >= 16
                    {
                        bitvect_decompressed.append_bits(0, 16);
                    }
                    else
                    {
                        bitvect_decompressed.append_bits(0, num_bits_to_append as u32);
                    }
                    num_bits_to_append -= 16;
                }
                bitvect_decompressed.append_bits(1, 1);
            }
        }
        else if code == ((1 << LEAF_BIT_COUNTER_LEN) - 1)
        {
            //copy the byte mask uncompressed into the leaf
            num_bits_to_append = BTV_LEAF_SIZE as i32;
            while num_bits_to_append > 0
            {
                mask = ((1 << 8) - 1) << (8 - (n_curr_pos % 8));
                if n_curr_pos/8<n_bv_size-1
                {
                    n_curr_byte = ((((bitvector[(n_curr_pos / 8)] as i32) << 8) | (bitvector[(n_curr_pos / 8) + 1] as i32)) & mask) >> (8 - (n_curr_pos % 8));
                }
                else
                {
                    n_curr_byte = (((bitvector[(n_curr_pos / 8)] as i32) << 8) & mask) >> (8 - (n_curr_pos % 8));
                }
                if num_bits_to_append >= 8
                {
                    n_curr_pos += 8;
                    bitvect_decompressed.append_bits(n_curr_byte as u32, 8);
                }
                else
                {
                    n_curr_pos += num_bits_to_append as usize;
                    bitvect_decompressed.append_bits(n_curr_byte as u32 >> (8 - num_bits_to_append), num_bits_to_append as u32);
                }
                num_bits_to_append -= 8;
            }
        }
        else 
        {
            assert!(false);
        }
    }
    //add last leaves at the end
    for _i in (bitvect_decompressed.get_current_bits_size() / BTV_LEAF_SIZE as u32)..((BITVECTOR_SIZE / BTV_LEAF_SIZE) as u32 + 1)
    {
        num_bits_to_append = BTV_LEAF_SIZE as i32;
        while num_bits_to_append > 0
        {
            if num_bits_to_append >= 16
            {
                bitvect_decompressed.append_bits(0, 16);
            }
            else
            {
                bitvect_decompressed.append_bits(0, num_bits_to_append as u32);
            }
            num_bits_to_append -= 16;
        }
    }
    bitvect_decompressed.finalize();
    bitvect_decompressed.truncate(BITVECTOR_SIZE as i32);
    return bitvect_decompressed;
}


pub fn load_uncompressed_bitvector(str_filename:String) -> Vec<u8>
{
    let mut bitvector:Vec<u8>;

    let mut f = fs::File::open(&str_filename).expect("no file found");
    let metadata = fs::metadata(&str_filename).expect("unable to read metadata");
    bitvector = vec![0; metadata.len() as usize];
    f.read(&mut bitvector).expect("buffer overflow");
    println!("Filename: {};",str_filename);
    bitvector
}

#[cfg(test)]
mod test
{
    use super::*;

    #[test]
    fn bitvector_compression_test() 
    {
        let bitvector:Vec<u8>;
        //bitvector = load_uncompressed_bitvector(String::from("/home/carlo/bitvectors/bitvector_10_10.dat"));
        bitvector = load_uncompressed_bitvector(String::from("/home/carlo/bitvectors/bitvector_100_100.dat"));   
        //bitvector = load_uncompressed_bitvector(String::from("/home/carlo/bitvectors/bitvector_1000_1000.dat"));
        //bitvector = load_uncompressed_bitvector(String::from("/home/carlo/bitvectors/bitvector_10000_9990.dat"));   
        //bitvector = load_uncompressed_bitvector(String::from("/home/carlo/bitvectors/bitvector_100000_98810.dat"));  
        //bitvector = load_uncompressed_bitvector(String::from("/home/carlo/bitvectors/bitvector_1000000_884643.dat"));  
        //bitvector = load_uncompressed_bitvector(String::from("/home/carlo/bitvectors/bitvector_4000000_2525522.dat"));
        
        if bitvector.len()>0
        {
            let bitvect_compressed= compress_bitvector(&bitvector);
            println!("Compressed bitvector len: {}",bitvect_compressed.get_size());

            let bitvector_uncompressed= decompress_bitvector(&bitvect_compressed.bitstream);
            if bitvector==bitvector_uncompressed.bitstream
            {
                println!("test ok");
            }
            else
            {
                println!("test ko");
                //detect the position of the difference
                let mut i=0;
                while i<bitvector.len()
                {
                    if bitvector[i]!=bitvector_uncompressed.bitstream[i]
                    {
                        println!("first difference found at position {}, leaf {}, values orig:{}, decom: {}",i,i*8/BTV_LEAF_SIZE, bitvector[i],bitvector_uncompressed.bitstream[i]);
                        break;
                    }
                    i+=1;
                }
            }

            let mut compressor= BzEncoder::new(bitvector.as_slice(), bzip2::Compression::best());
            let mut bzip_compressed=Vec::new();
            compressor.read_to_end(&mut bzip_compressed);
            println!("Compressed by bzip2 library, size: {}",bzip_compressed.len());

            let mut e:ZlibEncoder<Vec<u8>> = ZlibEncoder::new(Vec::new(), GzipCompression::default());
            e.write_all(b"foo");
            e.write_all(bitvector.as_slice());
            let compressed_bytes = e.finish();
            match compressed_bytes {
                Ok(v) => println!("Compressed by gzip library, size: {}",v.len()),
                Err(e) => println!("Error during gzip compression: {:?}", e),
            }
            
            

        }
        else
        {
            println!("failed to load bitvector from file");
        }
    }
}
