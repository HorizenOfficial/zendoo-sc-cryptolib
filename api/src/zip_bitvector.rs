pub const BITVECTOR_SIZE:usize = 4000000;
pub const BTV_LEAF_SIZE:usize =  253;   //n.b. current leaf size limit is 254 bits
pub const BTV_TREE_DEPTH:usize =  14;
pub const LEAF_BIT_COUNTER_LEN:usize =  2;

use std::{fs, str::FromStr};
use std::io::Read;
use std::io::Write; 

use bzip2::Compression;
use bzip2::read::{BzEncoder, BzDecoder};
use flate2::Compression as GzipCompression;
use flate2::write::GzEncoder;
use flate2::read::GzDecoder;


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
            return
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
    pub fn get_size(&self) -> Result<i32,String> {
        if self.b_finalized == false
        {
            assert!(false);
            Err(String::from("Error: stream must be finalized"))
        }
        else
        {
            Ok(self.bitstream.len() as i32)
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
    pub fn truncate(&mut self,n_max_bit_length: i32) -> Result<bool,String>
    {
        if self.b_finalized == false
        {
            assert!(false);
            Err(String::from("Error: stream must be finalized"))
        }
        else
        {
            self.bitstream.truncate((n_max_bit_length / 8) as usize);
            Ok(true)
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
    let final_size;
    match bitvect_compressed.get_size(){
        Ok(len) => {
            final_size=len;
        },
        Err(_e) => {
            final_size=-1;
        }
    }
    print!("final size: {}; ", final_size);
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

pub fn bitvector_get_best_compression(bitvector: &Vec<u8>) -> Vec<u8>
{
    let mut bitvector_best_len=-1;
    let mut bitvector_best_algorithm:i8=-1; //-1 not set
    let mut best_bitvector_stream:Vec<u8>=Vec::new();
    let bitvect_compressed= compress_bitvector(&bitvector);
    let len_hzip=bitvect_compressed.get_size();
    match len_hzip {
        Ok(len_hzip)=>{
            bitvector_best_len=len_hzip as i32;
            bitvector_best_algorithm=0; //0=Hzip  
            best_bitvector_stream=bitvect_compressed.bitstream;
            println!("Compressed bitvector len using hzip: {}",len_hzip);
        },
        Err(s)=>{
            println!("{}", s);
        }
    }


    let mut compressor= BzEncoder::new(bitvector.as_slice(), Compression::best());
    let mut bzip2_compressed=Vec::new();
    let final_size=compressor.read_to_end(&mut bzip2_compressed);
    match final_size {
        Ok(len_bzip2)=>{
            if (bitvector_best_len==-1) || ((len_bzip2 as i32)<bitvector_best_len)
            {
                bitvector_best_len=len_bzip2 as i32;
                bitvector_best_algorithm=1; //1=Bzip2  
                best_bitvector_stream=bzip2_compressed;    
            }
            println!("Compressed by bzip2 library, size: {}",len_bzip2);
        },
        Err(_e)=>{
            println!("Error compressing with bzip2");
        }
    }

    let mut e= GzEncoder::new(Vec::new(), GzipCompression::best());
    e.write_all(bitvector.as_slice());
    let compressed_bytes = e.finish();
    match compressed_bytes {
        Ok(v) => {
            let len_gzip:i32;
            len_gzip=(v.len()) as i32;
            if (bitvector_best_len==-1) || ((len_gzip as i32)<bitvector_best_len)
            {
                bitvector_best_len=len_gzip;
                bitvector_best_algorithm=2; //2=Gzip  
                best_bitvector_stream=v;
            }
            println!("Compressed by gzip library, size: {}",len_gzip);
        },
        Err(_e) => {
            println!("Error compressing by gzip library");
        }
    }
    best_bitvector_stream.insert(0, bitvector_best_algorithm as u8);
    best_bitvector_stream
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

pub fn bitvector_get_decompressed_stream(bitvector_compressed: &mut Vec<u8>) -> Vec<u8> 
{
    let mut bitvector_uncompressed=Vec::new();
    let alg_type=bitvector_compressed.remove(0);
    match alg_type {
        0 => {
            bitvector_uncompressed = decompress_bitvector(&bitvector_compressed).bitstream;
            },
        1 => {
            let mut decompressor= BzDecoder::new(bitvector_compressed.as_slice());
            decompressor.read_to_end(&mut bitvector_uncompressed).unwrap();        
        },
        2 => {
            let mut e = GzDecoder::new(bitvector_compressed.as_slice());
            e.read_to_end(&mut bitvector_uncompressed).unwrap();
        
        },
        _ => {
            println!("Error: algorithm not supported")
            }
    }
    bitvector_uncompressed
}

#[cfg(test)]
mod test
{
    use super::*;

    #[test]
    fn bitvector_compression_test() 
    {
        let bitvector:Vec<u8>;
        //bitvector = load_uncompressed_bitvector(String::from("/home/carlo/bitvectors/bitvector_10_10.dat"));                      //Best: Hzip
        //bitvector = load_uncompressed_bitvector(String::from("/home/carlo/bitvectors/bitvector_100_100.dat"));                    //Best: Hzip
        //bitvector = load_uncompressed_bitvector(String::from("/home/carlo/bitvectors/bitvector_1000_1000.dat"));                  //Best: Bzip2
        //bitvector = load_uncompressed_bitvector(String::from("/home/carlo/bitvectors/bitvector_10000_9990.dat"));                 //Best: Bzip2
        bitvector = load_uncompressed_bitvector(String::from("/home/carlo/bitvectors/bitvector_100000_98810.dat"));     //Best: Bzip2
        //bitvector = load_uncompressed_bitvector(String::from("/home/carlo/bitvectors/bitvector_1000000_884643.dat"));             //Best: Gzip
        //bitvector = load_uncompressed_bitvector(String::from("/home/carlo/bitvectors/bitvector_4000000_2525522.dat"));            //Best: Gzip
        
        if bitvector.len()>0
        {
            let mut bitvector_compressed= bitvector_get_best_compression(&bitvector);
            println!("Compressed bitvector len: {}",bitvector_compressed.len());
            let alg_description: String;
            match bitvector_compressed[0] {
                0 => alg_description=String::from("Hzip"),
                1 => alg_description=String::from("Bzip2"),
                2 => alg_description=String::from("Gzip"),
                _ => alg_description=String::from("Error: not supported")
            }
            println!("Algorithm used: {} - {}",bitvector_compressed[0], alg_description);

            let bitvector_uncompressed= bitvector_get_decompressed_stream(&mut bitvector_compressed);
            
            if bitvector==bitvector_uncompressed
            {
                println!("test matching ok");
            }
            else
            {
                println!("test matching ko");
                //detect the position of the difference
                let mut i=0;
                while i<bitvector.len()
                {
                    if bitvector[i]!=bitvector_uncompressed[i]
                    {
                        println!("first difference found at position {}, leaf {}, values orig:{}, decom: {}",i,i*8/BTV_LEAF_SIZE, bitvector[i],bitvector_uncompressed[i]);
                        break;
                    }
                    i+=1;
                }
            }        
        }
        else
        {
            println!("failed to load bitvector from file");
        }
    }
}
