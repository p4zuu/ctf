use std::env;

/*
   bin eg:  556bca753000-556bca754000
   libc eg: 7f3734e0d000-7f3734e0f000

*/
fn retrieve_address(crc32_address: u64, is_bin: bool) -> Option<u64> {
    let start: u64;
    let end: u64;
    if is_bin {
        start = 0x550000000000;
        end = 0x560000000000;
    } else {
        start = 0x7f0000000000;
        end = 0x800000000000;
    }

    for i in (start..end).step_by(1 << 0xc) {
        let bruted_crc = crc32fast::hash(&i.to_le_bytes()) as u64;
        let bruted_address = bruted_crc << 0xc;

        if bruted_address == crc32_address {
            return Some(i);
        }
    }

    None
}

fn find_address_before(target_address: u64) -> Option<u64> {
    for i in 0..0x100000000u64 {
        let input = &i.to_le_bytes();
        let mut v = input.to_vec();
        v.retain(|&x| x != 0);

        let bruted_crc = crc32fast::hash(&v) as u64;
        let bruted_address = bruted_crc << 0xc;

        if bruted_address > target_address {
            continue;
        }

        if target_address - bruted_address < 0x100 {
            println!("v: {:X?}", v);
            println!("map: {:X?}", bruted_address);
            return Some(i);
        }
    }

    None
}

fn main() {
    for (i, arg) in env::args()
        .collect::<Vec<String>>()
        .iter_mut()
        .enumerate()
        .skip(1)
    {
        let is_bin = i == 1;
        let crc32 = u64::from_str_radix(arg.trim_start_matches("0x"), 16).unwrap();

        let address = retrieve_address(crc32, is_bin).unwrap();
        println!("{:X?}: {:X?}", crc32, address);

        if is_bin {
            let key = find_address_before(crc32).unwrap();
            println!("key: {:X?}", key);
        }
    }
}
