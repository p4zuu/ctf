use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

fn main() -> std::io::Result<()> {
    let mut file = File::open("flecks")?;
    file.seek(SeekFrom::Start(0xc6e00))?;

    let mut raw_content = [0u8; 0x32];
    let _ = file.read(&mut raw_content)?;

    let mut v = raw_content.chunks(2).collect::<Vec<&[u8]>>();
    v.sort_by(|&a, &b| a[0].cmp(&b[0]));

    println!(
        "Flag: {:?}",
        String::from_utf8_lossy(&v.iter().map(|&s| s[1]).collect::<Vec<u8>>())
    );
    println!("Indexes [0xa, 0x12, 0x17, 0x19]are missing, I guessed their value.");

    Ok(())
}
