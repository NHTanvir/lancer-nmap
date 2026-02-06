//! `-oS` script-kiddie 1337-speak output (just for the meme — upstream
//! parity).

use crate::normal;
use nmap_core::result::ScanResult;

pub fn emit(r: &ScanResult) -> String {
    let mut s = normal::emit(r);
    s = s.replace('a', "4");
    s = s.replace('e', "3");
    s = s.replace('i', "1");
    s = s.replace('o', "0");
    s = s.replace('s', "5");
    s = s.replace('S', "5");
    s = s.replace('A', "4");
    s = s.replace('E', "3");
    s = s.replace('t', "7");
    s.replace('T', "7")
}
