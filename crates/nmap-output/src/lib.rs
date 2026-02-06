//! Output emitters: normal (-oN), XML (-oX), grepable (-oG),
//! script-kiddie (-oS), JSON (Lancer extension), SARIF (Lancer extension),
//! CSV (Lancer extension).

pub mod normal;
pub mod xml;
pub mod grepable;
pub mod script_kiddie;
pub mod json;
pub mod sarif;
pub mod csv_out;
pub mod common;

pub use normal::emit as emit_normal;
pub use xml::emit as emit_xml;
pub use grepable::emit as emit_grepable;
pub use script_kiddie::emit as emit_script_kiddie;
pub use json::emit as emit_json;
pub use sarif::emit as emit_sarif;
pub use csv_out::emit as emit_csv;
