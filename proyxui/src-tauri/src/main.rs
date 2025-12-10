#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::error::Error as StdError;

fn main() -> Result<(), Box<dyn StdError>> {
    proyxui_lib::run()
}
