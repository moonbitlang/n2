#![allow(clippy::all)]
pub mod canon;
pub mod db;
pub mod densemap;
mod depfile;
mod eval;
pub mod graph;
mod hash;
pub mod load;
pub mod parse;
mod process;
#[cfg(unix)]
mod process_posix;
#[cfg(windows)]
mod process_win;
pub mod progress;
pub mod run;
pub mod scanner;
mod signal;
pub mod smallmap;
mod task;
pub mod terminal;
pub mod trace;
pub mod work;

// #[cfg(not(any(windows, target_arch = "wasm32")))]
// use jemallocator::Jemalloc;

// #[cfg(not(any(windows, target_arch = "wasm32")))]
// #[global_allocator]
// static GLOBAL: Jemalloc = Jemalloc;
