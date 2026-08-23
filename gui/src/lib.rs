//! nettool-gui - a desktop front end for the `nettool` network diagnostics CLI.
//!
//! The GUI never re-implements the diagnostics: it runs `nettool ... --json` on worker
//! threads and renders the results, so both interfaces always agree. This library target
//! exists so the models, the command builders and the analysis helpers can be tested
//! without opening a window.

pub mod app;
pub mod maclocation;
pub mod model;
pub mod runner;
pub mod ui;
