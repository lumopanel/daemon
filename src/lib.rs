//! Lumo Daemon Library
//!
//! This crate provides the core functionality for the Lumo privilege daemon,
//! which executes privileged operations requested via Unix socket.

pub mod audit;
pub mod auth;
pub mod commands;
pub mod config;
pub mod error;
pub mod executor;
pub mod protocol;
pub mod services;
pub mod socket;
pub mod templates;
pub mod validation;
