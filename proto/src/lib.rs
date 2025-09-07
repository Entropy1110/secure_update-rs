#![no_std]
use num_enum::{FromPrimitive, IntoPrimitive};

#[derive(FromPrimitive, IntoPrimitive)]
#[repr(u32)]
pub enum Command {
    GenKey,
    GetPub,
    SetServerPub,
    VerifyServer,
    #[default]
    Unknown,
}

// UUID shared by host and TA
pub const UUID: &str = &include_str!("../../uuid.txt");
