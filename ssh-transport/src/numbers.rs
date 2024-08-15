//! Constants for SSH.
//! <https://datatracker.ietf.org/doc/html/rfc4250>

// -----
// Transport layer protocol:

// 1 to 19 Transport layer generic (e.g., disconnect, ignore, debug, etc.)
pub const SSH_MSG_DISCONNECT: u8 = 1;
pub const SSH_MSG_IGNORE: u8 = 2;
pub const SSH_MSG_UNIMPLEMENTED: u8 = 3;
pub const SSH_MSG_DEBUG: u8 = 4;
pub const SSH_MSG_SERVICE_REQUEST: u8 = 5;
pub const SSH_MSG_SERVICE_ACCEPT: u8 = 6;

// 20 to 29 Algorithm negotiation
pub const SSH_MSG_KEXINIT: u8 = 20;
pub const SSH_MSG_NEWKEYS: u8 = 21;

// 30 to 49 Key exchange method specific (numbers can be reused for different authentication methods)
pub const SSH_MSG_KEXDH_INIT: u8 = 30;
pub const SSH_MSG_KEX_ECDH_INIT: u8 = 30; // Same number
pub const SSH_MSG_KEXDH_REPLY: u8 = 31;
pub const SSH_MSG_KEX_ECDH_REPLY: u8 = 31;

// -----
// User authentication protocol:

// 50 to 59   User authentication generic
pub const SSH_MSG_USERAUTH_REQUEST: u8 = 50;
pub const SSH_MSG_USERAUTH_FAILURE: u8 = 51;
pub const SSH_MSG_USERAUTH_SUCCESS: u8 = 52;
pub const SSH_MSG_USERAUTH_BANNER: u8 = 53;

//  60 to 79   User authentication method specific (numbers can be reused for different authentication methods)

// -----
// Connection protocol:

// 80 to 89   Connection protocol generic
pub const SSH_MSG_GLOBAL_REQUEST: u8 = 80;
pub const SSH_MSG_REQUEST_SUCCESS: u8 = 81;
pub const SSH_MSG_REQUEST_FAILURE: u8 = 82;

// 90 to 127  Channel related messages
pub const SSH_MSG_CHANNEL_OPEN: u8 = 90;
pub const SSH_MSG_CHANNEL_OPEN_CONFIRMATION: u8 = 91;
pub const SSH_MSG_CHANNEL_OPEN_FAILURE: u8 = 92;
pub const SSH_MSG_CHANNEL_WINDOW_ADJUST: u8 = 93;
pub const SSH_MSG_CHANNEL_DATA: u8 = 94;
pub const SSH_MSG_CHANNEL_EXTENDED_DATA: u8 = 95;
pub const SSH_MSG_CHANNEL_EOF: u8 = 96;
pub const SSH_MSG_CHANNEL_CLOSE: u8 = 97;
pub const SSH_MSG_CHANNEL_REQUEST: u8 = 98;
pub const SSH_MSG_CHANNEL_SUCCESS: u8 = 99;
pub const SSH_MSG_CHANNEL_FAILURE: u8 = 100;

pub fn packet_type_to_string(packet_type: u8) -> &'static str {
    match packet_type {
        1 => "SSH_MSG_DISCONNECT",
        2 => "SSH_MSG_IGNORE",
        3 => "SSH_MSG_UNIMPLEMENTED",
        4 => "SSH_MSG_DEBUG",
        5 => "SSH_MSG_SERVICE_REQUEST",
        6 => "SSH_MSG_SERVICE_ACCEPT",
        20 => "SSH_MSG_KEXINIT",
        21 => "SSH_MSG_NEWKEYS",
        30 => "SSH_MSG_KEX_ECDH_INIT",
        31 => "SSH_MSG_KEX_ECDH_REPLY",
        50 => "SSH_MSG_USERAUTH_REQUEST",
        51 => "SSH_MSG_USERAUTH_FAILURE",
        52 => "SSH_MSG_USERAUTH_SUCCESS",
        53 => "SSH_MSG_USERAUTH_BANNER",
        80 => "SSH_MSG_GLOBAL_REQUEST",
        81 => "SSH_MSG_REQUEST_SUCCESS",
        82 => "SSH_MSG_REQUEST_FAILURE",
        90 => "SSH_MSG_CHANNEL_OPEN",
        91 => "SSH_MSG_CHANNEL_OPEN_CONFIRMATION",
        92 => "SSH_MSG_CHANNEL_OPEN_FAILURE",
        93 => "SSH_MSG_CHANNEL_WINDOW_ADJUST",
        94 => "SSH_MSG_CHANNEL_DATA",
        95 => "SSH_MSG_CHANNEL_EXTENDED_DATA",
        96 => "SSH_MSG_CHANNEL_EOF",
        97 => "SSH_MSG_CHANNEL_CLOSE",
        98 => "SSH_MSG_CHANNEL_REQUEST",
        99 => "SSH_MSG_CHANNEL_SUCCESS",
        100 => "SSH_MSG_CHANNEL_FAILURE",
        _ => "<unknown>",
    }
}

pub const SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT: u32 = 1;
pub const SSH_DISCONNECT_PROTOCOL_ERROR: u32 = 2;
pub const SSH_DISCONNECT_KEY_EXCHANGE_FAILED: u32 = 3;
pub const SSH_DISCONNECT_RESERVED: u32 = 4;
pub const SSH_DISCONNECT_MAC_ERROR: u32 = 5;
pub const SSH_DISCONNECT_COMPRESSION_ERROR: u32 = 6;
pub const SSH_DISCONNECT_SERVICE_NOT_AVAILABLE: u32 = 7;
pub const SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED: u32 = 8;
pub const SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE: u32 = 9;
pub const SSH_DISCONNECT_CONNECTION_LOST: u32 = 10;
pub const SSH_DISCONNECT_BY_APPLICATION: u32 = 11;
pub const SSH_DISCONNECT_TOO_MANY_CONNECTIONS: u32 = 12;
pub const SSH_DISCONNECT_AUTH_CANCELLED_BY_USER: u32 = 13;
pub const SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE: u32 = 14;
pub const SSH_DISCONNECT_ILLEGAL_USER_NAME: u32 = 15;

pub fn disconnect_reason_to_string(reason: u32) -> Option<&'static str> {
    Some(match reason {
        1 => "SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT",
        2 => "SSH_DISCONNECT_PROTOCOL_ERROR",
        3 => "SSH_DISCONNECT_KEY_EXCHANGE_FAILED",
        4 => "SSH_DISCONNECT_RESERVED",
        5 => "SSH_DISCONNECT_MAC_ERROR",
        6 => "SSH_DISCONNECT_COMPRESSION_ERROR",
        7 => "SSH_DISCONNECT_SERVICE_NOT_AVAILABLE",
        8 => "SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED",
        9 => "SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE",
        10 => "SSH_DISCONNECT_CONNECTION_LOST",
        11 => "SSH_DISCONNECT_BY_APPLICATION",
        12 => "SSH_DISCONNECT_TOO_MANY_CONNECTIONS",
        13 => "SSH_DISCONNECT_AUTH_CANCELLED_BY_USER",
        14 => "SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE",
        15 => "SSH_DISCONNECT_ILLEGAL_USER_NAME",
        _ => return None,
    })
}

pub const SSH_OPEN_ADMINISTRATIVELY_PROHIBITED: u32 = 1;
pub const SSH_OPEN_CONNECT_FAILED: u32 = 2;
pub const SSH_OPEN_UNKNOWN_CHANNEL_TYPE: u32 = 3;
pub const SSH_OPEN_RESOURCE_SHORTAGE: u32 = 4;

pub fn channel_connection_failure_to_string(reason: u32) -> Option<&'static str> {
    Some(match reason {
        1 => "SSH_OPEN_ADMINISTRATIVELY_PROHIBITED",
        2 => "SSH_OPEN_CONNECT_FAILED",
        3 => "SSH_OPEN_UNKNOWN_CHANNEL_TYPE",
        4 => "SSH_OPEN_RESOURCE_SHORTAGE",
        _ => return None,
    })
}

pub const SSH_EXTENDED_DATA_STDERR: u32 = 1;
