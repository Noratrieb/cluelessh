//! Constants for SSH.
//! <https://datatracker.ietf.org/doc/html/rfc4250>

#[macro_export]
macro_rules! consts {
    (
        $ty:ty, fn $to_str_name:ident,
        $(const $NAME:ident = $value:expr;)*
    ) => {
        $(
            pub const $NAME: $ty = $value;
        )*

        pub fn $to_str_name(v: $ty) -> &'static str {
            #[allow(unreachable_patterns)]
            match v {
                $(
                    $NAME => stringify!($NAME),
                )*
                _ => "<unknown>",
            }
        }
    };
}

consts! {
    u8, fn packet_type_to_string,
    // -----
    // Transport layer protocol:

    // 1 to 19 Transport layer generic (e.g., disconnect, ignore, debug, etc.)
    const SSH_MSG_DISCONNECT = 1;
    const SSH_MSG_IGNORE = 2;
    const SSH_MSG_UNIMPLEMENTED = 3;
    const SSH_MSG_DEBUG = 4;
    const SSH_MSG_SERVICE_REQUEST = 5;
    const SSH_MSG_SERVICE_ACCEPT = 6;
    const SSH_MSG_EXT_INFO = 7;
    const SSH_MSG_NEWCOMPRESS = 8;

    // 20 to 29 Algorithm negotiation
    const SSH_MSG_KEXINIT = 20;
    const SSH_MSG_NEWKEYS = 21;

    // 30 to 49 Key exchange method specific (numbers can be reused for different authentication methods)
    const SSH_MSG_KEXDH_INIT = 30;
    const SSH_MSG_KEX_ECDH_INIT = 30; // Same number
    const SSH_MSG_KEXDH_REPLY = 31;
    const SSH_MSG_KEX_ECDH_REPLY = 31;

    // -----
    // User authentication protocol:

    // 50 to 59   User authentication generic
    const SSH_MSG_USERAUTH_REQUEST = 50;
    const SSH_MSG_USERAUTH_FAILURE = 51;
    const SSH_MSG_USERAUTH_SUCCESS = 52;
    const SSH_MSG_USERAUTH_BANNER = 53;

    //  60 to 79   User authentication method specific (numbers can be reused for different authentication methods)
    const SSH_MSG_USERAUTH_PK_OK = 60;

    // -----
    // Connection protocol:

    // 80 to 89   Connection protocol generic
    const SSH_MSG_GLOBAL_REQUEST = 80;
    const SSH_MSG_REQUEST_SUCCESS = 81;
    const SSH_MSG_REQUEST_FAILURE = 82;

    // 90 to 127  Channel related messages
    const SSH_MSG_CHANNEL_OPEN = 90;
    const SSH_MSG_CHANNEL_OPEN_CONFIRMATION = 91;
    const SSH_MSG_CHANNEL_OPEN_FAILURE = 92;
    const SSH_MSG_CHANNEL_WINDOW_ADJUST = 93;
    const SSH_MSG_CHANNEL_DATA = 94;
    const SSH_MSG_CHANNEL_EXTENDED_DATA = 95;
    const SSH_MSG_CHANNEL_EOF = 96;
    const SSH_MSG_CHANNEL_CLOSE = 97;
    const SSH_MSG_CHANNEL_REQUEST = 98;
    const SSH_MSG_CHANNEL_SUCCESS = 99;
    const SSH_MSG_CHANNEL_FAILURE = 100;
}

consts! {
    u32, fn disconnect_reason_to_string,
    const SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT = 1;
    const SSH_DISCONNECT_PROTOCOL_ERROR = 2;
    const SSH_DISCONNECT_KEY_EXCHANGE_FAILED = 3;
    const SSH_DISCONNECT_RESERVED = 4;
    const SSH_DISCONNECT_MAC_ERROR = 5;
    const SSH_DISCONNECT_COMPRESSION_ERROR = 6;
    const SSH_DISCONNECT_SERVICE_NOT_AVAILABLE = 7;
    const SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED = 8;
    const SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE = 9;
    const SSH_DISCONNECT_CONNECTION_LOST = 10;
    const SSH_DISCONNECT_BY_APPLICATION = 11;
    const SSH_DISCONNECT_TOO_MANY_CONNECTIONS = 12;
    const SSH_DISCONNECT_AUTH_CANCELLED_BY_USER = 13;
    const SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE = 14;
    const SSH_DISCONNECT_ILLEGAL_USER_NAME = 15;
}

consts! {
    u32, fn channel_connection_failure_to_string,

    const SSH_OPEN_ADMINISTRATIVELY_PROHIBITED = 1;
    const SSH_OPEN_CONNECT_FAILED = 2;
    const SSH_OPEN_UNKNOWN_CHANNEL_TYPE = 3;
    const SSH_OPEN_RESOURCE_SHORTAGE = 4;
}

pub const SSH_EXTENDED_DATA_STDERR: u32 = 1;

consts! {
    u8, fn sftp_message_type_to_string,
    const SSH_FXP_INIT = 1;
    const SSH_FXP_VERSION = 2;
    const SSH_FXP_OPEN = 3;
    const SSH_FXP_CLOSE = 4;
    const SSH_FXP_READ = 5;
    const SSH_FXP_WRITE = 6;
    const SSH_FXP_LSTAT = 7;
    const SSH_FXP_FSTAT = 8;
    const SSH_FXP_SETSTAT = 9;
    const SSH_FXP_FSETSTAT = 10;
    const SSH_FXP_OPENDIR = 11;
    const SSH_FXP_READDIR = 12;
    const SSH_FXP_REMOVE = 13;
    const SSH_FXP_MKDIR = 14;
    const SSH_FXP_RMDIR = 15;
    const SSH_FXP_REALPATH = 16;
    const SSH_FXP_STAT = 17;
    const SSH_FXP_RENAME = 18;
    const SSH_FXP_READLINK = 19;
    const SSH_FXP_SYMLINK = 20;
    const SSH_FXP_STATUS = 101;
    const SSH_FXP_HANDLE = 102;
    const SSH_FXP_DATA = 103;
    const SSH_FXP_NAME = 104;
    const SSH_FXP_ATTRS = 105;
    const SSH_FXP_EXTENDED = 200;
    const SSH_FXP_EXTENDED_REPLY = 201;
}

consts! {
    u32, fn sftp_error_code_to_string,
    const SSH_FX_OK = 0;
    const SSH_FX_EOF = 1;
    const SSH_FX_NO_SUCH_FILE = 2;
    const SSH_FX_PERMISSION_DENIED = 3;
    const SSH_FX_FAILURE = 4;
    const SSH_FX_BAD_MESSAGE = 5;
    const SSH_FX_NO_CONNECTION = 6;
    const SSH_FX_CONNECTION_LOST = 7;
    const SSH_FX_OP_UNSUPPORTED = 8;
}

consts! {
    u32, fn sftp_file_attr_flag_to_string,
    const SSH_FILEXFER_ATTR_SIZE = 0x00000001;
    const SSH_FILEXFER_ATTR_UIDGID = 0x00000002;
    const SSH_FILEXFER_ATTR_PERMISSIONS = 0x00000004;
    const SSH_FILEXFER_ATTR_ACMODTIME = 0x00000008;
    const SSH_FILEXFER_ATTR_EXTENDED = 0x80000000;
}
