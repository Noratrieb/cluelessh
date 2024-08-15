use crate::packet::Packet;
use crate::parse::Writer;

#[allow(non_camel_case_types)]
mod ssh_type_to_rust {
    pub(super) use {bool, u32, u8};
    pub(super) type string<'a> = &'a [u8];
    pub(super) type name_list<'a> = crate::parse::NameList<'a>;
}

macro_rules! ctors {
    (
        $(
            fn $fn_name:ident(
                $msg_type:ident;
                $(
                    $name:ident: $ssh_type:ident
                ),*
                $(,)?
            );
        )*
    ) => {
        impl Packet {
            $(
                pub fn $fn_name(
                    $(
                        $name: ssh_type_to_rust::$ssh_type
                    ),*
                ) -> Packet {
                    let mut w = Writer::new();

                    w.u8($crate::numbers::$msg_type);

                    $(
                        w.$ssh_type($name);
                    )*

                    Packet {
                        payload: w.finish(),
                    }
                }
            )*
        }
    };
}

ctors! {
    // -----
    // Transport layer protocol:

    // 1 to 19 Transport layer generic (e.g., disconnect, ignore, debug, etc.)
    fn new_msg_service_request(SSH_MSG_SERVICE_REQUEST; service_name: string);
    // 20 to 29 Algorithm negotiation
    // 30 to 49 Key exchange method specific (numbers can be reused for different authentication methods)
    fn new_msg_kex_ecdh_init(SSH_MSG_KEX_ECDH_INIT; client_ephemeral_public_key_qc: string);
    fn new_msg_kex_ecdh_reply(SSH_MSG_KEX_ECDH_REPLY;
        server_public_host_key_ks: string,
        server_ephemeral_public_key_qs: string,
        signature: string,
    );

    // -----
    // User authentication protocol:

    // 50 to 59   User authentication generic
    fn new_msg_userauth_failure(SSH_MSG_USERAUTH_FAILURE;
        auth_options: name_list,
        partial_success: bool,
    );
    fn new_msg_userauth_success(SSH_MSG_USERAUTH_SUCCESS;);
    fn new_msg_userauth_banner(SSH_MSG_USERAUTH_BANNER; msg: string, language_tag: string);

    //  60 to 79   User authentication method specific (numbers can be reused for different authentication methods)

    // -----
    // Connection protocol:

    // 80 to 89   Connection protocol generic
    fn new_msg_request_failure(SSH_MSG_REQUEST_FAILURE;);

    // 90 to 127  Channel related messages
    fn new_msg_channel_open_session(SSH_MSG_CHANNEL_OPEN;
        session: string,
        sender_channel: u32,
        initial_window_size: u32,
        maximum_packet_size: u32,
    );
    fn new_msg_channel_open_confirmation(SSH_MSG_CHANNEL_OPEN_CONFIRMATION;
        peer_channel: u32,
        sender_channel: u32,
        initial_window_size: u32,
        max_packet_size: u32,
    );
    fn new_msg_channel_open_failure(SSH_MSG_CHANNEL_OPEN_FAILURE;
        sender_channe: u32,
        reason_code: u32,
        description: string,
        language_tag: string,
    );
    fn new_msg_channel_window_adjust(SSH_MSG_CHANNEL_WINDOW_ADJUST; recipient_channel: u32, bytes_to_add: u32);
    fn new_msg_channel_data(SSH_MSG_CHANNEL_DATA; recipient_channel: u32, data: string);

    fn new_msg_channel_eof(SSH_MSG_CHANNEL_EOF; recipient_channel: u32);
    fn new_msg_channel_close(SSH_MSG_CHANNEL_CLOSE; recipient_channel: u32);

    fn new_msg_channel_request_pty_req(SSH_MSG_CHANNEL_REQUEST;
        recipient_channel: u32,
        kind_pty_req: string,
        want_reply: bool,
        term: string,
        term_width_char: u32,
        term_height_rows: u32,
        term_width_px: u32,
        term_height_px: u32,
        term_modes: string,
    );
    fn new_msg_channel_request_shell(SSH_MSG_CHANNEL_REQUEST;
        recipient_channel: u32,
        kind_shell: string,
        want_reply: bool,
    );
    fn new_msg_channel_request_exit_status(SSH_MSG_CHANNEL_REQUEST; recipient_channel: u32, kind_exit_status: string, false_: bool, exit_status: u32);

    fn new_msg_channel_success(SSH_MSG_CHANNEL_SUCCESS; recipient_channel: u32);
    fn new_msg_channel_failure(SSH_MSG_CHANNEL_FAILURE; recipient_channel: u32);
}
