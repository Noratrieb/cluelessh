use cluelessh_format::Writer;
use cluelessh_transport::key::PublicKey;

// TODO SessionId newtype
pub fn signature_data(session_id: [u8; 32], username: &str, pubkey: &PublicKey) -> Vec<u8> {
    let mut s = Writer::new();

    s.string(session_id);
    s.u8(cluelessh_transport::numbers::SSH_MSG_USERAUTH_REQUEST);
    s.string(username);
    s.string("ssh-connection");
    s.string("publickey");
    s.bool(true);
    s.string(pubkey.algorithm_name());
    s.string(pubkey.to_wire_encoding());

    s.finish()
}
