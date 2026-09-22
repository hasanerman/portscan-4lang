use std::net::IpAddr;

pub fn is_local(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(v4) => is_local_v4(v4.octets()),
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_local_v4(mapped.octets());
            }
            is_local_v6(v6.octets())
        }
    }
}

fn is_local_v4(b: [u8; 4]) -> bool {
    b[0] == 127
        || b[0] == 10
        || b[0] == 0
        || (b[0] == 172 && (16..=31).contains(&b[1]))
        || (b[0] == 192 && b[1] == 168)
        || (b[0] == 169 && b[1] == 254)
}

fn is_local_v6(b: [u8; 16]) -> bool {
    if b[..15].iter().all(|&byte| byte == 0) && (b[15] == 0 || b[15] == 1) {
        return true;
    }
    if b[0] == 0xfe && (b[1] & 0xc0) == 0x80 {
        return true;
    }
    (b[0] & 0xfe) == 0xfc
}
