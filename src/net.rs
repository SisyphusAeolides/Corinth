#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ipv4Address(pub [u8; 4]);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Route {
    pub network: Ipv4Address,
    pub prefix_len: u8,
    pub gateway: Option<Ipv4Address>,
}
