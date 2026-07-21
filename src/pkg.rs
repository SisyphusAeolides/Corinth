#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackageId<'a> {
    pub name: &'a str,
    pub version: &'a str,
}
