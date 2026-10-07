use core::mem::{offset_of, size_of};

pub const FDDI_K_ALEN: usize = 6;
pub const FDDI_K_8022_HLEN: usize = 16;
pub const FDDI_K_SNAP_HLEN: usize = 21;
pub const FDDI_K_8022_DLEN: usize = 4475;
pub const FDDI_K_SNAP_DLEN: usize = 4470;
pub const FDDI_K_LLC_ZLEN: usize = 13;
pub const FDDI_K_LLC_LEN: usize = 4491;
pub const FDDI_K_OUI_LEN: usize = 3;
pub const FDDI_FC_K_CLASS_MASK: u8 = 0x80;
pub const FDDI_FC_K_FORMAT_LLC: u8 = 0x10;
pub const FDDI_FC_K_ASYNC_LLC_DEF: u8 = 0x54;
pub const FDDI_FC_K_NON_RESTRICTED_TOKEN: u8 = 0x80;
pub const FDDI_EXTENDED_SAP: u8 = 0xAA;
pub const FDDI_UI_CMD: u8 = 0x03;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FddiHeader {
    pub fddi_fc: u8,
    pub fddi_dhost: [u8; FDDI_K_ALEN],
    pub fddi_shost: [u8; FDDI_K_ALEN],
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Fddi80221Hdr {
    pub dsap: u8,
    pub ssap: u8,
    pub ctrl: u8,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Fddi80222Hdr {
    pub dsap: u8,
    pub ssap: u8,
    pub ctrl_1: u8,
    pub ctrl_2: u8,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FddiSnapHdr {
    pub dsap: u8,
    pub ssap: u8,
    pub ctrl: u8,
    pub oui: [u8; FDDI_K_OUI_LEN],
    pub ethertype: u16,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub union FddiLlc {
    pub llc_8022_1: Fddi80221Hdr,
    pub llc_8022_2: Fddi80222Hdr,
    pub llc_snap: FddiSnapHdr,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct Fddihdr {
    pub fc: u8,
    pub daddr: [u8; FDDI_K_ALEN],
    pub saddr: [u8; FDDI_K_ALEN],
    pub hdr: FddiLlc,
}

const _: () = {
    assert!(size_of::<FddiHeader>() == 13);
    assert!(offset_of!(FddiHeader, fddi_dhost) == 1);
    assert!(offset_of!(FddiHeader, fddi_shost) == 7);
    assert!(size_of::<Fddi80221Hdr>() == 3);
    assert!(size_of::<Fddi80222Hdr>() == 4);
    assert!(size_of::<FddiSnapHdr>() == 8);
    assert!(offset_of!(FddiSnapHdr, oui) == 3);
    assert!(offset_of!(FddiSnapHdr, ethertype) == 6);
    assert!(size_of::<Fddihdr>() == 21);
    assert!(offset_of!(Fddihdr, daddr) == 1);
    assert!(offset_of!(Fddihdr, saddr) == 7);
    assert!(offset_of!(Fddihdr, hdr) == 13);
};
