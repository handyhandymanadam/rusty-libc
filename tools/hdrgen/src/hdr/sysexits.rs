use crate::model::*;

pub static HDR: Header = Header {
    path: "sysexits.h",
    items: &[
        Item::Guard { name: "_SYSEXITS_H", value: "1", end: "", items: &[
            Item::Consts(&[
                ("EX_OK", V::Dec(0)),
                ("EX__BASE", V::Dec(64)),
                ("EX_USAGE", V::Dec(64)),
                ("EX_DATAERR", V::Dec(65)),
                ("EX_NOINPUT", V::Dec(66)),
                ("EX_NOUSER", V::Dec(67)),
                ("EX_NOHOST", V::Dec(68)),
                ("EX_UNAVAILABLE", V::Dec(69)),
                ("EX_SOFTWARE", V::Dec(70)),
                ("EX_OSERR", V::Dec(71)),
                ("EX_OSFILE", V::Dec(72)),
                ("EX_CANTCREAT", V::Dec(73)),
                ("EX_IOERR", V::Dec(74)),
                ("EX_TEMPFAIL", V::Dec(75)),
                ("EX_PROTOCOL", V::Dec(76)),
                ("EX_NOPERM", V::Dec(77)),
                ("EX_CONFIG", V::Dec(78)),
                ("EX__MAX", V::Dec(78)),
            ]),
        ]},
    ],
};
