use crate::model::*;

pub static AFTER_INCLUDES: &[Item] = &[
    Item::Comment("/* glibc declares malloc, calloc, realloc and free here too; stdlib.h has them */"),
    Item::Include("<stdlib.h>"),
    Item::Include("<stdio.h>   /* glibc: FILE, for malloc_info */"),
];
pub const AFTER_INCLUDES_CHOMP: bool = false;

