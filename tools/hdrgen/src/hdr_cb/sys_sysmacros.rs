use crate::model::*;

pub static AFTER_INCLUDES: &[Item] = &[
    Item::Raw(Reason::GlibcMacro, "#define major(dev) gnu_dev_major(dev)"),
    Item::Raw(Reason::GlibcMacro, "#define minor(dev) gnu_dev_minor(dev)"),
    Item::Raw(Reason::GlibcMacro, "#define makedev(maj, min) gnu_dev_makedev(maj, min)"),
];
pub const AFTER_INCLUDES_CHOMP: bool = false;

