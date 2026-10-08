use crate::model::*;

pub static HDR: Header = Header {
    path: "sys/io.h",
    items: &[
        Item::Guard { name: "_SYS_IO_H", value: "1", end: "", items: &[
            Item::Include("<features.h>"),
            Item::ExternBegin,
            Item::Blank,
            Item::Include("<sys/perm.h>"),
            Item::Raw(Reason::StaticInline, r#"static __inline unsigned char inb (unsigned short int __port) { unsigned char _v; __asm__ __volatile__ ("inb %w1,%0":"=a" (_v):"Nd" (__port)); return _v; }"#),
            Item::Raw(Reason::StaticInline, r#"static __inline unsigned char inb_p (unsigned short int __port) { unsigned char _v; __asm__ __volatile__ ("inb %w1,%0\noutb %%al,$0x80":"=a" (_v):"Nd" (__port)); return _v; }"#),
            Item::Raw(Reason::StaticInline, r#"static __inline unsigned short int inw (unsigned short int __port) { unsigned short _v; __asm__ __volatile__ ("inw %w1,%0":"=a" (_v):"Nd" (__port)); return _v; }"#),
            Item::Raw(Reason::StaticInline, r#"static __inline unsigned int inl (unsigned short int __port) { unsigned int _v; __asm__ __volatile__ ("inl %w1,%0":"=a" (_v):"Nd" (__port)); return _v; }"#),
            Item::Raw(Reason::StaticInline, r#"static __inline void outb (unsigned char __value, unsigned short int __port) { __asm__ __volatile__ ("outb %b0,%w1": :"a" (__value), "Nd" (__port)); }"#),
            Item::Raw(Reason::StaticInline, r#"static __inline void outb_p (unsigned char __value, unsigned short int __port) { __asm__ __volatile__ ("outb %b0,%w1\noutb %%al,$0x80": :"a" (__value), "Nd" (__port)); }"#),
            Item::Raw(Reason::StaticInline, r#"static __inline void outw (unsigned short int __value, unsigned short int __port) { __asm__ __volatile__ ("outw %w0,%w1": :"a" (__value), "Nd" (__port)); }"#),
            Item::Raw(Reason::StaticInline, r#"static __inline void outl (unsigned int __value, unsigned short int __port) { __asm__ __volatile__ ("outl %0,%w1": :"a" (__value), "Nd" (__port)); }"#),
            Item::Blank,
            Item::ExternEnd,
        ]},
    ],
};
