use crate::model::*;

pub static HDR: Header = Header {
    path: "bits/fcntl-linux-fortify.h",
    items: &[
        Item::Comment(r####"/* Checking macros for fcntl functions.  Linux version.
   Copyright (C) 2025-2026 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <https://www.gnu.org/licenses/>.  */"####),
        Item::Guard { name: "_BITS_FCNTL_LINUX_FORTIFY_H", value: "1", end: "", items: &[
            Item::Raw(Reason::FeatureTest, r####"#ifndef	_FCNTL_H
# error "Never include <bits/fcntl-linux-fortify.h> directly; use <fcntl.h> instead."
#endif"####),
            Item::Raw(Reason::FeatureTest, r####"#ifdef __USE_GNU"####),
            Item::Raw(Reason::Other, r####"extern int __REDIRECT (__openat2_alias, (int __dfd, const char *__filename,
					 const struct open_how *__how,
					 size_t __usize), openat2)
     __nonnull ((2, 3));"####),
            Item::Raw(Reason::FeatureTest, r####"#if !__fortify_use_clang
__errordecl (__openat2_invalid_size,
	     "the specified size is larger than sizeof (struct open_how)");
#endif"####),
            Item::Raw(Reason::StaticInline, r####"__fortify_function int
openat2 (int __dfd, const char *__filename, const struct open_how *__how,
	 size_t __usize)
     __fortify_clang_warning (__builtin_constant_p (__usize)
			      && __usize > sizeof (struct open_how),
			      "the specified size is larger than sizeof (struct open_how)")
{
#if !__fortify_use_clang
  if (__builtin_constant_p (__usize) && __usize > sizeof (struct open_how))
    __openat2_invalid_size ();
#endif
  return __openat2_alias (__dfd, __filename, __how, __usize);
}"####),
            Item::Raw(Reason::FeatureTest, r####"#endif"####),
        ]},
    ],
};
