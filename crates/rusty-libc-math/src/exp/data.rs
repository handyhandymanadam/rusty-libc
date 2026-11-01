//! Tables for exp, exp2, exp10, log, log2, pow and the float versions.
//!
//! GENERATED from ARM optimized-routines math/*_data.c (https://github.com/ARM-software/optimized-routines,
//! commit 503fafe, MIT OR Apache-2.0 WITH LLVM-exception, Copyright Arm Limited) by a script that
//! evaluates the C preprocessor choices glibc 2.43 also uses (exp N=128, log N=128, log2 N=64,
//! pow N=128, float functions N=32/16). Values are the C source's hexadecimal floats, written as
//! bit patterns. Derived data: list in LICENSES.md.
#![allow(clippy::unreadable_literal)]

// ARM optimized-routines math/exp_data.c (MIT OR Apache-2.0 WITH LLVM-exception), N=128, order 5, not wide
pub static EXP_POLY: [f64; 4] = [
    f64::from_bits(0x3fdffffffffffdbd), // 0x1.ffffffffffdbdp-2
    f64::from_bits(0x3fc555555555543c), // 0x1.555555555543cp-3
    f64::from_bits(0x3fa55555cf172b91), // 0x1.55555cf172b91p-5
    f64::from_bits(0x3f81111167a4d017), // 0x1.1111167a4d017p-7
];

// ARM optimized-routines math/exp_data.c (MIT OR Apache-2.0 WITH LLVM-exception), N=128, order 5, not wide
pub static EXP2_POLY: [f64; 5] = [
    f64::from_bits(0x3fe62e42fefa39ef), // 0x1.62e42fefa39efp-1
    f64::from_bits(0x3fcebfbdff82c424), // 0x1.ebfbdff82c424p-3
    f64::from_bits(0x3fac6b08d70cf4b5), // 0x1.c6b08d70cf4b5p-5
    f64::from_bits(0x3f83b2abd24650cc), // 0x1.3b2abd24650ccp-7
    f64::from_bits(0x3f55d7e09b4e3a84), // 0x1.5d7e09b4e3a84p-10
];

// ARM optimized-routines math/exp_data.c (MIT OR Apache-2.0 WITH LLVM-exception), N=128, order 5, not wide
pub static EXP10_POLY: [f64; 5] = [
    f64::from_bits(0x40026bb1bbb55516), // 0x1.26bb1bbb55516p+1
    f64::from_bits(0x40053524c73ce9fe), // 0x1.53524c73ce9fep+1
    f64::from_bits(0x4000470591ce4b26), // 0x1.0470591ce4b26p+1
    f64::from_bits(0x3ff2bd76577fe684), // 0x1.2bd76577fe684p+0
    f64::from_bits(0x3fe1446eeccd0efb), // 0x1.1446eeccd0efbp-1
];

// ARM optimized-routines math/exp_data.c (MIT OR Apache-2.0 WITH LLVM-exception), N=128, order 5, not wide: tab[2k]=bits of the tail T[k], tab[2k+1]=bits(H[k])-(k<<52)/N
pub static EXP_TAB: [u64; 256] = [
    0x0000000000000000, 0x3ff0000000000000,
    0x3c9b3b4f1a88bf6e, 0x3feff63da9fb3335,
    0xbc7160139cd8dc5d, 0x3fefec9a3e778061,
    0xbc905e7a108766d1, 0x3fefe315e86e7f85,
    0x3c8cd2523567f613, 0x3fefd9b0d3158574,
    0xbc8bce8023f98efa, 0x3fefd06b29ddf6de,
    0x3c60f74e61e6c861, 0x3fefc74518759bc8,
    0x3c90a3e45b33d399, 0x3fefbe3ecac6f383,
    0x3c979aa65d837b6d, 0x3fefb5586cf9890f,
    0x3c8eb51a92fdeffc, 0x3fefac922b7247f7,
    0x3c3ebe3d702f9cd1, 0x3fefa3ec32d3d1a2,
    0xbc6a033489906e0b, 0x3fef9b66affed31b,
    0xbc9556522a2fbd0e, 0x3fef9301d0125b51,
    0xbc5080ef8c4eea55, 0x3fef8abdc06c31cc,
    0xbc91c923b9d5f416, 0x3fef829aaea92de0,
    0x3c80d3e3e95c55af, 0x3fef7a98c8a58e51,
    0xbc801b15eaa59348, 0x3fef72b83c7d517b,
    0xbc8f1ff055de323d, 0x3fef6af9388c8dea,
    0x3c8b898c3f1353bf, 0x3fef635beb6fcb75,
    0xbc96d99c7611eb26, 0x3fef5be084045cd4,
    0x3c9aecf73e3a2f60, 0x3fef54873168b9aa,
    0xbc8fe782cb86389d, 0x3fef4d5022fcd91d,
    0x3c8a6f4144a6c38d, 0x3fef463b88628cd6,
    0x3c807a05b0e4047d, 0x3fef3f49917ddc96,
    0x3c968efde3a8a894, 0x3fef387a6e756238,
    0x3c875e18f274487d, 0x3fef31ce4fb2a63f,
    0x3c80472b981fe7f2, 0x3fef2b4565e27cdd,
    0xbc96b87b3f71085e, 0x3fef24dfe1f56381,
    0x3c82f7e16d09ab31, 0x3fef1e9df51fdee1,
    0xbc3d219b1a6fbffa, 0x3fef187fd0dad990,
    0x3c8b3782720c0ab4, 0x3fef1285a6e4030b,
    0x3c6e149289cecb8f, 0x3fef0cafa93e2f56,
    0x3c834d754db0abb6, 0x3fef06fe0a31b715,
    0x3c864201e2ac744c, 0x3fef0170fc4cd831,
    0x3c8fdd395dd3f84a, 0x3feefc08b26416ff,
    0xbc86a3803b8e5b04, 0x3feef6c55f929ff1,
    0xbc924aedcc4b5068, 0x3feef1a7373aa9cb,
    0xbc9907f81b512d8e, 0x3feeecae6d05d866,
    0xbc71d1e83e9436d2, 0x3feee7db34e59ff7,
    0xbc991919b3ce1b15, 0x3feee32dc313a8e5,
    0x3c859f48a72a4c6d, 0x3feedea64c123422,
    0xbc9312607a28698a, 0x3feeda4504ac801c,
    0xbc58a78f4817895b, 0x3feed60a21f72e2a,
    0xbc7c2c9b67499a1b, 0x3feed1f5d950a897,
    0x3c4363ed60c2ac11, 0x3feece086061892d,
    0x3c9666093b0664ef, 0x3feeca41ed1d0057,
    0x3c6ecce1daa10379, 0x3feec6a2b5c13cd0,
    0x3c93ff8e3f0f1230, 0x3feec32af0d7d3de,
    0x3c7690cebb7aafb0, 0x3feebfdad5362a27,
    0x3c931dbdeb54e077, 0x3feebcb299fddd0d,
    0xbc8f94340071a38e, 0x3feeb9b2769d2ca7,
    0xbc87deccdc93a349, 0x3feeb6daa2cf6642,
    0xbc78dec6bd0f385f, 0x3feeb42b569d4f82,
    0xbc861246ec7b5cf6, 0x3feeb1a4ca5d920f,
    0x3c93350518fdd78e, 0x3feeaf4736b527da,
    0x3c7b98b72f8a9b05, 0x3feead12d497c7fd,
    0x3c9063e1e21c5409, 0x3feeab07dd485429,
    0x3c34c7855019c6ea, 0x3feea9268a5946b7,
    0x3c9432e62b64c035, 0x3feea76f15ad2148,
    0xbc8ce44a6199769f, 0x3feea5e1b976dc09,
    0xbc8c33c53bef4da8, 0x3feea47eb03a5585,
    0xbc845378892be9ae, 0x3feea34634ccc320,
    0xbc93cedd78565858, 0x3feea23882552225,
    0x3c5710aa807e1964, 0x3feea155d44ca973,
    0xbc93b3efbf5e2228, 0x3feea09e667f3bcd,
    0xbc6a12ad8734b982, 0x3feea012750bdabf,
    0xbc6367efb86da9ee, 0x3fee9fb23c651a2f,
    0xbc80dc3d54e08851, 0x3fee9f7df9519484,
    0xbc781f647e5a3ecf, 0x3fee9f75e8ec5f74,
    0xbc86ee4ac08b7db0, 0x3fee9f9a48a58174,
    0xbc8619321e55e68a, 0x3fee9feb564267c9,
    0x3c909ccb5e09d4d3, 0x3feea0694fde5d3f,
    0xbc7b32dcb94da51d, 0x3feea11473eb0187,
    0x3c94ecfd5467c06b, 0x3feea1ed0130c132,
    0x3c65ebe1abd66c55, 0x3feea2f336cf4e62,
    0xbc88a1c52fb3cf42, 0x3feea427543e1a12,
    0xbc9369b6f13b3734, 0x3feea589994cce13,
    0xbc805e843a19ff1e, 0x3feea71a4623c7ad,
    0xbc94d450d872576e, 0x3feea8d99b4492ed,
    0x3c90ad675b0e8a00, 0x3feeaac7d98a6699,
    0x3c8db72fc1f0eab4, 0x3feeace5422aa0db,
    0xbc65b6609cc5e7ff, 0x3feeaf3216b5448c,
    0x3c7bf68359f35f44, 0x3feeb1ae99157736,
    0xbc93091fa71e3d83, 0x3feeb45b0b91ffc6,
    0xbc5da9b88b6c1e29, 0x3feeb737b0cdc5e5,
    0xbc6c23f97c90b959, 0x3feeba44cbc8520f,
    0xbc92434322f4f9aa, 0x3feebd829fde4e50,
    0xbc85ca6cd7668e4b, 0x3feec0f170ca07ba,
    0x3c71affc2b91ce27, 0x3feec49182a3f090,
    0x3c6dd235e10a73bb, 0x3feec86319e32323,
    0xbc87c50422622263, 0x3feecc667b5de565,
    0x3c8b1c86e3e231d5, 0x3feed09bec4a2d33,
    0xbc91bbd1d3bcbb15, 0x3feed503b23e255d,
    0x3c90cc319cee31d2, 0x3feed99e1330b358,
    0x3c8469846e735ab3, 0x3feede6b5579fdbf,
    0xbc82dfcd978e9db4, 0x3feee36bbfd3f37a,
    0x3c8c1a7792cb3387, 0x3feee89f995ad3ad,
    0xbc907b8f4ad1d9fa, 0x3feeee07298db666,
    0xbc55c3d956dcaeba, 0x3feef3a2b84f15fb,
    0xbc90a40e3da6f640, 0x3feef9728de5593a,
    0xbc68d6f438ad9334, 0x3feeff76f2fb5e47,
    0xbc91eee26b588a35, 0x3fef05b030a1064a,
    0x3c74ffd70a5fddcd, 0x3fef0c1e904bc1d2,
    0xbc91bdfbfa9298ac, 0x3fef12c25bd71e09,
    0x3c736eae30af0cb3, 0x3fef199bdd85529c,
    0x3c8ee3325c9ffd94, 0x3fef20ab5fffd07a,
    0x3c84e08fd10959ac, 0x3fef27f12e57d14b,
    0x3c63cdaf384e1a67, 0x3fef2f6d9406e7b5,
    0x3c676b2c6c921968, 0x3fef3720dcef9069,
    0xbc808a1883ccb5d2, 0x3fef3f0b555dc3fa,
    0xbc8fad5d3ffffa6f, 0x3fef472d4a07897c,
    0xbc900dae3875a949, 0x3fef4f87080d89f2,
    0x3c74a385a63d07a7, 0x3fef5818dcfba487,
    0xbc82919e2040220f, 0x3fef60e316c98398,
    0x3c8e5a50d5c192ac, 0x3fef69e603db3285,
    0x3c843a59ac016b4b, 0x3fef7321f301b460,
    0xbc82d52107b43e1f, 0x3fef7c97337b9b5f,
    0xbc892ab93b470dc9, 0x3fef864614f5a129,
    0x3c74b604603a88d3, 0x3fef902ee78b3ff6,
    0x3c83c5ec519d7271, 0x3fef9a51fbc74c83,
    0xbc8ff7128fd391f0, 0x3fefa4afa2a490da,
    0xbc8dae98e223747d, 0x3fefaf482d8e67f1,
    0x3c8ec3bc41aa2008, 0x3fefba1bee615a27,
    0x3c842b94c3a9eb32, 0x3fefc52b376bba97,
    0x3c8a64a931d185ee, 0x3fefd0765b6e4540,
    0xbc8e37bae43be3ed, 0x3fefdbfdad9cbe14,
    0x3c77893b4d91cd9d, 0x3fefe7c1819e90d8,
    0x3c5305c14160cc89, 0x3feff3c22b8f71f1,
];

// ARM optimized-routines math/exp2f_data.c, N=32
pub static EXP2F_TAB: [u64; 32] = [
    0x3ff0000000000000, 0x3fefd9b0d3158574, 0x3fefb5586cf9890f, 0x3fef9301d0125b51,
    0x3fef72b83c7d517b, 0x3fef54873168b9aa, 0x3fef387a6e756238, 0x3fef1e9df51fdee1,
    0x3fef06fe0a31b715, 0x3feef1a7373aa9cb, 0x3feedea64c123422, 0x3feece086061892d,
    0x3feebfdad5362a27, 0x3feeb42b569d4f82, 0x3feeab07dd485429, 0x3feea47eb03a5585,
    0x3feea09e667f3bcd, 0x3fee9f75e8ec5f74, 0x3feea11473eb0187, 0x3feea589994cce13,
    0x3feeace5422aa0db, 0x3feeb737b0cdc5e5, 0x3feec49182a3f090, 0x3feed503b23e255d,
    0x3feee89f995ad3ad, 0x3feeff76f2fb5e47, 0x3fef199bdd85529c, 0x3fef3720dcef9069,
    0x3fef5818dcfba487, 0x3fef7c97337b9b5f, 0x3fefa4afa2a490da, 0x3fefd0765b6e4540,
];

// ARM optimized-routines math/exp2f_data.c, N=32
pub static EXP2F_POLY: [f64; 3] = [
    f64::from_bits(0x3fac6af84b912394), // 0x1.c6af84b912394p-5
    f64::from_bits(0x3fcebfce50fac4f3), // 0x1.ebfce50fac4f3p-3
    f64::from_bits(0x3fe62e42ff0c52d6), // 0x1.62e42ff0c52d6p-1
];

// ARM optimized-routines math/exp2f_data.c, N=32
pub static EXP2F_POLY_SCALED: [f64; 3] = [
    f64::from_bits(0x3ebc6af84b912394), // 0x1.c6af84b912394p-20
    f64::from_bits(0x3f2ebfce50fac4f3), // 0x1.ebfce50fac4f3p-13
    f64::from_bits(0x3f962e42ff0c52d6), // 0x1.62e42ff0c52d6p-6
];

// ARM optimized-routines math/log_data.c, N=128, order 6, poly1 order 12 (coefficients of x^2.. after the fixed -0.5)
pub static LOG_POLY: [f64; 5] = [
    f64::from_bits(0xbfe0000000000001), // -0x1.0000000000001p-1
    f64::from_bits(0x3fd555555551305b), // 0x1.555555551305bp-2
    f64::from_bits(0xbfcfffffffeb4590), // -0x1.fffffffeb4590p-3
    f64::from_bits(0x3fc999b324f10111), // 0x1.999b324f10111p-3
    f64::from_bits(0xbfc55575e506c89f), // -0x1.55575e506c89fp-3
];

// ARM optimized-routines math/log_data.c, N=128, order 6, poly1 order 12
pub static LOG_POLY1: [f64; 11] = [
    f64::from_bits(0xbfe0000000000000), // -0x1.0000000000000p-1
    f64::from_bits(0x3fd5555555555577), // 0x1.5555555555577p-2
    f64::from_bits(0xbfcffffffffffdcb), // -0x1.ffffffffffdcbp-3
    f64::from_bits(0x3fc999999995dd0c), // 0x1.999999995dd0cp-3
    f64::from_bits(0xbfc55555556745a7), // -0x1.55555556745a7p-3
    f64::from_bits(0x3fc24924a344de30), // 0x1.24924a344de30p-3
    f64::from_bits(0xbfbfffffa4423d65), // -0x1.fffffa4423d65p-4
    f64::from_bits(0x3fbc7184282ad6ca), // 0x1.c7184282ad6cap-4
    f64::from_bits(0xbfb999eb43b068ff), // -0x1.999eb43b068ffp-4
    f64::from_bits(0x3fb78182f7afd085), // 0x1.78182f7afd085p-4
    f64::from_bits(0xbfb5521375d145cd), // -0x1.5521375d145cdp-4
];

// ARM optimized-routines math/log_data.c, N=128, order 6, poly1 order 12: pairs invc, logc
pub static LOG_TAB: [f64; 256] = [
    f64::from_bits(0x3ff734f0c3e0de9f), // 0x1.734f0c3e0de9fp+0
    f64::from_bits(0xbfd7cc7f79e69000), // -0x1.7cc7f79e69000p-2
    f64::from_bits(0x3ff713786a2ce91f), // 0x1.713786a2ce91fp+0
    f64::from_bits(0xbfd76feec20d0000), // -0x1.76feec20d0000p-2
    f64::from_bits(0x3ff6f26008fab5a0), // 0x1.6f26008fab5a0p+0
    f64::from_bits(0xbfd713e31351e000), // -0x1.713e31351e000p-2
    f64::from_bits(0x3ff6d1a61f138c7d), // 0x1.6d1a61f138c7dp+0
    f64::from_bits(0xbfd6b85b38287800), // -0x1.6b85b38287800p-2
    f64::from_bits(0x3ff6b1490bc5b4d1), // 0x1.6b1490bc5b4d1p+0
    f64::from_bits(0xbfd65d5590807800), // -0x1.65d5590807800p-2
    f64::from_bits(0x3ff69147332f0cba), // 0x1.69147332f0cbap+0
    f64::from_bits(0xbfd602d076180000), // -0x1.602d076180000p-2
    f64::from_bits(0x3ff6719f18224223), // 0x1.6719f18224223p+0
    f64::from_bits(0xbfd5a8ca86909000), // -0x1.5a8ca86909000p-2
    f64::from_bits(0x3ff6524f99a51ed9), // 0x1.6524f99a51ed9p+0
    f64::from_bits(0xbfd54f4356035000), // -0x1.54f4356035000p-2
    f64::from_bits(0x3ff63356aa8f24c4), // 0x1.63356aa8f24c4p+0
    f64::from_bits(0xbfd4f637c36b4000), // -0x1.4f637c36b4000p-2
    f64::from_bits(0x3ff614b36b9ddc14), // 0x1.614b36b9ddc14p+0
    f64::from_bits(0xbfd49da7fda85000), // -0x1.49da7fda85000p-2
    f64::from_bits(0x3ff5f66452c65c4c), // 0x1.5f66452c65c4cp+0
    f64::from_bits(0xbfd445923989a800), // -0x1.445923989a800p-2
    f64::from_bits(0x3ff5d867b5912c4f), // 0x1.5d867b5912c4fp+0
    f64::from_bits(0xbfd3edf439b0b800), // -0x1.3edf439b0b800p-2
    f64::from_bits(0x3ff5babccb5b90de), // 0x1.5babccb5b90dep+0
    f64::from_bits(0xbfd396ce448f7000), // -0x1.396ce448f7000p-2
    f64::from_bits(0x3ff59d61f2d91a78), // 0x1.59d61f2d91a78p+0
    f64::from_bits(0xbfd3401e17bda000), // -0x1.3401e17bda000p-2
    f64::from_bits(0x3ff5805612465687), // 0x1.5805612465687p+0
    f64::from_bits(0xbfd2e9e2ef468000), // -0x1.2e9e2ef468000p-2
    f64::from_bits(0x3ff56397cee76bd3), // 0x1.56397cee76bd3p+0
    f64::from_bits(0xbfd2941b3830e000), // -0x1.2941b3830e000p-2
    f64::from_bits(0x3ff54725e2a77f93), // 0x1.54725e2a77f93p+0
    f64::from_bits(0xbfd23ec58cda8800), // -0x1.23ec58cda8800p-2
    f64::from_bits(0x3ff52aff42064583), // 0x1.52aff42064583p+0
    f64::from_bits(0xbfd1e9e129279000), // -0x1.1e9e129279000p-2
    f64::from_bits(0x3ff50f22dbb2bddf), // 0x1.50f22dbb2bddfp+0
    f64::from_bits(0xbfd1956d2b48f800), // -0x1.1956d2b48f800p-2
    f64::from_bits(0x3ff4f38f4734ded7), // 0x1.4f38f4734ded7p+0
    f64::from_bits(0xbfd141679ab9f800), // -0x1.141679ab9f800p-2
    f64::from_bits(0x3ff4d843cfde2840), // 0x1.4d843cfde2840p+0
    f64::from_bits(0xbfd0edd094ef9800), // -0x1.0edd094ef9800p-2
    f64::from_bits(0x3ff4bd3ec078a3c8), // 0x1.4bd3ec078a3c8p+0
    f64::from_bits(0xbfd09aa518db1000), // -0x1.09aa518db1000p-2
    f64::from_bits(0x3ff4a27fc3e0258a), // 0x1.4a27fc3e0258ap+0
    f64::from_bits(0xbfd047e65263b800), // -0x1.047e65263b800p-2
    f64::from_bits(0x3ff4880524d48434), // 0x1.4880524d48434p+0
    f64::from_bits(0xbfcfeb224586f000), // -0x1.feb224586f000p-3
    f64::from_bits(0x3ff46dce1b192d0b), // 0x1.46dce1b192d0bp+0
    f64::from_bits(0xbfcf474a7517b000), // -0x1.f474a7517b000p-3
    f64::from_bits(0x3ff453d9d3391854), // 0x1.453d9d3391854p+0
    f64::from_bits(0xbfcea4443d103000), // -0x1.ea4443d103000p-3
    f64::from_bits(0x3ff43a2744b4845a), // 0x1.43a2744b4845ap+0
    f64::from_bits(0xbfce020d44e9b000), // -0x1.e020d44e9b000p-3
    f64::from_bits(0x3ff420b54115f8fb), // 0x1.420b54115f8fbp+0
    f64::from_bits(0xbfcd60a22977f000), // -0x1.d60a22977f000p-3
    f64::from_bits(0x3ff40782da3ef4b1), // 0x1.40782da3ef4b1p+0
    f64::from_bits(0xbfccc00104959000), // -0x1.cc00104959000p-3
    f64::from_bits(0x3ff3ee8f5d57fe8f), // 0x1.3ee8f5d57fe8fp+0
    f64::from_bits(0xbfcc202956891000), // -0x1.c202956891000p-3
    f64::from_bits(0x3ff3d5d9a00b4ce9), // 0x1.3d5d9a00b4ce9p+0
    f64::from_bits(0xbfcb81178d811000), // -0x1.b81178d811000p-3
    f64::from_bits(0x3ff3bd60c010c12b), // 0x1.3bd60c010c12bp+0
    f64::from_bits(0xbfcae2c9ccd3d000), // -0x1.ae2c9ccd3d000p-3
    f64::from_bits(0x3ff3a5242b75dab8), // 0x1.3a5242b75dab8p+0
    f64::from_bits(0xbfca45402e129000), // -0x1.a45402e129000p-3
    f64::from_bits(0x3ff38d22cd9fd002), // 0x1.38d22cd9fd002p+0
    f64::from_bits(0xbfc9a877681df000), // -0x1.9a877681df000p-3
    f64::from_bits(0x3ff3755bc5847a1c), // 0x1.3755bc5847a1cp+0
    f64::from_bits(0xbfc90c6d69483000), // -0x1.90c6d69483000p-3
    f64::from_bits(0x3ff35dce49ad36e2), // 0x1.35dce49ad36e2p+0
    f64::from_bits(0xbfc87120a645c000), // -0x1.87120a645c000p-3
    f64::from_bits(0x3ff34679984dd440), // 0x1.34679984dd440p+0
    f64::from_bits(0xbfc7d68fb4143000), // -0x1.7d68fb4143000p-3
    f64::from_bits(0x3ff32f5cceffcb24), // 0x1.32f5cceffcb24p+0
    f64::from_bits(0xbfc73cb83c627000), // -0x1.73cb83c627000p-3
    f64::from_bits(0x3ff3187775a10d49), // 0x1.3187775a10d49p+0
    f64::from_bits(0xbfc6a39a9b376000), // -0x1.6a39a9b376000p-3
    f64::from_bits(0x3ff301c8373e3990), // 0x1.301c8373e3990p+0
    f64::from_bits(0xbfc60b3154b7a000), // -0x1.60b3154b7a000p-3
    f64::from_bits(0x3ff2eb4ebb95f841), // 0x1.2eb4ebb95f841p+0
    f64::from_bits(0xbfc5737d76243000), // -0x1.5737d76243000p-3
    f64::from_bits(0x3ff2d50a0219a9d1), // 0x1.2d50a0219a9d1p+0
    f64::from_bits(0xbfc4dc7b8fc23000), // -0x1.4dc7b8fc23000p-3
    f64::from_bits(0x3ff2bef9a8b7fd2a), // 0x1.2bef9a8b7fd2ap+0
    f64::from_bits(0xbfc4462c51d20000), // -0x1.4462c51d20000p-3
    f64::from_bits(0x3ff2a91c7a0c1bab), // 0x1.2a91c7a0c1babp+0
    f64::from_bits(0xbfc3b08abc830000), // -0x1.3b08abc830000p-3
    f64::from_bits(0x3ff293726014b530), // 0x1.293726014b530p+0
    f64::from_bits(0xbfc31b996b490000), // -0x1.31b996b490000p-3
    f64::from_bits(0x3ff27dfa5757a1f5), // 0x1.27dfa5757a1f5p+0
    f64::from_bits(0xbfc2875490a44000), // -0x1.2875490a44000p-3
    f64::from_bits(0x3ff268b39b1d3bbf), // 0x1.268b39b1d3bbfp+0
    f64::from_bits(0xbfc1f3b9f879a000), // -0x1.1f3b9f879a000p-3
    f64::from_bits(0x3ff2539d838ff5bd), // 0x1.2539d838ff5bdp+0
    f64::from_bits(0xbfc160c8252ca000), // -0x1.160c8252ca000p-3
    f64::from_bits(0x3ff23eb7aac9083b), // 0x1.23eb7aac9083bp+0
    f64::from_bits(0xbfc0ce7f57f72000), // -0x1.0ce7f57f72000p-3
    f64::from_bits(0x3ff22a012ba940b6), // 0x1.22a012ba940b6p+0
    f64::from_bits(0xbfc03cdc49fea000), // -0x1.03cdc49fea000p-3
    f64::from_bits(0x3ff2157996cc4132), // 0x1.2157996cc4132p+0
    f64::from_bits(0xbfbf57bdbc4b8000), // -0x1.f57bdbc4b8000p-4
    f64::from_bits(0x3ff201201dd2fc9b), // 0x1.201201dd2fc9bp+0
    f64::from_bits(0xbfbe370896404000), // -0x1.e370896404000p-4
    f64::from_bits(0x3ff1ecf4494d480b), // 0x1.1ecf4494d480bp+0
    f64::from_bits(0xbfbd17983ef94000), // -0x1.d17983ef94000p-4
    f64::from_bits(0x3ff1d8f5528f6569), // 0x1.1d8f5528f6569p+0
    f64::from_bits(0xbfbbf9674ed8a000), // -0x1.bf9674ed8a000p-4
    f64::from_bits(0x3ff1c52311577e7c), // 0x1.1c52311577e7cp+0
    f64::from_bits(0xbfbadc79202f6000), // -0x1.adc79202f6000p-4
    f64::from_bits(0x3ff1b17c74cb26e9), // 0x1.1b17c74cb26e9p+0
    f64::from_bits(0xbfb9c0c3e7288000), // -0x1.9c0c3e7288000p-4
    f64::from_bits(0x3ff19e010c2c1ab6), // 0x1.19e010c2c1ab6p+0
    f64::from_bits(0xbfb8a646b372c000), // -0x1.8a646b372c000p-4
    f64::from_bits(0x3ff18ab07bb670bd), // 0x1.18ab07bb670bdp+0
    f64::from_bits(0xbfb78d01b3ac0000), // -0x1.78d01b3ac0000p-4
    f64::from_bits(0x3ff1778a25efbcb6), // 0x1.1778a25efbcb6p+0
    f64::from_bits(0xbfb674f145380000), // -0x1.674f145380000p-4
    f64::from_bits(0x3ff1648d354c31da), // 0x1.1648d354c31dap+0
    f64::from_bits(0xbfb55e0e6d878000), // -0x1.55e0e6d878000p-4
    f64::from_bits(0x3ff151b990275fdd), // 0x1.151b990275fddp+0
    f64::from_bits(0xbfb4485cdea1e000), // -0x1.4485cdea1e000p-4
    f64::from_bits(0x3ff13f0ea432d24c), // 0x1.13f0ea432d24cp+0
    f64::from_bits(0xbfb333d94d6aa000), // -0x1.333d94d6aa000p-4
    f64::from_bits(0x3ff12c8b7210f9da), // 0x1.12c8b7210f9dap+0
    f64::from_bits(0xbfb22079f8c56000), // -0x1.22079f8c56000p-4
    f64::from_bits(0x3ff11a3028ecb531), // 0x1.11a3028ecb531p+0
    f64::from_bits(0xbfb10e4698622000), // -0x1.10e4698622000p-4
    f64::from_bits(0x3ff107fbda8434af), // 0x1.107fbda8434afp+0
    f64::from_bits(0xbfaffa6c6ad20000), // -0x1.ffa6c6ad20000p-5
    f64::from_bits(0x3ff0f5ee0f4e6bb3), // 0x1.0f5ee0f4e6bb3p+0
    f64::from_bits(0xbfadda8d4a774000), // -0x1.dda8d4a774000p-5
    f64::from_bits(0x3ff0e4065d2a9fce), // 0x1.0e4065d2a9fcep+0
    f64::from_bits(0xbfabbcece4850000), // -0x1.bbcece4850000p-5
    f64::from_bits(0x3ff0d244632ca521), // 0x1.0d244632ca521p+0
    f64::from_bits(0xbfa9a1894012c000), // -0x1.9a1894012c000p-5
    f64::from_bits(0x3ff0c0a77ce2981a), // 0x1.0c0a77ce2981ap+0
    f64::from_bits(0xbfa788583302c000), // -0x1.788583302c000p-5
    f64::from_bits(0x3ff0af2f83c636d1), // 0x1.0af2f83c636d1p+0
    f64::from_bits(0xbfa5715e67d68000), // -0x1.5715e67d68000p-5
    f64::from_bits(0x3ff09ddb98a01339), // 0x1.09ddb98a01339p+0
    f64::from_bits(0xbfa35c8a49658000), // -0x1.35c8a49658000p-5
    f64::from_bits(0x3ff08cabaf52e7df), // 0x1.08cabaf52e7dfp+0
    f64::from_bits(0xbfa149e364154000), // -0x1.149e364154000p-5
    f64::from_bits(0x3ff07b9f2f4e28fb), // 0x1.07b9f2f4e28fbp+0
    f64::from_bits(0xbf9e72c082eb8000), // -0x1.e72c082eb8000p-6
    f64::from_bits(0x3ff06ab58c358f19), // 0x1.06ab58c358f19p+0
    f64::from_bits(0xbf9a55f152528000), // -0x1.a55f152528000p-6
    f64::from_bits(0x3ff059eea5ecf92c), // 0x1.059eea5ecf92cp+0
    f64::from_bits(0xbf963d62cf818000), // -0x1.63d62cf818000p-6
    f64::from_bits(0x3ff04949cdd12c90), // 0x1.04949cdd12c90p+0
    f64::from_bits(0xbf9228fb8caa0000), // -0x1.228fb8caa0000p-6
    f64::from_bits(0x3ff038c6c6f0ada9), // 0x1.038c6c6f0ada9p+0
    f64::from_bits(0xbf8c317b20f90000), // -0x1.c317b20f90000p-7
    f64::from_bits(0x3ff02865137932a9), // 0x1.02865137932a9p+0
    f64::from_bits(0xbf8419355daa0000), // -0x1.419355daa0000p-7
    f64::from_bits(0x3ff0182427ea7348), // 0x1.0182427ea7348p+0
    f64::from_bits(0xbf781203c2ec0000), // -0x1.81203c2ec0000p-8
    f64::from_bits(0x3ff008040614b195), // 0x1.008040614b195p+0
    f64::from_bits(0xbf60040979240000), // -0x1.0040979240000p-9
    f64::from_bits(0x3fefe01ff726fa1a), // 0x1.fe01ff726fa1ap-1
    f64::from_bits(0x3f6feff384900000), // 0x1.feff384900000p-9
    f64::from_bits(0x3fefa11cc261ea74), // 0x1.fa11cc261ea74p-1
    f64::from_bits(0x3f87dc41353d0000), // 0x1.7dc41353d0000p-7
    f64::from_bits(0x3fef6310b081992e), // 0x1.f6310b081992ep-1
    f64::from_bits(0x3f93cea3c4c28000), // 0x1.3cea3c4c28000p-6
    f64::from_bits(0x3fef25f63ceeadcd), // 0x1.f25f63ceeadcdp-1
    f64::from_bits(0x3f9b9fc114890000), // 0x1.b9fc114890000p-6
    f64::from_bits(0x3feee9c8039113e7), // 0x1.ee9c8039113e7p-1
    f64::from_bits(0x3fa1b0d8ce110000), // 0x1.1b0d8ce110000p-5
    f64::from_bits(0x3feeae8078cbb1ab), // 0x1.eae8078cbb1abp-1
    f64::from_bits(0x3fa58a5bd001c000), // 0x1.58a5bd001c000p-5
    f64::from_bits(0x3fee741aa29d0c9b), // 0x1.e741aa29d0c9bp-1
    f64::from_bits(0x3fa95c8340d88000), // 0x1.95c8340d88000p-5
    f64::from_bits(0x3fee3a91830a99b5), // 0x1.e3a91830a99b5p-1
    f64::from_bits(0x3fad276aef578000), // 0x1.d276aef578000p-5
    f64::from_bits(0x3fee01e009609a56), // 0x1.e01e009609a56p-1
    f64::from_bits(0x3fb07598e598c000), // 0x1.07598e598c000p-4
    f64::from_bits(0x3fedca01e577bb98), // 0x1.dca01e577bb98p-1
    f64::from_bits(0x3fb253f5e30d2000), // 0x1.253f5e30d2000p-4
    f64::from_bits(0x3fed92f20b7c9103), // 0x1.d92f20b7c9103p-1
    f64::from_bits(0x3fb42edd8b380000), // 0x1.42edd8b380000p-4
    f64::from_bits(0x3fed5cac66fb5cce), // 0x1.d5cac66fb5ccep-1
    f64::from_bits(0x3fb606598757c000), // 0x1.606598757c000p-4
    f64::from_bits(0x3fed272caa5ede9d), // 0x1.d272caa5ede9dp-1
    f64::from_bits(0x3fb7da76356a0000), // 0x1.7da76356a0000p-4
    f64::from_bits(0x3fecf26e3e6b2ccd), // 0x1.cf26e3e6b2ccdp-1
    f64::from_bits(0x3fb9ab434e1c6000), // 0x1.9ab434e1c6000p-4
    f64::from_bits(0x3fecbe6da2a77902), // 0x1.cbe6da2a77902p-1
    f64::from_bits(0x3fbb78c7bb0d6000), // 0x1.b78c7bb0d6000p-4
    f64::from_bits(0x3fec8b266d37086d), // 0x1.c8b266d37086dp-1
    f64::from_bits(0x3fbd431332e72000), // 0x1.d431332e72000p-4
    f64::from_bits(0x3fec5894bd5d5804), // 0x1.c5894bd5d5804p-1
    f64::from_bits(0x3fbf0a3171de6000), // 0x1.f0a3171de6000p-4
    f64::from_bits(0x3fec26b533bb9f8c), // 0x1.c26b533bb9f8cp-1
    f64::from_bits(0x3fc067152b914000), // 0x1.067152b914000p-3
    f64::from_bits(0x3febf583eeece73f), // 0x1.bf583eeece73fp-1
    f64::from_bits(0x3fc147858292b000), // 0x1.147858292b000p-3
    f64::from_bits(0x3febc4fd75db96c1), // 0x1.bc4fd75db96c1p-1
    f64::from_bits(0x3fc2266ecdca3000), // 0x1.2266ecdca3000p-3
    f64::from_bits(0x3feb951e0c864a28), // 0x1.b951e0c864a28p-1
    f64::from_bits(0x3fc303d7a6c55000), // 0x1.303d7a6c55000p-3
    f64::from_bits(0x3feb65e2c5ef3e2c), // 0x1.b65e2c5ef3e2cp-1
    f64::from_bits(0x3fc3dfc33c331000), // 0x1.3dfc33c331000p-3
    f64::from_bits(0x3feb374867c9888b), // 0x1.b374867c9888bp-1
    f64::from_bits(0x3fc4ba366b7a8000), // 0x1.4ba366b7a8000p-3
    f64::from_bits(0x3feb094b211d304a), // 0x1.b094b211d304ap-1
    f64::from_bits(0x3fc5933928d1f000), // 0x1.5933928d1f000p-3
    f64::from_bits(0x3feadbe885f2ef7e), // 0x1.adbe885f2ef7ep-1
    f64::from_bits(0x3fc66acd2418f000), // 0x1.66acd2418f000p-3
    f64::from_bits(0x3feaaf1d31603da2), // 0x1.aaf1d31603da2p-1
    f64::from_bits(0x3fc740f8ec669000), // 0x1.740f8ec669000p-3
    f64::from_bits(0x3fea82e63fd358a7), // 0x1.a82e63fd358a7p-1
    f64::from_bits(0x3fc815c0f51af000), // 0x1.815c0f51af000p-3
    f64::from_bits(0x3fea5740ef09738b), // 0x1.a5740ef09738bp-1
    f64::from_bits(0x3fc8e92954f68000), // 0x1.8e92954f68000p-3
    f64::from_bits(0x3fea2c2a90ab4b27), // 0x1.a2c2a90ab4b27p-1
    f64::from_bits(0x3fc9bb3602f84000), // 0x1.9bb3602f84000p-3
    f64::from_bits(0x3fea01a01393f2d1), // 0x1.a01a01393f2d1p-1
    f64::from_bits(0x3fca8bed1c2c0000), // 0x1.a8bed1c2c0000p-3
    f64::from_bits(0x3fe9d79f24db3c1b), // 0x1.9d79f24db3c1bp-1
    f64::from_bits(0x3fcb5b515c01d000), // 0x1.b5b515c01d000p-3
    f64::from_bits(0x3fe9ae2505c7b190), // 0x1.9ae2505c7b190p-1
    f64::from_bits(0x3fcc2967ccbcc000), // 0x1.c2967ccbcc000p-3
    f64::from_bits(0x3fe9852ef297ce2f), // 0x1.9852ef297ce2fp-1
    f64::from_bits(0x3fccf635d5486000), // 0x1.cf635d5486000p-3
    f64::from_bits(0x3fe95cbaeea44b75), // 0x1.95cbaeea44b75p-1
    f64::from_bits(0x3fcdc1bd3446c000), // 0x1.dc1bd3446c000p-3
    f64::from_bits(0x3fe934c69de74838), // 0x1.934c69de74838p-1
    f64::from_bits(0x3fce8c01b8cfe000), // 0x1.e8c01b8cfe000p-3
    f64::from_bits(0x3fe90d4f2f6752e6), // 0x1.90d4f2f6752e6p-1
    f64::from_bits(0x3fcf5509c0179000), // 0x1.f5509c0179000p-3
    f64::from_bits(0x3fe8e6528effd79d), // 0x1.8e6528effd79dp-1
    f64::from_bits(0x3fd00e6c121fb800), // 0x1.00e6c121fb800p-2
    f64::from_bits(0x3fe8bfce9fcc007c), // 0x1.8bfce9fcc007cp-1
    f64::from_bits(0x3fd071b80e93d000), // 0x1.071b80e93d000p-2
    f64::from_bits(0x3fe899c0dabec30e), // 0x1.899c0dabec30ep-1
    f64::from_bits(0x3fd0d46b9e867000), // 0x1.0d46b9e867000p-2
    f64::from_bits(0x3fe87427aa2317fb), // 0x1.87427aa2317fbp-1
    f64::from_bits(0x3fd13687334bd000), // 0x1.13687334bd000p-2
    f64::from_bits(0x3fe84f00acb39a08), // 0x1.84f00acb39a08p-1
    f64::from_bits(0x3fd1980d67234800), // 0x1.1980d67234800p-2
    f64::from_bits(0x3fe82a49e8653e55), // 0x1.82a49e8653e55p-1
    f64::from_bits(0x3fd1f8ffe0cc8000), // 0x1.1f8ffe0cc8000p-2
    f64::from_bits(0x3fe8060195f40260), // 0x1.8060195f40260p-1
    f64::from_bits(0x3fd2595fd7636800), // 0x1.2595fd7636800p-2
    f64::from_bits(0x3fe7e22563e0a329), // 0x1.7e22563e0a329p-1
    f64::from_bits(0x3fd2b9300914a800), // 0x1.2b9300914a800p-2
    f64::from_bits(0x3fe7beb377dcb5ad), // 0x1.7beb377dcb5adp-1
    f64::from_bits(0x3fd3187210436000), // 0x1.3187210436000p-2
    f64::from_bits(0x3fe79baa679725c2), // 0x1.79baa679725c2p-1
    f64::from_bits(0x3fd377266dec1800), // 0x1.377266dec1800p-2
    f64::from_bits(0x3fe77907f2170657), // 0x1.77907f2170657p-1
    f64::from_bits(0x3fd3d54ffbaf3000), // 0x1.3d54ffbaf3000p-2
    f64::from_bits(0x3fe756cadbd6130c), // 0x1.756cadbd6130cp-1
    f64::from_bits(0x3fd432eee32fe000), // 0x1.432eee32fe000p-2
];

// ARM optimized-routines math/log2_data.c, N=64, order 7, poly1 order 11
pub static LOG2_POLY: [f64; 6] = [
    f64::from_bits(0xbfe71547652b8339), // -0x1.71547652b8339p-1
    f64::from_bits(0x3fdec709dc3a04be), // 0x1.ec709dc3a04bep-2
    f64::from_bits(0xbfd7154764702ffb), // -0x1.7154764702ffbp-2
    f64::from_bits(0x3fd2776c50034c48), // 0x1.2776c50034c48p-2
    f64::from_bits(0xbfcec7b328ea92bc), // -0x1.ec7b328ea92bcp-3
    f64::from_bits(0x3fca6225e117f92e), // 0x1.a6225e117f92ep-3
];

// ARM optimized-routines math/log2_data.c, N=64, order 7, poly1 order 11
pub static LOG2_POLY1: [f64; 10] = [
    f64::from_bits(0xbfe71547652b82fe), // -0x1.71547652b82fep-1
    f64::from_bits(0x3fdec709dc3a03f7), // 0x1.ec709dc3a03f7p-2
    f64::from_bits(0xbfd71547652b7c3f), // -0x1.71547652b7c3fp-2
    f64::from_bits(0x3fd2776c50f05be4), // 0x1.2776c50f05be4p-2
    f64::from_bits(0xbfcec709dd768fe5), // -0x1.ec709dd768fe5p-3
    f64::from_bits(0x3fca61761ec4e736), // 0x1.a61761ec4e736p-3
    f64::from_bits(0xbfc7153fbc64a79b), // -0x1.7153fbc64a79bp-3
    f64::from_bits(0x3fc484d154f01b4a), // 0x1.484d154f01b4ap-3
    f64::from_bits(0xbfc289e4a72c383c), // -0x1.289e4a72c383cp-3
    f64::from_bits(0x3fc0b32f285aee66), // 0x1.0b32f285aee66p-3
];

// ARM optimized-routines math/log2_data.c, N=64, order 7, poly1 order 11: pairs invc, logc
pub static LOG2_TAB: [f64; 128] = [
    f64::from_bits(0x3ff724286bb1acf8), // 0x1.724286bb1acf8p+0
    f64::from_bits(0xbfe1095feecdb000), // -0x1.1095feecdb000p-1
    f64::from_bits(0x3ff6e1f766d2cca1), // 0x1.6e1f766d2cca1p+0
    f64::from_bits(0xbfe08494bd76d000), // -0x1.08494bd76d000p-1
    f64::from_bits(0x3ff6a13d0e30d48a), // 0x1.6a13d0e30d48ap+0
    f64::from_bits(0xbfe00143aee8f800), // -0x1.00143aee8f800p-1
    f64::from_bits(0x3ff661ec32d06c85), // 0x1.661ec32d06c85p+0
    f64::from_bits(0xbfdefec5360b4000), // -0x1.efec5360b4000p-2
    f64::from_bits(0x3ff623fa951198f8), // 0x1.623fa951198f8p+0
    f64::from_bits(0xbfddfdd91ab7e000), // -0x1.dfdd91ab7e000p-2
    f64::from_bits(0x3ff5e75ba4cf026c), // 0x1.5e75ba4cf026cp+0
    f64::from_bits(0xbfdcffae0cc79000), // -0x1.cffae0cc79000p-2
    f64::from_bits(0x3ff5ac055a214fb8), // 0x1.5ac055a214fb8p+0
    f64::from_bits(0xbfdc043811fda000), // -0x1.c043811fda000p-2
    f64::from_bits(0x3ff571ed0f166e1e), // 0x1.571ed0f166e1ep+0
    f64::from_bits(0xbfdb0b67323ae000), // -0x1.b0b67323ae000p-2
    f64::from_bits(0x3ff53909590bf835), // 0x1.53909590bf835p+0
    f64::from_bits(0xbfda152f5a2db000), // -0x1.a152f5a2db000p-2
    f64::from_bits(0x3ff5014fed61addd), // 0x1.5014fed61adddp+0
    f64::from_bits(0xbfd9217f5af86000), // -0x1.9217f5af86000p-2
    f64::from_bits(0x3ff4cab88e487bd0), // 0x1.4cab88e487bd0p+0
    f64::from_bits(0xbfd8304db0719000), // -0x1.8304db0719000p-2
    f64::from_bits(0x3ff49539b4334fee), // 0x1.49539b4334feep+0
    f64::from_bits(0xbfd74189f9a9e000), // -0x1.74189f9a9e000p-2
    f64::from_bits(0x3ff460cbdfafd569), // 0x1.460cbdfafd569p+0
    f64::from_bits(0xbfd6552bb5199000), // -0x1.6552bb5199000p-2
    f64::from_bits(0x3ff42d664ee4b953), // 0x1.42d664ee4b953p+0
    f64::from_bits(0xbfd56b23a29b1000), // -0x1.56b23a29b1000p-2
    f64::from_bits(0x3ff3fb01111dd8a6), // 0x1.3fb01111dd8a6p+0
    f64::from_bits(0xbfd483650f5fa000), // -0x1.483650f5fa000p-2
    f64::from_bits(0x3ff3c995b70c5836), // 0x1.3c995b70c5836p+0
    f64::from_bits(0xbfd39de937f6a000), // -0x1.39de937f6a000p-2
    f64::from_bits(0x3ff3991c4ab6fd4a), // 0x1.3991c4ab6fd4ap+0
    f64::from_bits(0xbfd2baa1538d6000), // -0x1.2baa1538d6000p-2
    f64::from_bits(0x3ff3698e0ce099b5), // 0x1.3698e0ce099b5p+0
    f64::from_bits(0xbfd1d98340ca4000), // -0x1.1d98340ca4000p-2
    f64::from_bits(0x3ff33ae48213e7b2), // 0x1.33ae48213e7b2p+0
    f64::from_bits(0xbfd0fa853a40e000), // -0x1.0fa853a40e000p-2
    f64::from_bits(0x3ff30d191985bdb1), // 0x1.30d191985bdb1p+0
    f64::from_bits(0xbfd01d9c32e73000), // -0x1.01d9c32e73000p-2
    f64::from_bits(0x3ff2e025cab271d7), // 0x1.2e025cab271d7p+0
    f64::from_bits(0xbfce857da2fa6000), // -0x1.e857da2fa6000p-3
    f64::from_bits(0x3ff2b404cf13cd82), // 0x1.2b404cf13cd82p+0
    f64::from_bits(0xbfccd3c8633d8000), // -0x1.cd3c8633d8000p-3
    f64::from_bits(0x3ff288b02c7ccb50), // 0x1.288b02c7ccb50p+0
    f64::from_bits(0xbfcb26034c14a000), // -0x1.b26034c14a000p-3
    f64::from_bits(0x3ff25e2263944de5), // 0x1.25e2263944de5p+0
    f64::from_bits(0xbfc97c1c2f4fe000), // -0x1.97c1c2f4fe000p-3
    f64::from_bits(0x3ff234563d8615b1), // 0x1.234563d8615b1p+0
    f64::from_bits(0xbfc7d6023f800000), // -0x1.7d6023f800000p-3
    f64::from_bits(0x3ff20b46e33eaf38), // 0x1.20b46e33eaf38p+0
    f64::from_bits(0xbfc633a71a05e000), // -0x1.633a71a05e000p-3
    f64::from_bits(0x3ff1e2eefdcda3dd), // 0x1.1e2eefdcda3ddp+0
    f64::from_bits(0xbfc494f5e9570000), // -0x1.494f5e9570000p-3
    f64::from_bits(0x3ff1bb4a580b3930), // 0x1.1bb4a580b3930p+0
    f64::from_bits(0xbfc2f9e424e0a000), // -0x1.2f9e424e0a000p-3
    f64::from_bits(0x3ff19453847f2200), // 0x1.19453847f2200p+0
    f64::from_bits(0xbfc162595afdc000), // -0x1.162595afdc000p-3
    f64::from_bits(0x3ff16e06c0d5d73c), // 0x1.16e06c0d5d73cp+0
    f64::from_bits(0xbfbf9c9a75bd8000), // -0x1.f9c9a75bd8000p-4
    f64::from_bits(0x3ff1485f47b7e4c2), // 0x1.1485f47b7e4c2p+0
    f64::from_bits(0xbfbc7b575bf9c000), // -0x1.c7b575bf9c000p-4
    f64::from_bits(0x3ff12358ad0085d1), // 0x1.12358ad0085d1p+0
    f64::from_bits(0xbfb960c60ff48000), // -0x1.960c60ff48000p-4
    f64::from_bits(0x3ff0fef00f532227), // 0x1.0fef00f532227p+0
    f64::from_bits(0xbfb64ce247b60000), // -0x1.64ce247b60000p-4
    f64::from_bits(0x3ff0db2077d03a8f), // 0x1.0db2077d03a8fp+0
    f64::from_bits(0xbfb33f78b2014000), // -0x1.33f78b2014000p-4
    f64::from_bits(0x3ff0b7e6d65980d9), // 0x1.0b7e6d65980d9p+0
    f64::from_bits(0xbfb0387d1a42c000), // -0x1.0387d1a42c000p-4
    f64::from_bits(0x3ff0953efe7b408d), // 0x1.0953efe7b408dp+0
    f64::from_bits(0xbfaa6f9208b50000), // -0x1.a6f9208b50000p-5
    f64::from_bits(0x3ff07325cac53b83), // 0x1.07325cac53b83p+0
    f64::from_bits(0xbfa47a954f770000), // -0x1.47a954f770000p-5
    f64::from_bits(0x3ff05197e40d1b5c), // 0x1.05197e40d1b5cp+0
    f64::from_bits(0xbf9d23a8c50c0000), // -0x1.d23a8c50c0000p-6
    f64::from_bits(0x3ff03091c1208ea2), // 0x1.03091c1208ea2p+0
    f64::from_bits(0xbf916a2629780000), // -0x1.16a2629780000p-6
    f64::from_bits(0x3ff0101025b37e21), // 0x1.0101025b37e21p+0
    f64::from_bits(0xbf7720f8d8e80000), // -0x1.720f8d8e80000p-8
    f64::from_bits(0x3fefc07ef9caa76b), // 0x1.fc07ef9caa76bp-1
    f64::from_bits(0x3f86fe53b1500000), // 0x1.6fe53b1500000p-7
    f64::from_bits(0x3fef4465d3f6f184), // 0x1.f4465d3f6f184p-1
    f64::from_bits(0x3fa11ccce10f8000), // 0x1.11ccce10f8000p-5
    f64::from_bits(0x3feecc079f84107f), // 0x1.ecc079f84107fp-1
    f64::from_bits(0x3fac4dfc8c8b8000), // 0x1.c4dfc8c8b8000p-5
    f64::from_bits(0x3fee573a99975ae8), // 0x1.e573a99975ae8p-1
    f64::from_bits(0x3fb3aa321e574000), // 0x1.3aa321e574000p-4
    f64::from_bits(0x3fede5d6f0bd3de6), // 0x1.de5d6f0bd3de6p-1
    f64::from_bits(0x3fb918a0d08b8000), // 0x1.918a0d08b8000p-4
    f64::from_bits(0x3fed77b681ff38b3), // 0x1.d77b681ff38b3p-1
    f64::from_bits(0x3fbe72e9da044000), // 0x1.e72e9da044000p-4
    f64::from_bits(0x3fed0cb5724de943), // 0x1.d0cb5724de943p-1
    f64::from_bits(0x3fc1dcd2507f6000), // 0x1.1dcd2507f6000p-3
    f64::from_bits(0x3feca4b2dc0e7563), // 0x1.ca4b2dc0e7563p-1
    f64::from_bits(0x3fc476ab03dea000), // 0x1.476ab03dea000p-3
    f64::from_bits(0x3fec3f8ee8d6cb51), // 0x1.c3f8ee8d6cb51p-1
    f64::from_bits(0x3fc7074377e22000), // 0x1.7074377e22000p-3
    f64::from_bits(0x3febdd2b4f020c4c), // 0x1.bdd2b4f020c4cp-1
    f64::from_bits(0x3fc98ede8ba94000), // 0x1.98ede8ba94000p-3
    f64::from_bits(0x3feb7d6c006015ca), // 0x1.b7d6c006015cap-1
    f64::from_bits(0x3fcc0db86ad2e000), // 0x1.c0db86ad2e000p-3
    f64::from_bits(0x3feb20366e2e338f), // 0x1.b20366e2e338fp-1
    f64::from_bits(0x3fce840aafcee000), // 0x1.e840aafcee000p-3
    f64::from_bits(0x3feac57026295039), // 0x1.ac57026295039p-1
    f64::from_bits(0x3fd0790ab4678000), // 0x1.0790ab4678000p-2
    f64::from_bits(0x3fea6d01bc2731dd), // 0x1.a6d01bc2731ddp-1
    f64::from_bits(0x3fd1ac056801c000), // 0x1.1ac056801c000p-2
    f64::from_bits(0x3fea16d3bc3ff18b), // 0x1.a16d3bc3ff18bp-1
    f64::from_bits(0x3fd2db11d4fee000), // 0x1.2db11d4fee000p-2
    f64::from_bits(0x3fe9c2d14967fead), // 0x1.9c2d14967feadp-1
    f64::from_bits(0x3fd406464ec58000), // 0x1.406464ec58000p-2
    f64::from_bits(0x3fe970e4f47c9902), // 0x1.970e4f47c9902p-1
    f64::from_bits(0x3fd52dbe093af000), // 0x1.52dbe093af000p-2
    f64::from_bits(0x3fe920fb3982bcf2), // 0x1.920fb3982bcf2p-1
    f64::from_bits(0x3fd651902050d000), // 0x1.651902050d000p-2
    f64::from_bits(0x3fe8d30187f759f1), // 0x1.8d30187f759f1p-1
    f64::from_bits(0x3fd771d2cdeaf000), // 0x1.771d2cdeaf000p-2
    f64::from_bits(0x3fe886e5ebb9f66d), // 0x1.886e5ebb9f66dp-1
    f64::from_bits(0x3fd88e9c857d9000), // 0x1.88e9c857d9000p-2
    f64::from_bits(0x3fe83c97b658b994), // 0x1.83c97b658b994p-1
    f64::from_bits(0x3fd9a80155e16000), // 0x1.9a80155e16000p-2
    f64::from_bits(0x3fe7f405ffc61022), // 0x1.7f405ffc61022p-1
    f64::from_bits(0x3fdabe186ed3d000), // 0x1.abe186ed3d000p-2
    f64::from_bits(0x3fe7ad22181415ca), // 0x1.7ad22181415cap-1
    f64::from_bits(0x3fdbd0f2aea0e000), // 0x1.bd0f2aea0e000p-2
    f64::from_bits(0x3fe767dcf99eff8c), // 0x1.767dcf99eff8cp-1
    f64::from_bits(0x3fdce0a43dbf4000), // 0x1.ce0a43dbf4000p-2
];

// ARM optimized-routines math/pow_log_data.c, N=128, order 8
pub static POW_LOG_POLY: [f64; 7] = [
    f64::from_bits(0xbfe0000000000000), // -0x1.0000000000000p-1
    f64::from_bits(0xbfe5555555555560), // -0x1.5555555555560p-1
    f64::from_bits(0x3fe0000000000006), // 0x1.0000000000006p-1
    f64::from_bits(0x3fe999999959554e), // 0x1.999999959554ep-1
    f64::from_bits(0xbfe555555529a47a), // -0x1.555555529a47ap-1
    f64::from_bits(0xbff2495b9b4845e9), // -0x1.2495b9b4845e9p+0
    f64::from_bits(0x3ff0002b8b263fc3), // 0x1.0002b8b263fc3p+0
];

// ARM optimized-routines math/pow_log_data.c, N=128, order 8: quadruples invc, pad, logc, logctail
pub static POW_LOG_TAB: [f64; 512] = [
    f64::from_bits(0x3ff6a00000000000), // 0x1.6a00000000000p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0xbfd62c82f2b9c800), // -0x1.62c82f2b9c800p-2
    f64::from_bits(0x3cfab42428375680), // 0x1.ab42428375680p-48
    f64::from_bits(0x3ff6800000000000), // 0x1.6800000000000p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0xbfd5d1bdbf580800), // -0x1.5d1bdbf580800p-2
    f64::from_bits(0xbd1ca508d8e0f720), // -0x1.ca508d8e0f720p-46
    f64::from_bits(0x3ff6600000000000), // 0x1.6600000000000p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0xbfd5767717455800), // -0x1.5767717455800p-2
    f64::from_bits(0xbd2362a4d5b6506d), // -0x1.362a4d5b6506dp-45
    f64::from_bits(0x3ff6400000000000), // 0x1.6400000000000p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0xbfd51aad872df800), // -0x1.51aad872df800p-2
    f64::from_bits(0xbce684e49eb067d5), // -0x1.684e49eb067d5p-49
    f64::from_bits(0x3ff6200000000000), // 0x1.6200000000000p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0xbfd4be5f95777800), // -0x1.4be5f95777800p-2
    f64::from_bits(0xbd041b6993293ee0), // -0x1.41b6993293ee0p-47
    f64::from_bits(0x3ff6000000000000), // 0x1.6000000000000p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0xbfd4618bc21c6000), // -0x1.4618bc21c6000p-2
    f64::from_bits(0x3d13d82f484c84cc), // 0x1.3d82f484c84ccp-46
    f64::from_bits(0x3ff5e00000000000), // 0x1.5e00000000000p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0xbfd404308686a800), // -0x1.404308686a800p-2
    f64::from_bits(0x3cdc42f3ed820b3a), // 0x1.c42f3ed820b3ap-50
    f64::from_bits(0x3ff5c00000000000), // 0x1.5c00000000000p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0xbfd3a64c55694800), // -0x1.3a64c55694800p-2
    f64::from_bits(0x3d20b1c686519460), // 0x1.0b1c686519460p-45
    f64::from_bits(0x3ff5a00000000000), // 0x1.5a00000000000p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0xbfd347dd9a988000), // -0x1.347dd9a988000p-2
    f64::from_bits(0x3d25594dd4c58092), // 0x1.5594dd4c58092p-45
    f64::from_bits(0x3ff5800000000000), // 0x1.5800000000000p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0xbfd2e8e2bae12000), // -0x1.2e8e2bae12000p-2
    f64::from_bits(0x3d267b1e99b72bd8), // 0x1.67b1e99b72bd8p-45
    f64::from_bits(0x3ff5600000000000), // 0x1.5600000000000p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0xbfd2895a13de8800), // -0x1.2895a13de8800p-2
    f64::from_bits(0x3d15ca14b6cfb03f), // 0x1.5ca14b6cfb03fp-46
    f64::from_bits(0x3ff5600000000000), // 0x1.5600000000000p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0xbfd2895a13de8800), // -0x1.2895a13de8800p-2
    f64::from_bits(0x3d15ca14b6cfb03f), // 0x1.5ca14b6cfb03fp-46
    f64::from_bits(0x3ff5400000000000), // 0x1.5400000000000p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0xbfd22941fbcf7800), // -0x1.22941fbcf7800p-2
    f64::from_bits(0xbd165a242853da76), // -0x1.65a242853da76p-46
    f64::from_bits(0x3ff5200000000000), // 0x1.5200000000000p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0xbfd1c898c1699800), // -0x1.1c898c1699800p-2
    f64::from_bits(0xbd1fafbc68e75404), // -0x1.fafbc68e75404p-46
    f64::from_bits(0x3ff5000000000000), // 0x1.5000000000000p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0xbfd1675cababa800), // -0x1.1675cababa800p-2
    f64::from_bits(0x3d1f1fc63382a8f0), // 0x1.f1fc63382a8f0p-46
    f64::from_bits(0x3ff4e00000000000), // 0x1.4e00000000000p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0xbfd1058bf9ae4800), // -0x1.1058bf9ae4800p-2
    f64::from_bits(0xbd26a8c4fd055a66), // -0x1.6a8c4fd055a66p-45
    f64::from_bits(0x3ff4c00000000000), // 0x1.4c00000000000p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0xbfd0a324e2739000), // -0x1.0a324e2739000p-2
    f64::from_bits(0xbd0c6bee7ef4030e), // -0x1.c6bee7ef4030ep-47
    f64::from_bits(0x3ff4a00000000000), // 0x1.4a00000000000p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0xbfd0402594b4d000), // -0x1.0402594b4d000p-2
    f64::from_bits(0xbcf036b89ef42d7f), // -0x1.036b89ef42d7fp-48
    f64::from_bits(0x3ff4a00000000000), // 0x1.4a00000000000p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0xbfd0402594b4d000), // -0x1.0402594b4d000p-2
    f64::from_bits(0xbcf036b89ef42d7f), // -0x1.036b89ef42d7fp-48
    f64::from_bits(0x3ff4800000000000), // 0x1.4800000000000p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0xbfcfb9186d5e4000), // -0x1.fb9186d5e4000p-3
    f64::from_bits(0x3d0d572aab993c87), // 0x1.d572aab993c87p-47
    f64::from_bits(0x3ff4600000000000), // 0x1.4600000000000p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0xbfcef0adcbdc6000), // -0x1.ef0adcbdc6000p-3
    f64::from_bits(0x3d2b26b79c86af24), // 0x1.b26b79c86af24p-45
    f64::from_bits(0x3ff4400000000000), // 0x1.4400000000000p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0xbfce27076e2af000), // -0x1.e27076e2af000p-3
    f64::from_bits(0xbd172f4f543fff10), // -0x1.72f4f543fff10p-46
    f64::from_bits(0x3ff4200000000000), // 0x1.4200000000000p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0xbfcd5c216b4fc000), // -0x1.d5c216b4fc000p-3
    f64::from_bits(0x3d21ba91bbca681b), // 0x1.1ba91bbca681bp-45
    f64::from_bits(0x3ff4000000000000), // 0x1.4000000000000p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0xbfcc8ff7c79aa000), // -0x1.c8ff7c79aa000p-3
    f64::from_bits(0x3d27794f689f8434), // 0x1.7794f689f8434p-45
    f64::from_bits(0x3ff4000000000000), // 0x1.4000000000000p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0xbfcc8ff7c79aa000), // -0x1.c8ff7c79aa000p-3
    f64::from_bits(0x3d27794f689f8434), // 0x1.7794f689f8434p-45
    f64::from_bits(0x3ff3e00000000000), // 0x1.3e00000000000p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0xbfcbc286742d9000), // -0x1.bc286742d9000p-3
    f64::from_bits(0x3d194eb0318bb78f), // 0x1.94eb0318bb78fp-46
    f64::from_bits(0x3ff3c00000000000), // 0x1.3c00000000000p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0xbfcaf3c94e80c000), // -0x1.af3c94e80c000p-3
    f64::from_bits(0x3cba4e633fcd9066), // 0x1.a4e633fcd9066p-52
    f64::from_bits(0x3ff3a00000000000), // 0x1.3a00000000000p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0xbfca23bc1fe2b000), // -0x1.a23bc1fe2b000p-3
    f64::from_bits(0xbd258c64dc46c1ea), // -0x1.58c64dc46c1eap-45
    f64::from_bits(0x3ff3a00000000000), // 0x1.3a00000000000p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0xbfca23bc1fe2b000), // -0x1.a23bc1fe2b000p-3
    f64::from_bits(0xbd258c64dc46c1ea), // -0x1.58c64dc46c1eap-45
    f64::from_bits(0x3ff3800000000000), // 0x1.3800000000000p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0xbfc9525a9cf45000), // -0x1.9525a9cf45000p-3
    f64::from_bits(0xbd2ad1d904c1d4e3), // -0x1.ad1d904c1d4e3p-45
    f64::from_bits(0x3ff3600000000000), // 0x1.3600000000000p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0xbfc87fa06520d000), // -0x1.87fa06520d000p-3
    f64::from_bits(0x3d2bbdbf7fdbfa09), // 0x1.bbdbf7fdbfa09p-45
    f64::from_bits(0x3ff3400000000000), // 0x1.3400000000000p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0xbfc7ab890210e000), // -0x1.7ab890210e000p-3
    f64::from_bits(0x3d2bdb9072534a58), // 0x1.bdb9072534a58p-45
    f64::from_bits(0x3ff3400000000000), // 0x1.3400000000000p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0xbfc7ab890210e000), // -0x1.7ab890210e000p-3
    f64::from_bits(0x3d2bdb9072534a58), // 0x1.bdb9072534a58p-45
    f64::from_bits(0x3ff3200000000000), // 0x1.3200000000000p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0xbfc6d60fe719d000), // -0x1.6d60fe719d000p-3
    f64::from_bits(0xbd10e46aa3b2e266), // -0x1.0e46aa3b2e266p-46
    f64::from_bits(0x3ff3000000000000), // 0x1.3000000000000p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0xbfc5ff3070a79000), // -0x1.5ff3070a79000p-3
    f64::from_bits(0xbd1e9e439f105039), // -0x1.e9e439f105039p-46
    f64::from_bits(0x3ff3000000000000), // 0x1.3000000000000p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0xbfc5ff3070a79000), // -0x1.5ff3070a79000p-3
    f64::from_bits(0xbd1e9e439f105039), // -0x1.e9e439f105039p-46
    f64::from_bits(0x3ff2e00000000000), // 0x1.2e00000000000p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0xbfc526e5e3a1b000), // -0x1.526e5e3a1b000p-3
    f64::from_bits(0xbd20de8b90075b8f), // -0x1.0de8b90075b8fp-45
    f64::from_bits(0x3ff2c00000000000), // 0x1.2c00000000000p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0xbfc44d2b6ccb8000), // -0x1.44d2b6ccb8000p-3
    f64::from_bits(0x3d170cc16135783c), // 0x1.70cc16135783cp-46
    f64::from_bits(0x3ff2c00000000000), // 0x1.2c00000000000p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0xbfc44d2b6ccb8000), // -0x1.44d2b6ccb8000p-3
    f64::from_bits(0x3d170cc16135783c), // 0x1.70cc16135783cp-46
    f64::from_bits(0x3ff2a00000000000), // 0x1.2a00000000000p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0xbfc371fc201e9000), // -0x1.371fc201e9000p-3
    f64::from_bits(0x3cf178864d27543a), // 0x1.178864d27543ap-48
    f64::from_bits(0x3ff2800000000000), // 0x1.2800000000000p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0xbfc29552f81ff000), // -0x1.29552f81ff000p-3
    f64::from_bits(0xbd248d301771c408), // -0x1.48d301771c408p-45
    f64::from_bits(0x3ff2600000000000), // 0x1.2600000000000p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0xbfc1b72ad52f6000), // -0x1.1b72ad52f6000p-3
    f64::from_bits(0xbd2e80a41811a396), // -0x1.e80a41811a396p-45
    f64::from_bits(0x3ff2600000000000), // 0x1.2600000000000p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0xbfc1b72ad52f6000), // -0x1.1b72ad52f6000p-3
    f64::from_bits(0xbd2e80a41811a396), // -0x1.e80a41811a396p-45
    f64::from_bits(0x3ff2400000000000), // 0x1.2400000000000p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0xbfc0d77e7cd09000), // -0x1.0d77e7cd09000p-3
    f64::from_bits(0x3d0a699688e85bf4), // 0x1.a699688e85bf4p-47
    f64::from_bits(0x3ff2400000000000), // 0x1.2400000000000p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0xbfc0d77e7cd09000), // -0x1.0d77e7cd09000p-3
    f64::from_bits(0x3d0a699688e85bf4), // 0x1.a699688e85bf4p-47
    f64::from_bits(0x3ff2200000000000), // 0x1.2200000000000p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0xbfbfec9131dbe000), // -0x1.fec9131dbe000p-4
    f64::from_bits(0xbd2575545ca333f2), // -0x1.575545ca333f2p-45
    f64::from_bits(0x3ff2000000000000), // 0x1.2000000000000p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0xbfbe27076e2b0000), // -0x1.e27076e2b0000p-4
    f64::from_bits(0x3d2a342c2af0003c), // 0x1.a342c2af0003cp-45
    f64::from_bits(0x3ff2000000000000), // 0x1.2000000000000p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0xbfbe27076e2b0000), // -0x1.e27076e2b0000p-4
    f64::from_bits(0x3d2a342c2af0003c), // 0x1.a342c2af0003cp-45
    f64::from_bits(0x3ff1e00000000000), // 0x1.1e00000000000p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0xbfbc5e548f5bc000), // -0x1.c5e548f5bc000p-4
    f64::from_bits(0xbd1d0c57585fbe06), // -0x1.d0c57585fbe06p-46
    f64::from_bits(0x3ff1c00000000000), // 0x1.1c00000000000p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0xbfba926d3a4ae000), // -0x1.a926d3a4ae000p-4
    f64::from_bits(0x3d253935e85baac8), // 0x1.53935e85baac8p-45
    f64::from_bits(0x3ff1c00000000000), // 0x1.1c00000000000p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0xbfba926d3a4ae000), // -0x1.a926d3a4ae000p-4
    f64::from_bits(0x3d253935e85baac8), // 0x1.53935e85baac8p-45
    f64::from_bits(0x3ff1a00000000000), // 0x1.1a00000000000p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0xbfb8c345d631a000), // -0x1.8c345d631a000p-4
    f64::from_bits(0x3d137c294d2f5668), // 0x1.37c294d2f5668p-46
    f64::from_bits(0x3ff1a00000000000), // 0x1.1a00000000000p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0xbfb8c345d631a000), // -0x1.8c345d631a000p-4
    f64::from_bits(0x3d137c294d2f5668), // 0x1.37c294d2f5668p-46
    f64::from_bits(0x3ff1800000000000), // 0x1.1800000000000p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0xbfb6f0d28ae56000), // -0x1.6f0d28ae56000p-4
    f64::from_bits(0xbd269737c93373da), // -0x1.69737c93373dap-45
    f64::from_bits(0x3ff1600000000000), // 0x1.1600000000000p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0xbfb51b073f062000), // -0x1.51b073f062000p-4
    f64::from_bits(0x3d1f025b61c65e57), // 0x1.f025b61c65e57p-46
    f64::from_bits(0x3ff1600000000000), // 0x1.1600000000000p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0xbfb51b073f062000), // -0x1.51b073f062000p-4
    f64::from_bits(0x3d1f025b61c65e57), // 0x1.f025b61c65e57p-46
    f64::from_bits(0x3ff1400000000000), // 0x1.1400000000000p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0xbfb341d7961be000), // -0x1.341d7961be000p-4
    f64::from_bits(0x3d2c5edaccf913df), // 0x1.c5edaccf913dfp-45
    f64::from_bits(0x3ff1400000000000), // 0x1.1400000000000p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0xbfb341d7961be000), // -0x1.341d7961be000p-4
    f64::from_bits(0x3d2c5edaccf913df), // 0x1.c5edaccf913dfp-45
    f64::from_bits(0x3ff1200000000000), // 0x1.1200000000000p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0xbfb16536eea38000), // -0x1.16536eea38000p-4
    f64::from_bits(0x3d147c5e768fa309), // 0x1.47c5e768fa309p-46
    f64::from_bits(0x3ff1000000000000), // 0x1.1000000000000p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0xbfaf0a30c0118000), // -0x1.f0a30c0118000p-5
    f64::from_bits(0x3d2d599e83368e91), // 0x1.d599e83368e91p-45
    f64::from_bits(0x3ff1000000000000), // 0x1.1000000000000p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0xbfaf0a30c0118000), // -0x1.f0a30c0118000p-5
    f64::from_bits(0x3d2d599e83368e91), // 0x1.d599e83368e91p-45
    f64::from_bits(0x3ff0e00000000000), // 0x1.0e00000000000p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0xbfab42dd71198000), // -0x1.b42dd71198000p-5
    f64::from_bits(0x3d1c827ae5d6704c), // 0x1.c827ae5d6704cp-46
    f64::from_bits(0x3ff0e00000000000), // 0x1.0e00000000000p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0xbfab42dd71198000), // -0x1.b42dd71198000p-5
    f64::from_bits(0x3d1c827ae5d6704c), // 0x1.c827ae5d6704cp-46
    f64::from_bits(0x3ff0c00000000000), // 0x1.0c00000000000p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0xbfa77458f632c000), // -0x1.77458f632c000p-5
    f64::from_bits(0xbd2cfc4634f2a1ee), // -0x1.cfc4634f2a1eep-45
    f64::from_bits(0x3ff0c00000000000), // 0x1.0c00000000000p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0xbfa77458f632c000), // -0x1.77458f632c000p-5
    f64::from_bits(0xbd2cfc4634f2a1ee), // -0x1.cfc4634f2a1eep-45
    f64::from_bits(0x3ff0a00000000000), // 0x1.0a00000000000p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0xbfa39e87b9fec000), // -0x1.39e87b9fec000p-5
    f64::from_bits(0x3cf502b7f526feaa), // 0x1.502b7f526feaap-48
    f64::from_bits(0x3ff0a00000000000), // 0x1.0a00000000000p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0xbfa39e87b9fec000), // -0x1.39e87b9fec000p-5
    f64::from_bits(0x3cf502b7f526feaa), // 0x1.502b7f526feaap-48
    f64::from_bits(0x3ff0800000000000), // 0x1.0800000000000p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0xbf9f829b0e780000), // -0x1.f829b0e780000p-6
    f64::from_bits(0xbd2980267c7e09e4), // -0x1.980267c7e09e4p-45
    f64::from_bits(0x3ff0800000000000), // 0x1.0800000000000p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0xbf9f829b0e780000), // -0x1.f829b0e780000p-6
    f64::from_bits(0xbd2980267c7e09e4), // -0x1.980267c7e09e4p-45
    f64::from_bits(0x3ff0600000000000), // 0x1.0600000000000p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0xbf97b91b07d58000), // -0x1.7b91b07d58000p-6
    f64::from_bits(0xbd288d5493faa639), // -0x1.88d5493faa639p-45
    f64::from_bits(0x3ff0400000000000), // 0x1.0400000000000p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0xbf8fc0a8b0fc0000), // -0x1.fc0a8b0fc0000p-7
    f64::from_bits(0xbcdf1e7cf6d3a69c), // -0x1.f1e7cf6d3a69cp-50
    f64::from_bits(0x3ff0400000000000), // 0x1.0400000000000p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0xbf8fc0a8b0fc0000), // -0x1.fc0a8b0fc0000p-7
    f64::from_bits(0xbcdf1e7cf6d3a69c), // -0x1.f1e7cf6d3a69cp-50
    f64::from_bits(0x3ff0200000000000), // 0x1.0200000000000p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0xbf7fe02a6b100000), // -0x1.fe02a6b100000p-8
    f64::from_bits(0xbd19e23f0dda40e4), // -0x1.9e23f0dda40e4p-46
    f64::from_bits(0x3ff0200000000000), // 0x1.0200000000000p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0xbf7fe02a6b100000), // -0x1.fe02a6b100000p-8
    f64::from_bits(0xbd19e23f0dda40e4), // -0x1.9e23f0dda40e4p-46
    f64::from_bits(0x3ff0000000000000), // 0x1.0000000000000p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0x3ff0000000000000), // 0x1.0000000000000p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0x3fefc00000000000), // 0x1.fc00000000000p-1
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0x3f80101575890000), // 0x1.0101575890000p-7
    f64::from_bits(0xbd10c76b999d2be8), // -0x1.0c76b999d2be8p-46
    f64::from_bits(0x3fef800000000000), // 0x1.f800000000000p-1
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0x3f90205658938000), // 0x1.0205658938000p-6
    f64::from_bits(0xbd23dc5b06e2f7d2), // -0x1.3dc5b06e2f7d2p-45
    f64::from_bits(0x3fef400000000000), // 0x1.f400000000000p-1
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0x3f98492528c90000), // 0x1.8492528c90000p-6
    f64::from_bits(0xbd2aa0ba325a0c34), // -0x1.aa0ba325a0c34p-45
    f64::from_bits(0x3fef000000000000), // 0x1.f000000000000p-1
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0x3fa0415d89e74000), // 0x1.0415d89e74000p-5
    f64::from_bits(0x3d0111c05cf1d753), // 0x1.111c05cf1d753p-47
    f64::from_bits(0x3feec00000000000), // 0x1.ec00000000000p-1
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0x3fa466aed42e0000), // 0x1.466aed42e0000p-5
    f64::from_bits(0xbd2c167375bdfd28), // -0x1.c167375bdfd28p-45
    f64::from_bits(0x3fee800000000000), // 0x1.e800000000000p-1
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0x3fa894aa149fc000), // 0x1.894aa149fc000p-5
    f64::from_bits(0xbd197995d05a267d), // -0x1.97995d05a267dp-46
    f64::from_bits(0x3fee400000000000), // 0x1.e400000000000p-1
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0x3faccb73cdddc000), // 0x1.ccb73cdddc000p-5
    f64::from_bits(0xbd1a68f247d82807), // -0x1.a68f247d82807p-46
    f64::from_bits(0x3fee200000000000), // 0x1.e200000000000p-1
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0x3faeea31c006c000), // 0x1.eea31c006c000p-5
    f64::from_bits(0xbd0e113e4fc93b7b), // -0x1.e113e4fc93b7bp-47
    f64::from_bits(0x3fede00000000000), // 0x1.de00000000000p-1
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0x3fb1973bd1466000), // 0x1.1973bd1466000p-4
    f64::from_bits(0xbd25325d560d9e9b), // -0x1.5325d560d9e9bp-45
    f64::from_bits(0x3feda00000000000), // 0x1.da00000000000p-1
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0x3fb3bdf5a7d1e000), // 0x1.3bdf5a7d1e000p-4
    f64::from_bits(0x3d2cc85ea5db4ed7), // 0x1.cc85ea5db4ed7p-45
    f64::from_bits(0x3fed600000000000), // 0x1.d600000000000p-1
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0x3fb5e95a4d97a000), // 0x1.5e95a4d97a000p-4
    f64::from_bits(0xbd2c69063c5d1d1e), // -0x1.c69063c5d1d1ep-45
    f64::from_bits(0x3fed400000000000), // 0x1.d400000000000p-1
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0x3fb700d30aeac000), // 0x1.700d30aeac000p-4
    f64::from_bits(0x3cec1e8da99ded32), // 0x1.c1e8da99ded32p-49
    f64::from_bits(0x3fed000000000000), // 0x1.d000000000000p-1
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0x3fb9335e5d594000), // 0x1.9335e5d594000p-4
    f64::from_bits(0x3d23115c3abd47da), // 0x1.3115c3abd47dap-45
    f64::from_bits(0x3fecc00000000000), // 0x1.cc00000000000p-1
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0x3fbb6ac88dad6000), // 0x1.b6ac88dad6000p-4
    f64::from_bits(0xbd1390802bf768e5), // -0x1.390802bf768e5p-46
    f64::from_bits(0x3feca00000000000), // 0x1.ca00000000000p-1
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0x3fbc885801bc4000), // 0x1.c885801bc4000p-4
    f64::from_bits(0x3d2646d1c65aacd3), // 0x1.646d1c65aacd3p-45
    f64::from_bits(0x3fec600000000000), // 0x1.c600000000000p-1
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0x3fbec739830a2000), // 0x1.ec739830a2000p-4
    f64::from_bits(0xbd2dc068afe645e0), // -0x1.dc068afe645e0p-45
    f64::from_bits(0x3fec400000000000), // 0x1.c400000000000p-1
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0x3fbfe89139dbe000), // 0x1.fe89139dbe000p-4
    f64::from_bits(0xbd2534d64fa10afd), // -0x1.534d64fa10afdp-45
    f64::from_bits(0x3fec000000000000), // 0x1.c000000000000p-1
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0x3fc1178e8227e000), // 0x1.1178e8227e000p-3
    f64::from_bits(0x3d21ef78ce2d07f2), // 0x1.1ef78ce2d07f2p-45
    f64::from_bits(0x3febe00000000000), // 0x1.be00000000000p-1
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0x3fc1aa2b7e23f000), // 0x1.1aa2b7e23f000p-3
    f64::from_bits(0x3d2ca78e44389934), // 0x1.ca78e44389934p-45
    f64::from_bits(0x3feba00000000000), // 0x1.ba00000000000p-1
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0x3fc2d1610c868000), // 0x1.2d1610c868000p-3
    f64::from_bits(0x3d039d6ccb81b4a1), // 0x1.39d6ccb81b4a1p-47
    f64::from_bits(0x3feb800000000000), // 0x1.b800000000000p-1
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0x3fc365fcb0159000), // 0x1.365fcb0159000p-3
    f64::from_bits(0x3cc62fa8234b7289), // 0x1.62fa8234b7289p-51
    f64::from_bits(0x3feb400000000000), // 0x1.b400000000000p-1
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0x3fc4913d8333b000), // 0x1.4913d8333b000p-3
    f64::from_bits(0x3d25837954fdb678), // 0x1.5837954fdb678p-45
    f64::from_bits(0x3feb200000000000), // 0x1.b200000000000p-1
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0x3fc527e5e4a1b000), // 0x1.527e5e4a1b000p-3
    f64::from_bits(0x3d2633e8e5697dc7), // 0x1.633e8e5697dc7p-45
    f64::from_bits(0x3feae00000000000), // 0x1.ae00000000000p-1
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0x3fc6574ebe8c1000), // 0x1.6574ebe8c1000p-3
    f64::from_bits(0x3d19cf8b2c3c2e78), // 0x1.9cf8b2c3c2e78p-46
    f64::from_bits(0x3feac00000000000), // 0x1.ac00000000000p-1
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0x3fc6f0128b757000), // 0x1.6f0128b757000p-3
    f64::from_bits(0xbd25118de59c21e1), // -0x1.5118de59c21e1p-45
    f64::from_bits(0x3feaa00000000000), // 0x1.aa00000000000p-1
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0x3fc7898d85445000), // 0x1.7898d85445000p-3
    f64::from_bits(0xbd1c661070914305), // -0x1.c661070914305p-46
    f64::from_bits(0x3fea600000000000), // 0x1.a600000000000p-1
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0x3fc8beafeb390000), // 0x1.8beafeb390000p-3
    f64::from_bits(0xbd073d54aae92cd1), // -0x1.73d54aae92cd1p-47
    f64::from_bits(0x3fea400000000000), // 0x1.a400000000000p-1
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0x3fc95a5adcf70000), // 0x1.95a5adcf70000p-3
    f64::from_bits(0x3d07f22858a0ff6f), // 0x1.7f22858a0ff6fp-47
    f64::from_bits(0x3fea000000000000), // 0x1.a000000000000p-1
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0x3fca93ed3c8ae000), // 0x1.a93ed3c8ae000p-3
    f64::from_bits(0xbd28724350562169), // -0x1.8724350562169p-45
    f64::from_bits(0x3fe9e00000000000), // 0x1.9e00000000000p-1
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0x3fcb31d8575bd000), // 0x1.b31d8575bd000p-3
    f64::from_bits(0xbd0c358d4eace1aa), // -0x1.c358d4eace1aap-47
    f64::from_bits(0x3fe9c00000000000), // 0x1.9c00000000000p-1
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0x3fcbd087383be000), // 0x1.bd087383be000p-3
    f64::from_bits(0xbd2d4bc4595412b6), // -0x1.d4bc4595412b6p-45
    f64::from_bits(0x3fe9a00000000000), // 0x1.9a00000000000p-1
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0x3fcc6ffbc6f01000), // 0x1.c6ffbc6f01000p-3
    f64::from_bits(0xbcf1ec72c5962bd2), // -0x1.1ec72c5962bd2p-48
    f64::from_bits(0x3fe9600000000000), // 0x1.9600000000000p-1
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0x3fcdb13db0d49000), // 0x1.db13db0d49000p-3
    f64::from_bits(0xbd2aff2af715b035), // -0x1.aff2af715b035p-45
    f64::from_bits(0x3fe9400000000000), // 0x1.9400000000000p-1
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0x3fce530effe71000), // 0x1.e530effe71000p-3
    f64::from_bits(0x3cc212276041f430), // 0x1.212276041f430p-51
    f64::from_bits(0x3fe9200000000000), // 0x1.9200000000000p-1
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0x3fcef5ade4dd0000), // 0x1.ef5ade4dd0000p-3
    f64::from_bits(0xbcca211565bb8e11), // -0x1.a211565bb8e11p-51
    f64::from_bits(0x3fe9000000000000), // 0x1.9000000000000p-1
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0x3fcf991c6cb3b000), // 0x1.f991c6cb3b000p-3
    f64::from_bits(0x3d1bcbecca0cdf30), // 0x1.bcbecca0cdf30p-46
    f64::from_bits(0x3fe8c00000000000), // 0x1.8c00000000000p-1
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0x3fd07138604d5800), // 0x1.07138604d5800p-2
    f64::from_bits(0x3cf89cdb16ed4e91), // 0x1.89cdb16ed4e91p-48
    f64::from_bits(0x3fe8a00000000000), // 0x1.8a00000000000p-1
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0x3fd0c42d67616000), // 0x1.0c42d67616000p-2
    f64::from_bits(0x3d27188b163ceae9), // 0x1.7188b163ceae9p-45
    f64::from_bits(0x3fe8800000000000), // 0x1.8800000000000p-1
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0x3fd1178e8227e800), // 0x1.1178e8227e800p-2
    f64::from_bits(0xbd2c210e63a5f01c), // -0x1.c210e63a5f01cp-45
    f64::from_bits(0x3fe8600000000000), // 0x1.8600000000000p-1
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0x3fd16b5ccbacf800), // 0x1.16b5ccbacf800p-2
    f64::from_bits(0x3d2b9acdf7a51681), // 0x1.b9acdf7a51681p-45
    f64::from_bits(0x3fe8400000000000), // 0x1.8400000000000p-1
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0x3fd1bf99635a6800), // 0x1.1bf99635a6800p-2
    f64::from_bits(0x3d2ca6ed5147bdb7), // 0x1.ca6ed5147bdb7p-45
    f64::from_bits(0x3fe8200000000000), // 0x1.8200000000000p-1
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0x3fd214456d0eb800), // 0x1.214456d0eb800p-2
    f64::from_bits(0x3d0a87deba46baea), // 0x1.a87deba46baeap-47
    f64::from_bits(0x3fe7e00000000000), // 0x1.7e00000000000p-1
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0x3fd2bef07cdc9000), // 0x1.2bef07cdc9000p-2
    f64::from_bits(0x3d2a9cfa4a5004f4), // 0x1.a9cfa4a5004f4p-45
    f64::from_bits(0x3fe7c00000000000), // 0x1.7c00000000000p-1
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0x3fd314f1e1d36000), // 0x1.314f1e1d36000p-2
    f64::from_bits(0xbd28e27ad3213cb8), // -0x1.8e27ad3213cb8p-45
    f64::from_bits(0x3fe7a00000000000), // 0x1.7a00000000000p-1
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0x3fd36b6776be1000), // 0x1.36b6776be1000p-2
    f64::from_bits(0x3d116ecdb0f177c8), // 0x1.16ecdb0f177c8p-46
    f64::from_bits(0x3fe7800000000000), // 0x1.7800000000000p-1
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0x3fd3c25277333000), // 0x1.3c25277333000p-2
    f64::from_bits(0x3d183b54b606bd5c), // 0x1.83b54b606bd5cp-46
    f64::from_bits(0x3fe7600000000000), // 0x1.7600000000000p-1
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0x3fd419b423d5e800), // 0x1.419b423d5e800p-2
    f64::from_bits(0x3d08e436ec90e09d), // 0x1.8e436ec90e09dp-47
    f64::from_bits(0x3fe7400000000000), // 0x1.7400000000000p-1
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0x3fd4718dc271c800), // 0x1.4718dc271c800p-2
    f64::from_bits(0xbd2f27ce0967d675), // -0x1.f27ce0967d675p-45
    f64::from_bits(0x3fe7200000000000), // 0x1.7200000000000p-1
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0x3fd4c9e09e173000), // 0x1.4c9e09e173000p-2
    f64::from_bits(0xbd2e20891b0ad8a4), // -0x1.e20891b0ad8a4p-45
    f64::from_bits(0x3fe7000000000000), // 0x1.7000000000000p-1
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0x3fd522ae0738a000), // 0x1.522ae0738a000p-2
    f64::from_bits(0x3d2ebe708164c759), // 0x1.ebe708164c759p-45
    f64::from_bits(0x3fe6e00000000000), // 0x1.6e00000000000p-1
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0x3fd57bf753c8d000), // 0x1.57bf753c8d000p-2
    f64::from_bits(0x3d1fadedee5d40ef), // 0x1.fadedee5d40efp-46
    f64::from_bits(0x3fe6c00000000000), // 0x1.6c00000000000p-1
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0x3fd5d5bddf596000), // 0x1.5d5bddf596000p-2
    f64::from_bits(0xbd0a0b2a08a465dc), // -0x1.a0b2a08a465dcp-47
];

// ARM optimized-routines math/logf_data.c: pairs invc, logc
pub static LOGF_TAB: [f64; 32] = [
    f64::from_bits(0x3ff661ec79f8f3be), // 0x1.661ec79f8f3bep+0
    f64::from_bits(0xbfd57bf7808caade), // -0x1.57bf7808caadep-2
    f64::from_bits(0x3ff571ed4aaf883d), // 0x1.571ed4aaf883dp+0
    f64::from_bits(0xbfd2bef0a7c06ddb), // -0x1.2bef0a7c06ddbp-2
    f64::from_bits(0x3ff49539f0f010b0), // 0x1.49539f0f010b0p+0
    f64::from_bits(0xbfd01eae7f513a67), // -0x1.01eae7f513a67p-2
    f64::from_bits(0x3ff3c995b0b80385), // 0x1.3c995b0b80385p+0
    f64::from_bits(0xbfcb31d8a68224e9), // -0x1.b31d8a68224e9p-3
    f64::from_bits(0x3ff30d190c8864a5), // 0x1.30d190c8864a5p+0
    f64::from_bits(0xbfc6574f0ac07758), // -0x1.6574f0ac07758p-3
    f64::from_bits(0x3ff25e227b0b8ea0), // 0x1.25e227b0b8ea0p+0
    f64::from_bits(0xbfc1aa2bc79c8100), // -0x1.1aa2bc79c8100p-3
    f64::from_bits(0x3ff1bb4a4a1a343f), // 0x1.1bb4a4a1a343fp+0
    f64::from_bits(0xbfba4e76ce8c0e5e), // -0x1.a4e76ce8c0e5ep-4
    f64::from_bits(0x3ff12358f08ae5ba), // 0x1.12358f08ae5bap+0
    f64::from_bits(0xbfb1973c5a611ccc), // -0x1.1973c5a611cccp-4
    f64::from_bits(0x3ff0953f419900a7), // 0x1.0953f419900a7p+0
    f64::from_bits(0xbfa252f438e10c1e), // -0x1.252f438e10c1ep-5
    f64::from_bits(0x3ff0000000000000), // 0x1.0000000000000p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0x3fee608cfd9a47ac), // 0x1.e608cfd9a47acp-1
    f64::from_bits(0x3faaa5aa5df25984), // 0x1.aa5aa5df25984p-5
    f64::from_bits(0x3feca4b31f026aa0), // 0x1.ca4b31f026aa0p-1
    f64::from_bits(0x3fbc5e53aa362eb4), // 0x1.c5e53aa362eb4p-4
    f64::from_bits(0x3feb2036576afce6), // 0x1.b2036576afce6p-1
    f64::from_bits(0x3fc526e57720db08), // 0x1.526e57720db08p-3
    f64::from_bits(0x3fe9c2d163a1aa2d), // 0x1.9c2d163a1aa2dp-1
    f64::from_bits(0x3fcbc2860d224770), // 0x1.bc2860d224770p-3
    f64::from_bits(0x3fe886e6037841ed), // 0x1.886e6037841edp-1
    f64::from_bits(0x3fd1058bc8a07ee1), // 0x1.1058bc8a07ee1p-2
    f64::from_bits(0x3fe767dcf5534862), // 0x1.767dcf5534862p-1
    f64::from_bits(0x3fd4043057b6ee09), // 0x1.4043057b6ee09p-2
];

// ARM optimized-routines math/logf_data.c
pub static LOGF_POLY: [f64; 3] = [
    f64::from_bits(0xbfd00ea348b88334), // -0x1.00ea348b88334p-2
    f64::from_bits(0x3fd5575b0be00b6a), // 0x1.5575b0be00b6ap-2
    f64::from_bits(0xbfdffffef20a4123), // -0x1.ffffef20a4123p-2
];

// ARM optimized-routines math/log2f_data.c: pairs invc, logc
pub static LOG2F_TAB: [f64; 32] = [
    f64::from_bits(0x3ff661ec79f8f3be), // 0x1.661ec79f8f3bep+0
    f64::from_bits(0xbfdefec65b963019), // -0x1.efec65b963019p-2
    f64::from_bits(0x3ff571ed4aaf883d), // 0x1.571ed4aaf883dp+0
    f64::from_bits(0xbfdb0b6832d4fca4), // -0x1.b0b6832d4fca4p-2
    f64::from_bits(0x3ff49539f0f010b0), // 0x1.49539f0f010b0p+0
    f64::from_bits(0xbfd7418b0a1fb77b), // -0x1.7418b0a1fb77bp-2
    f64::from_bits(0x3ff3c995b0b80385), // 0x1.3c995b0b80385p+0
    f64::from_bits(0xbfd39de91a6dcf7b), // -0x1.39de91a6dcf7bp-2
    f64::from_bits(0x3ff30d190c8864a5), // 0x1.30d190c8864a5p+0
    f64::from_bits(0xbfd01d9bf3f2b631), // -0x1.01d9bf3f2b631p-2
    f64::from_bits(0x3ff25e227b0b8ea0), // 0x1.25e227b0b8ea0p+0
    f64::from_bits(0xbfc97c1d1b3b7af0), // -0x1.97c1d1b3b7af0p-3
    f64::from_bits(0x3ff1bb4a4a1a343f), // 0x1.1bb4a4a1a343fp+0
    f64::from_bits(0xbfc2f9e393af3c9f), // -0x1.2f9e393af3c9fp-3
    f64::from_bits(0x3ff12358f08ae5ba), // 0x1.12358f08ae5bap+0
    f64::from_bits(0xbfb960cbbf788d5c), // -0x1.960cbbf788d5cp-4
    f64::from_bits(0x3ff0953f419900a7), // 0x1.0953f419900a7p+0
    f64::from_bits(0xbfaa6f9db6475fce), // -0x1.a6f9db6475fcep-5
    f64::from_bits(0x3ff0000000000000), // 0x1.0000000000000p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0x3fee608cfd9a47ac), // 0x1.e608cfd9a47acp-1
    f64::from_bits(0x3fb338ca9f24f53d), // 0x1.338ca9f24f53dp-4
    f64::from_bits(0x3feca4b31f026aa0), // 0x1.ca4b31f026aa0p-1
    f64::from_bits(0x3fc476a9543891ba), // 0x1.476a9543891bap-3
    f64::from_bits(0x3feb2036576afce6), // 0x1.b2036576afce6p-1
    f64::from_bits(0x3fce840b4ac4e4d2), // 0x1.e840b4ac4e4d2p-3
    f64::from_bits(0x3fe9c2d163a1aa2d), // 0x1.9c2d163a1aa2dp-1
    f64::from_bits(0x3fd40645f0c6651c), // 0x1.40645f0c6651cp-2
    f64::from_bits(0x3fe886e6037841ed), // 0x1.886e6037841edp-1
    f64::from_bits(0x3fd88e9c2c1b9ff8), // 0x1.88e9c2c1b9ff8p-2
    f64::from_bits(0x3fe767dcf5534862), // 0x1.767dcf5534862p-1
    f64::from_bits(0x3fdce0a44eb17bcc), // 0x1.ce0a44eb17bccp-2
];

// ARM optimized-routines math/log2f_data.c
pub static LOG2F_POLY: [f64; 4] = [
    f64::from_bits(0xbfd712b6f70a7e4d), // -0x1.712b6f70a7e4dp-2
    f64::from_bits(0x3fdecabf496832e0), // 0x1.ecabf496832e0p-2
    f64::from_bits(0xbfe715479ffae3de), // -0x1.715479ffae3dep-1
    f64::from_bits(0x3ff715475f35c8b8), // 0x1.715475f35c8b8p+0
];

// ARM optimized-routines math/powf_log2_data.c: pairs invc, logc
pub static POWF_LOG2_TAB: [f64; 32] = [
    f64::from_bits(0x3ff661ec79f8f3be), // 0x1.661ec79f8f3bep+0
    f64::from_bits(0xbfdefec65b963019), // -0x1.efec65b963019p-2
    f64::from_bits(0x3ff571ed4aaf883d), // 0x1.571ed4aaf883dp+0
    f64::from_bits(0xbfdb0b6832d4fca4), // -0x1.b0b6832d4fca4p-2
    f64::from_bits(0x3ff49539f0f010b0), // 0x1.49539f0f010b0p+0
    f64::from_bits(0xbfd7418b0a1fb77b), // -0x1.7418b0a1fb77bp-2
    f64::from_bits(0x3ff3c995b0b80385), // 0x1.3c995b0b80385p+0
    f64::from_bits(0xbfd39de91a6dcf7b), // -0x1.39de91a6dcf7bp-2
    f64::from_bits(0x3ff30d190c8864a5), // 0x1.30d190c8864a5p+0
    f64::from_bits(0xbfd01d9bf3f2b631), // -0x1.01d9bf3f2b631p-2
    f64::from_bits(0x3ff25e227b0b8ea0), // 0x1.25e227b0b8ea0p+0
    f64::from_bits(0xbfc97c1d1b3b7af0), // -0x1.97c1d1b3b7af0p-3
    f64::from_bits(0x3ff1bb4a4a1a343f), // 0x1.1bb4a4a1a343fp+0
    f64::from_bits(0xbfc2f9e393af3c9f), // -0x1.2f9e393af3c9fp-3
    f64::from_bits(0x3ff12358f08ae5ba), // 0x1.12358f08ae5bap+0
    f64::from_bits(0xbfb960cbbf788d5c), // -0x1.960cbbf788d5cp-4
    f64::from_bits(0x3ff0953f419900a7), // 0x1.0953f419900a7p+0
    f64::from_bits(0xbfaa6f9db6475fce), // -0x1.a6f9db6475fcep-5
    f64::from_bits(0x3ff0000000000000), // 0x1.0000000000000p+0
    f64::from_bits(0x0000000000000000), // 0x0.0p+0
    f64::from_bits(0x3fee608cfd9a47ac), // 0x1.e608cfd9a47acp-1
    f64::from_bits(0x3fb338ca9f24f53d), // 0x1.338ca9f24f53dp-4
    f64::from_bits(0x3feca4b31f026aa0), // 0x1.ca4b31f026aa0p-1
    f64::from_bits(0x3fc476a9543891ba), // 0x1.476a9543891bap-3
    f64::from_bits(0x3feb2036576afce6), // 0x1.b2036576afce6p-1
    f64::from_bits(0x3fce840b4ac4e4d2), // 0x1.e840b4ac4e4d2p-3
    f64::from_bits(0x3fe9c2d163a1aa2d), // 0x1.9c2d163a1aa2dp-1
    f64::from_bits(0x3fd40645f0c6651c), // 0x1.40645f0c6651cp-2
    f64::from_bits(0x3fe886e6037841ed), // 0x1.886e6037841edp-1
    f64::from_bits(0x3fd88e9c2c1b9ff8), // 0x1.88e9c2c1b9ff8p-2
    f64::from_bits(0x3fe767dcf5534862), // 0x1.767dcf5534862p-1
    f64::from_bits(0x3fdce0a44eb17bcc), // 0x1.ce0a44eb17bccp-2
];

// ARM optimized-routines math/powf_log2_data.c
pub static POWF_LOG2_POLY: [f64; 5] = [
    f64::from_bits(0x3fd27616c9496e0b), // 0x1.27616c9496e0bp-2
    f64::from_bits(0xbfd71969a075c67a), // -0x1.71969a075c67ap-2
    f64::from_bits(0x3fdec70a6ca7badd), // 0x1.ec70a6ca7baddp-2
    f64::from_bits(0xbfe7154748bef6c8), // -0x1.7154748bef6c8p-1
    f64::from_bits(0x3ff71547652ab82b), // 0x1.71547652ab82bp+0
];
