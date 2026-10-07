use crate::unistd::{self, EBADF, EINVAL, ENOENT, ENOSYS, fail, nr};
use core::arch::x86_64::{__cpuid, __cpuid_count};
use core::ffi::{c_char, c_int, c_long};
use rusty_libc_core::{Errno, errno, syscall};

pub const CS_PATH: c_int = 0;
pub const CS_V6_WIDTH_RESTRICTED_ENVS: c_int = 1;
pub const CS_GNU_LIBC_VERSION: c_int = 2;
pub const CS_GNU_LIBPTHREAD_VERSION: c_int = 3;
pub const CS_V5_WIDTH_RESTRICTED_ENVS: c_int = 4;
pub const CS_V7_WIDTH_RESTRICTED_ENVS: c_int = 5;
pub const CS_LFS_CFLAGS: c_int = 1000;
pub const CS_LFS_LDFLAGS: c_int = 1001;
pub const CS_LFS_LIBS: c_int = 1002;
pub const CS_LFS_LINTFLAGS: c_int = 1003;
pub const CS_LFS64_CFLAGS: c_int = 1004;
pub const CS_LFS64_LDFLAGS: c_int = 1005;
pub const CS_LFS64_LIBS: c_int = 1006;
pub const CS_LFS64_LINTFLAGS: c_int = 1007;
pub const CS_XBS5_ILP32_OFF32_CFLAGS: c_int = 1100;
pub const CS_XBS5_ILP32_OFF32_LDFLAGS: c_int = 1101;
pub const CS_XBS5_ILP32_OFF32_LIBS: c_int = 1102;
pub const CS_XBS5_ILP32_OFF32_LINTFLAGS: c_int = 1103;
pub const CS_XBS5_ILP32_OFFBIG_CFLAGS: c_int = 1104;
pub const CS_XBS5_ILP32_OFFBIG_LDFLAGS: c_int = 1105;
pub const CS_XBS5_ILP32_OFFBIG_LIBS: c_int = 1106;
pub const CS_XBS5_ILP32_OFFBIG_LINTFLAGS: c_int = 1107;
pub const CS_XBS5_LP64_OFF64_CFLAGS: c_int = 1108;
pub const CS_XBS5_LP64_OFF64_LDFLAGS: c_int = 1109;
pub const CS_XBS5_LP64_OFF64_LIBS: c_int = 1110;
pub const CS_XBS5_LP64_OFF64_LINTFLAGS: c_int = 1111;
pub const CS_XBS5_LPBIG_OFFBIG_CFLAGS: c_int = 1112;
pub const CS_XBS5_LPBIG_OFFBIG_LDFLAGS: c_int = 1113;
pub const CS_XBS5_LPBIG_OFFBIG_LIBS: c_int = 1114;
pub const CS_XBS5_LPBIG_OFFBIG_LINTFLAGS: c_int = 1115;
pub const CS_POSIX_V6_ILP32_OFF32_CFLAGS: c_int = 1116;
pub const CS_POSIX_V6_ILP32_OFF32_LDFLAGS: c_int = 1117;
pub const CS_POSIX_V6_ILP32_OFF32_LIBS: c_int = 1118;
pub const CS_POSIX_V6_ILP32_OFF32_LINTFLAGS: c_int = 1119;
pub const CS_POSIX_V6_ILP32_OFFBIG_CFLAGS: c_int = 1120;
pub const CS_POSIX_V6_ILP32_OFFBIG_LDFLAGS: c_int = 1121;
pub const CS_POSIX_V6_ILP32_OFFBIG_LIBS: c_int = 1122;
pub const CS_POSIX_V6_ILP32_OFFBIG_LINTFLAGS: c_int = 1123;
pub const CS_POSIX_V6_LP64_OFF64_CFLAGS: c_int = 1124;
pub const CS_POSIX_V6_LP64_OFF64_LDFLAGS: c_int = 1125;
pub const CS_POSIX_V6_LP64_OFF64_LIBS: c_int = 1126;
pub const CS_POSIX_V6_LP64_OFF64_LINTFLAGS: c_int = 1127;
pub const CS_POSIX_V6_LPBIG_OFFBIG_CFLAGS: c_int = 1128;
pub const CS_POSIX_V6_LPBIG_OFFBIG_LDFLAGS: c_int = 1129;
pub const CS_POSIX_V6_LPBIG_OFFBIG_LIBS: c_int = 1130;
pub const CS_POSIX_V6_LPBIG_OFFBIG_LINTFLAGS: c_int = 1131;
pub const CS_POSIX_V7_ILP32_OFF32_CFLAGS: c_int = 1132;
pub const CS_POSIX_V7_ILP32_OFF32_LDFLAGS: c_int = 1133;
pub const CS_POSIX_V7_ILP32_OFF32_LIBS: c_int = 1134;
pub const CS_POSIX_V7_ILP32_OFF32_LINTFLAGS: c_int = 1135;
pub const CS_POSIX_V7_ILP32_OFFBIG_CFLAGS: c_int = 1136;
pub const CS_POSIX_V7_ILP32_OFFBIG_LDFLAGS: c_int = 1137;
pub const CS_POSIX_V7_ILP32_OFFBIG_LIBS: c_int = 1138;
pub const CS_POSIX_V7_ILP32_OFFBIG_LINTFLAGS: c_int = 1139;
pub const CS_POSIX_V7_LP64_OFF64_CFLAGS: c_int = 1140;
pub const CS_POSIX_V7_LP64_OFF64_LDFLAGS: c_int = 1141;
pub const CS_POSIX_V7_LP64_OFF64_LIBS: c_int = 1142;
pub const CS_POSIX_V7_LP64_OFF64_LINTFLAGS: c_int = 1143;
pub const CS_POSIX_V7_LPBIG_OFFBIG_CFLAGS: c_int = 1144;
pub const CS_POSIX_V7_LPBIG_OFFBIG_LDFLAGS: c_int = 1145;
pub const CS_POSIX_V7_LPBIG_OFFBIG_LIBS: c_int = 1146;
pub const CS_POSIX_V7_LPBIG_OFFBIG_LINTFLAGS: c_int = 1147;
pub const CS_V6_ENV: c_int = 1148;
pub const CS_V7_ENV: c_int = 1149;
pub const PC_LINK_MAX: c_int = 0;
pub const PC_MAX_CANON: c_int = 1;
pub const PC_MAX_INPUT: c_int = 2;
pub const PC_NAME_MAX: c_int = 3;
pub const PC_PATH_MAX: c_int = 4;
pub const PC_PIPE_BUF: c_int = 5;
pub const PC_CHOWN_RESTRICTED: c_int = 6;
pub const PC_NO_TRUNC: c_int = 7;
pub const PC_VDISABLE: c_int = 8;
pub const PC_SYNC_IO: c_int = 9;
pub const PC_ASYNC_IO: c_int = 10;
pub const PC_PRIO_IO: c_int = 11;
pub const PC_SOCK_MAXBUF: c_int = 12;
pub const PC_FILESIZEBITS: c_int = 13;
pub const PC_REC_INCR_XFER_SIZE: c_int = 14;
pub const PC_REC_MAX_XFER_SIZE: c_int = 15;
pub const PC_REC_MIN_XFER_SIZE: c_int = 16;
pub const PC_REC_XFER_ALIGN: c_int = 17;
pub const PC_ALLOC_SIZE_MIN: c_int = 18;
pub const PC_SYMLINK_MAX: c_int = 19;
pub const PC_2_SYMLINKS: c_int = 20;
pub const SC_ARG_MAX: c_int = 0;
pub const SC_CHILD_MAX: c_int = 1;
pub const SC_CLK_TCK: c_int = 2;
pub const SC_NGROUPS_MAX: c_int = 3;
pub const SC_OPEN_MAX: c_int = 4;
pub const SC_STREAM_MAX: c_int = 5;
pub const SC_TZNAME_MAX: c_int = 6;
pub const SC_JOB_CONTROL: c_int = 7;
pub const SC_SAVED_IDS: c_int = 8;
pub const SC_REALTIME_SIGNALS: c_int = 9;
pub const SC_PRIORITY_SCHEDULING: c_int = 10;
pub const SC_TIMERS: c_int = 11;
pub const SC_ASYNCHRONOUS_IO: c_int = 12;
pub const SC_PRIORITIZED_IO: c_int = 13;
pub const SC_SYNCHRONIZED_IO: c_int = 14;
pub const SC_FSYNC: c_int = 15;
pub const SC_MAPPED_FILES: c_int = 16;
pub const SC_MEMLOCK: c_int = 17;
pub const SC_MEMLOCK_RANGE: c_int = 18;
pub const SC_MEMORY_PROTECTION: c_int = 19;
pub const SC_MESSAGE_PASSING: c_int = 20;
pub const SC_SEMAPHORES: c_int = 21;
pub const SC_SHARED_MEMORY_OBJECTS: c_int = 22;
pub const SC_AIO_LISTIO_MAX: c_int = 23;
pub const SC_AIO_MAX: c_int = 24;
pub const SC_AIO_PRIO_DELTA_MAX: c_int = 25;
pub const SC_DELAYTIMER_MAX: c_int = 26;
pub const SC_MQ_OPEN_MAX: c_int = 27;
pub const SC_MQ_PRIO_MAX: c_int = 28;
pub const SC_VERSION: c_int = 29;
pub const SC_PAGESIZE: c_int = 30;
pub const SC_RTSIG_MAX: c_int = 31;
pub const SC_SEM_NSEMS_MAX: c_int = 32;
pub const SC_SEM_VALUE_MAX: c_int = 33;
pub const SC_SIGQUEUE_MAX: c_int = 34;
pub const SC_TIMER_MAX: c_int = 35;
pub const SC_BC_BASE_MAX: c_int = 36;
pub const SC_BC_DIM_MAX: c_int = 37;
pub const SC_BC_SCALE_MAX: c_int = 38;
pub const SC_BC_STRING_MAX: c_int = 39;
pub const SC_COLL_WEIGHTS_MAX: c_int = 40;
pub const SC_EQUIV_CLASS_MAX: c_int = 41;
pub const SC_EXPR_NEST_MAX: c_int = 42;
pub const SC_LINE_MAX: c_int = 43;
pub const SC_RE_DUP_MAX: c_int = 44;
pub const SC_CHARCLASS_NAME_MAX: c_int = 45;
pub const SC_2_VERSION: c_int = 46;
pub const SC_2_C_BIND: c_int = 47;
pub const SC_2_C_DEV: c_int = 48;
pub const SC_2_FORT_DEV: c_int = 49;
pub const SC_2_FORT_RUN: c_int = 50;
pub const SC_2_SW_DEV: c_int = 51;
pub const SC_2_LOCALEDEF: c_int = 52;
pub const SC_PII: c_int = 53;
pub const SC_PII_XTI: c_int = 54;
pub const SC_PII_SOCKET: c_int = 55;
pub const SC_PII_INTERNET: c_int = 56;
pub const SC_PII_OSI: c_int = 57;
pub const SC_POLL: c_int = 58;
pub const SC_SELECT: c_int = 59;
pub const SC_IOV_MAX: c_int = 60;
pub const SC_UIO_MAXIOV: c_int = 60;
pub const SC_PII_INTERNET_STREAM: c_int = 61;
pub const SC_PII_INTERNET_DGRAM: c_int = 62;
pub const SC_PII_OSI_COTS: c_int = 63;
pub const SC_PII_OSI_CLTS: c_int = 64;
pub const SC_PII_OSI_M: c_int = 65;
pub const SC_T_IOV_MAX: c_int = 66;
pub const SC_THREADS: c_int = 67;
pub const SC_THREAD_SAFE_FUNCTIONS: c_int = 68;
pub const SC_GETGR_R_SIZE_MAX: c_int = 69;
pub const SC_GETPW_R_SIZE_MAX: c_int = 70;
pub const SC_LOGIN_NAME_MAX: c_int = 71;
pub const SC_TTY_NAME_MAX: c_int = 72;
pub const SC_THREAD_DESTRUCTOR_ITERATIONS: c_int = 73;
pub const SC_THREAD_KEYS_MAX: c_int = 74;
pub const SC_THREAD_STACK_MIN: c_int = 75;
pub const SC_THREAD_THREADS_MAX: c_int = 76;
pub const SC_THREAD_ATTR_STACKADDR: c_int = 77;
pub const SC_THREAD_ATTR_STACKSIZE: c_int = 78;
pub const SC_THREAD_PRIORITY_SCHEDULING: c_int = 79;
pub const SC_THREAD_PRIO_INHERIT: c_int = 80;
pub const SC_THREAD_PRIO_PROTECT: c_int = 81;
pub const SC_THREAD_PROCESS_SHARED: c_int = 82;
pub const SC_NPROCESSORS_CONF: c_int = 83;
pub const SC_NPROCESSORS_ONLN: c_int = 84;
pub const SC_PHYS_PAGES: c_int = 85;
pub const SC_AVPHYS_PAGES: c_int = 86;
pub const SC_ATEXIT_MAX: c_int = 87;
pub const SC_PASS_MAX: c_int = 88;
pub const SC_XOPEN_VERSION: c_int = 89;
pub const SC_XOPEN_XCU_VERSION: c_int = 90;
pub const SC_XOPEN_UNIX: c_int = 91;
pub const SC_XOPEN_CRYPT: c_int = 92;
pub const SC_XOPEN_ENH_I18N: c_int = 93;
pub const SC_XOPEN_SHM: c_int = 94;
pub const SC_2_CHAR_TERM: c_int = 95;
pub const SC_2_C_VERSION: c_int = 96;
pub const SC_2_UPE: c_int = 97;
pub const SC_XOPEN_XPG2: c_int = 98;
pub const SC_XOPEN_XPG3: c_int = 99;
pub const SC_XOPEN_XPG4: c_int = 100;
pub const SC_CHAR_BIT: c_int = 101;
pub const SC_CHAR_MAX: c_int = 102;
pub const SC_CHAR_MIN: c_int = 103;
pub const SC_INT_MAX: c_int = 104;
pub const SC_INT_MIN: c_int = 105;
pub const SC_LONG_BIT: c_int = 106;
pub const SC_WORD_BIT: c_int = 107;
pub const SC_MB_LEN_MAX: c_int = 108;
pub const SC_NZERO: c_int = 109;
pub const SC_SSIZE_MAX: c_int = 110;
pub const SC_SCHAR_MAX: c_int = 111;
pub const SC_SCHAR_MIN: c_int = 112;
pub const SC_SHRT_MAX: c_int = 113;
pub const SC_SHRT_MIN: c_int = 114;
pub const SC_UCHAR_MAX: c_int = 115;
pub const SC_UINT_MAX: c_int = 116;
pub const SC_ULONG_MAX: c_int = 117;
pub const SC_USHRT_MAX: c_int = 118;
pub const SC_NL_ARGMAX: c_int = 119;
pub const SC_NL_LANGMAX: c_int = 120;
pub const SC_NL_MSGMAX: c_int = 121;
pub const SC_NL_NMAX: c_int = 122;
pub const SC_NL_SETMAX: c_int = 123;
pub const SC_NL_TEXTMAX: c_int = 124;
pub const SC_XBS5_ILP32_OFF32: c_int = 125;
pub const SC_XBS5_ILP32_OFFBIG: c_int = 126;
pub const SC_XBS5_LP64_OFF64: c_int = 127;
pub const SC_XBS5_LPBIG_OFFBIG: c_int = 128;
pub const SC_XOPEN_LEGACY: c_int = 129;
pub const SC_XOPEN_REALTIME: c_int = 130;
pub const SC_XOPEN_REALTIME_THREADS: c_int = 131;
pub const SC_ADVISORY_INFO: c_int = 132;
pub const SC_BARRIERS: c_int = 133;
pub const SC_BASE: c_int = 134;
pub const SC_C_LANG_SUPPORT: c_int = 135;
pub const SC_C_LANG_SUPPORT_R: c_int = 136;
pub const SC_CLOCK_SELECTION: c_int = 137;
pub const SC_CPUTIME: c_int = 138;
pub const SC_THREAD_CPUTIME: c_int = 139;
pub const SC_DEVICE_IO: c_int = 140;
pub const SC_DEVICE_SPECIFIC: c_int = 141;
pub const SC_DEVICE_SPECIFIC_R: c_int = 142;
pub const SC_FD_MGMT: c_int = 143;
pub const SC_FIFO: c_int = 144;
pub const SC_PIPE: c_int = 145;
pub const SC_FILE_ATTRIBUTES: c_int = 146;
pub const SC_FILE_LOCKING: c_int = 147;
pub const SC_FILE_SYSTEM: c_int = 148;
pub const SC_MONOTONIC_CLOCK: c_int = 149;
pub const SC_MULTI_PROCESS: c_int = 150;
pub const SC_SINGLE_PROCESS: c_int = 151;
pub const SC_NETWORKING: c_int = 152;
pub const SC_READER_WRITER_LOCKS: c_int = 153;
pub const SC_SPIN_LOCKS: c_int = 154;
pub const SC_REGEXP: c_int = 155;
pub const SC_REGEX_VERSION: c_int = 156;
pub const SC_SHELL: c_int = 157;
pub const SC_SIGNALS: c_int = 158;
pub const SC_SPAWN: c_int = 159;
pub const SC_SPORADIC_SERVER: c_int = 160;
pub const SC_THREAD_SPORADIC_SERVER: c_int = 161;
pub const SC_SYSTEM_DATABASE: c_int = 162;
pub const SC_SYSTEM_DATABASE_R: c_int = 163;
pub const SC_TIMEOUTS: c_int = 164;
pub const SC_TYPED_MEMORY_OBJECTS: c_int = 165;
pub const SC_USER_GROUPS: c_int = 166;
pub const SC_USER_GROUPS_R: c_int = 167;
pub const SC_2_PBS: c_int = 168;
pub const SC_2_PBS_ACCOUNTING: c_int = 169;
pub const SC_2_PBS_LOCATE: c_int = 170;
pub const SC_2_PBS_MESSAGE: c_int = 171;
pub const SC_2_PBS_TRACK: c_int = 172;
pub const SC_SYMLOOP_MAX: c_int = 173;
pub const SC_STREAMS: c_int = 174;
pub const SC_2_PBS_CHECKPOINT: c_int = 175;
pub const SC_V6_ILP32_OFF32: c_int = 176;
pub const SC_V6_ILP32_OFFBIG: c_int = 177;
pub const SC_V6_LP64_OFF64: c_int = 178;
pub const SC_V6_LPBIG_OFFBIG: c_int = 179;
pub const SC_HOST_NAME_MAX: c_int = 180;
pub const SC_TRACE: c_int = 181;
pub const SC_TRACE_EVENT_FILTER: c_int = 182;
pub const SC_TRACE_INHERIT: c_int = 183;
pub const SC_TRACE_LOG: c_int = 184;
pub const SC_LEVEL1_ICACHE_SIZE: c_int = 185;
pub const SC_LEVEL1_ICACHE_ASSOC: c_int = 186;
pub const SC_LEVEL1_ICACHE_LINESIZE: c_int = 187;
pub const SC_LEVEL1_DCACHE_SIZE: c_int = 188;
pub const SC_LEVEL1_DCACHE_ASSOC: c_int = 189;
pub const SC_LEVEL1_DCACHE_LINESIZE: c_int = 190;
pub const SC_LEVEL2_CACHE_SIZE: c_int = 191;
pub const SC_LEVEL2_CACHE_ASSOC: c_int = 192;
pub const SC_LEVEL2_CACHE_LINESIZE: c_int = 193;
pub const SC_LEVEL3_CACHE_SIZE: c_int = 194;
pub const SC_LEVEL3_CACHE_ASSOC: c_int = 195;
pub const SC_LEVEL3_CACHE_LINESIZE: c_int = 196;
pub const SC_LEVEL4_CACHE_SIZE: c_int = 197;
pub const SC_LEVEL4_CACHE_ASSOC: c_int = 198;
pub const SC_LEVEL4_CACHE_LINESIZE: c_int = 199;
pub const SC_IPV6: c_int = 235;
pub const SC_RAW_SOCKETS: c_int = 236;
pub const SC_V7_ILP32_OFF32: c_int = 237;
pub const SC_V7_ILP32_OFFBIG: c_int = 238;
pub const SC_V7_LP64_OFF64: c_int = 239;
pub const SC_V7_LPBIG_OFFBIG: c_int = 240;
pub const SC_SS_REPL_MAX: c_int = 241;
pub const SC_TRACE_EVENT_NAME_MAX: c_int = 242;
pub const SC_TRACE_NAME_MAX: c_int = 243;
pub const SC_TRACE_SYS_MAX: c_int = 244;
pub const SC_TRACE_USER_EVENT_MAX: c_int = 245;
pub const SC_XOPEN_STREAMS: c_int = 246;
pub const SC_THREAD_ROBUST_PRIO_INHERIT: c_int = 247;
pub const SC_THREAD_ROBUST_PRIO_PROTECT: c_int = 248;
pub const SC_MINSIGSTKSZ: c_int = 249;
pub const SC_SIGSTKSZ: c_int = 250;

const E: i64 = i64::MIN;
const D: i64 = i64::MIN + 1;

static TABLE: [i64; 251] = [
    D,
    D,
    100,
    D,
    D,
    16,
    -1,
    1,
    1,
    200809,
    200809,
    200809,
    200809,
    200809,
    200809,
    200809,
    200809,
    200809,
    200809,
    200809,
    200809,
    200809,
    200809,
    -1,
    -1,
    20,
    2147483647,
    -1,
    32768,
    200809,
    4096,
    32,
    -1,
    2147483647,
    D,
    -1,
    99,
    2048,
    99,
    1000,
    255,
    E,
    32,
    2048,
    32767,
    2048,
    200809,
    200809,
    200809,
    -1,
    -1,
    200809,
    200809,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    1024,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    200809,
    200809,
    1024,
    1024,
    256,
    32,
    4,
    1024,
    16384,
    -1,
    200809,
    200809,
    200809,
    200809,
    200809,
    200809,
    D,
    D,
    D,
    D,
    2147483647,
    8192,
    700,
    4,
    1,
    -1,
    1,
    1,
    200809,
    200809,
    -1,
    1,
    1,
    1,
    8,
    127,
    -128,
    2147483647,
    -2147483648,
    64,
    32,
    16,
    20,
    32767,
    127,
    -128,
    32767,
    -32768,
    255,
    4294967295,
    -1,
    65535,
    4096,
    2048,
    2147483647,
    2147483647,
    2147483647,
    2147483647,
    1,
    1,
    1,
    -1,
    1,
    1,
    1,
    200809,
    200809,
    -1,
    -1,
    -1,
    200809,
    200809,
    200809,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    200809,
    -1,
    -1,
    -1,
    200809,
    200809,
    1,
    -1,
    1,
    -1,
    200809,
    -1,
    -1,
    -1,
    -1,
    200809,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    1,
    1,
    1,
    -1,
    64,
    -1,
    -1,
    -1,
    -1,
    D,
    D,
    D,
    D,
    D,
    D,
    D,
    D,
    D,
    D,
    D,
    D,
    D,
    D,
    D,
    E,
    E,
    E,
    E,
    E,
    E,
    E,
    E,
    E,
    E,
    E,
    E,
    E,
    E,
    E,
    E,
    E,
    E,
    E,
    E,
    E,
    E,
    E,
    E,
    E,
    E,
    E,
    E,
    E,
    E,
    E,
    E,
    E,
    E,
    E,
    200809,
    200809,
    1,
    1,
    1,
    -1,
    E,
    -1,
    -1,
    -1,
    -1,
    -1,
    E,
    E,
    D,
    D,
];

const RLIMIT_STACK: c_int = 3;
const RLIMIT_NPROC: c_int = 6;
const RLIMIT_SIGPENDING: c_int = 11;
const RLIM_INFINITY: u64 = u64::MAX;

fn getrlimit(res: c_int) -> Option<u64> {
    let mut lim = [0u64; 2];
    let r = unsafe { syscall::syscall4(nr::PRLIMIT64, 0, res as usize, 0, lim.as_mut_ptr() as usize) };
    if r == 0 { Some(lim[0]) } else { None }
}

fn read_file(path: &core::ffi::CStr, buf: &mut [u8]) -> usize {
    unsafe {
        let fd = syscall::syscall4(nr::OPENAT, unistd::AT_FDCWD as usize, path.as_ptr() as usize, 0o2000000, 0);
        if syscall::check(fd).is_err() {
            return 0;
        }
        let mut n = 0;
        while n < buf.len() {
            match syscall::check(syscall::syscall3(nr::READ, fd, buf.as_mut_ptr() as usize + n, buf.len() - n)) {
                Ok(0) | Err(_) => break,
                Ok(k) => n += k,
            }
        }
        syscall::syscall1(nr::CLOSE, fd);
        n
    }
}

fn parse_uint(s: &[u8]) -> Option<(u64, usize)> {
    let mut i = 0;
    let mut v: u64 = 0;
    while i < s.len() && s[i].is_ascii_digit() {
        v = v.wrapping_mul(10).wrapping_add((s[i] - b'0') as u64);
        i += 1;
    }
    if i == 0 { None } else { Some((v, i)) }
}

fn sysfs_count(path: &core::ffi::CStr) -> i32 {
    let mut buf = [0u8; 1024];
    let n = read_file(path, &mut buf);
    let s = &buf[..n];
    let mut i = 0;
    let mut result: i64 = 0;
    if s.is_empty() {
        return 0;
    }
    loop {
        let Some((a, k)) = parse_uint(&s[i..]) else { return 0 };
        i += k;
        let mut b = a;
        if i < s.len() && s[i] == b'-' {
            i += 1;
            let Some((m, k)) = parse_uint(&s[i..]) else { return 0 };
            i += k;
            b = m;
        }
        if b >= a {
            result += (b - a + 1) as i64;
        }
        if i < s.len() && s[i] == b',' {
            i += 1;
        }
        if !(i < s.len() && s[i] != b'\n') {
            break;
        }
    }
    result as i32
}

fn nprocs_stat() -> i32 {
    let mut buf = [0u8; 65536];
    let n = read_file(c"/proc/stat", &mut buf);
    let mut count = 0;
    for line in buf[..n].split(|&c| c == b'\n') {
        if !line.starts_with(b"cpu") {
            break;
        }
        if line.len() > 3 && line[3].is_ascii_digit() {
            count += 1;
        }
    }
    count
}

fn nprocs_sched() -> i32 {
    let mut mask = [0u64; 512];
    let r = unsafe { syscall::syscall3(nr::SCHED_GETAFFINITY, 0, 4096, mask.as_mut_ptr() as usize) };
    match syscall::check(r) {
        Ok(n) if n > 0 => mask[..n.div_ceil(8)].iter().map(|w| w.count_ones() as i32).sum(),
        Err(Errno(EINVAL)) => 32768,
        _ => 0,
    }
}

fn nprocs_fallback() -> i32 {
    let r = nprocs_stat();
    if r != 0 {
        return r;
    }
    let r = nprocs_sched();
    if r != 0 { r } else { 2 }
}

pub extern "C" fn get_nprocs() -> c_int {
    let r = sysfs_count(c"/sys/devices/system/cpu/online");
    if r != 0 { r } else { nprocs_fallback() }
}

pub extern "C" fn get_nprocs_conf() -> c_int {
    let r = sysfs_count(c"/sys/devices/system/cpu/possible");
    if r != 0 { r } else { nprocs_fallback() }
}

#[repr(C)]
#[derive(Default)]
struct SysInfo {
    uptime: i64,
    loads: [u64; 3],
    totalram: u64,
    freeram: u64,
    sharedram: u64,
    bufferram: u64,
    totalswap: u64,
    freeswap: u64,
    procs: u16,
    pad: u16,
    pad2: u32,
    totalhigh: u64,
    freehigh: u64,
    mem_unit: u32,
    f: [u8; 4],
}

fn mempages(num: u64, mut mem_unit: u32) -> i64 {
    let mut ps: u64 = 4096;
    while mem_unit > 1 && ps > 1 {
        mem_unit >>= 1;
        ps >>= 1;
    }
    let mut num = num.wrapping_mul(mem_unit as u64);
    while ps > 1 {
        ps >>= 1;
        num >>= 1;
    }
    num as i64
}

fn sysinfo() -> SysInfo {
    let mut si = SysInfo::default();
    unsafe { syscall::syscall1(nr::SYSINFO, &mut si as *mut SysInfo as usize) };
    si
}

pub extern "C" fn get_phys_pages() -> c_long {
    let si = sysinfo();
    mempages(si.totalram, si.mem_unit)
}

pub extern "C" fn get_avphys_pages() -> c_long {
    let si = sysinfo();
    mempages(si.freeram, si.mem_unit)
}

fn vendor() -> [u8; 12] {
    let r = __cpuid(0);
    let mut v = [0u8; 12];
    v[0..4].copy_from_slice(&r.ebx.to_le_bytes());
    v[4..8].copy_from_slice(&r.edx.to_le_bytes());
    v[8..12].copy_from_slice(&r.ecx.to_le_bytes());
    v
}

fn is_assoc(name: c_int) -> bool {
    matches!(name, SC_LEVEL1_ICACHE_ASSOC | SC_LEVEL1_DCACHE_ASSOC | SC_LEVEL2_CACHE_ASSOC | SC_LEVEL3_CACHE_ASSOC)
}
fn is_line(name: c_int) -> bool {
    matches!(name, SC_LEVEL1_ICACHE_LINESIZE | SC_LEVEL1_DCACHE_LINESIZE | SC_LEVEL2_CACHE_LINESIZE | SC_LEVEL3_CACHE_LINESIZE)
}

fn amd_assoc_code(c: u32) -> i64 {
    match c {
        0 | 1 | 2 | 4 => c as i64,
        6 => 8,
        8 => 16,
        10 => 32,
        11 => 48,
        12 => 64,
        13 => 96,
        14 => 128,
        _ => 0,
    }
}

fn handle_amd(name: c_int) -> i64 {
    if name > SC_LEVEL3_CACHE_LINESIZE {
        return 0;
    }
    let max_cpuid = __cpuid(0x8000_0000).eax;
    if max_cpuid >= 0x8000_001d {
        let count = if name >= SC_LEVEL3_CACHE_SIZE {
            3
        } else if name >= SC_LEVEL2_CACHE_SIZE {
            2
        } else if name >= SC_LEVEL1_DCACHE_SIZE {
            0
        } else {
            1
        };
        let r = __cpuid_count(0x8000_001d, count);
        if r.ecx != 0 {
            let ways = ((r.ebx >> 22) & 0x3ff) as i64 + 1;
            let line = (r.ebx & 0xfff) as i64 + 1;
            return if is_assoc(name) {
                ways
            } else if is_line(name) {
                line
            } else {
                ways * line * (r.ecx as i64 + 1)
            };
        }
    }
    let fnum = 0x8000_0005 + (name >= SC_LEVEL2_CACHE_SIZE) as u32;
    if max_cpuid < fnum {
        return 0;
    }
    let r = __cpuid(fnum);
    let (mut name, mut ecx, edx) = (name, r.ecx, r.edx);
    if name < SC_LEVEL1_DCACHE_SIZE {
        name += SC_LEVEL1_DCACHE_SIZE - SC_LEVEL1_ICACHE_SIZE;
        ecx = edx;
    }
    match name {
        SC_LEVEL1_DCACHE_SIZE => ((ecx >> 14) & 0x3fc00) as i64,
        SC_LEVEL1_DCACHE_ASSOC => {
            let e = ecx >> 16;
            if e & 0xff == 0xff { ((e << 2) & 0x3fc00) as i64 } else { (e & 0xff) as i64 }
        }
        SC_LEVEL1_DCACHE_LINESIZE => (ecx & 0xff) as i64,
        SC_LEVEL2_CACHE_SIZE => {
            if ecx & 0xf000 == 0 {
                0
            } else {
                ((ecx >> 6) & 0x3fffc00) as i64
            }
        }
        SC_LEVEL2_CACHE_ASSOC => {
            let code = (ecx >> 12) & 0xf;
            if code == 15 { (((ecx >> 6) & 0x3fffc00) / (ecx & 0xff).max(1)) as i64 } else { amd_assoc_code(code) }
        }
        SC_LEVEL2_CACHE_LINESIZE => {
            if ecx & 0xf000 == 0 {
                0
            } else {
                (ecx & 0xff) as i64
            }
        }
        SC_LEVEL3_CACHE_SIZE => {
            if edx & 0xf000 == 0 {
                return 0;
            }
            let total = ((edx & 0x3ffc_0000) << 1) as i64;
            let mut threads = 0i64;
            if max_cpuid >= 0x8000_0008 {
                threads = (__cpuid(0x8000_0008).ecx & 0xff) as i64 + 1;
            }
            if threads == 0 {
                let r1 = __cpuid(1);
                if r1.edx & (1 << 28) != 0 {
                    threads = ((r1.ebx >> 16) & 0xff) as i64;
                }
            }
            let per_thread = if threads > 0 { total / threads } else { 0 };
            let r1 = __cpuid(1);
            let family = ((r1.eax >> 8) & 0xf) + if (r1.eax >> 8) & 0xf == 0xf { (r1.eax >> 20) & 0xff } else { 0 };
            if family >= 0x17 {
                let c = __cpuid_count(0x8000_001d, 3);
                per_thread * (((c.eax >> 14) & 0xfff) as i64 + 1)
            } else {
                per_thread
            }
        }
        SC_LEVEL3_CACHE_ASSOC => {
            let code = (edx >> 12) & 0xf;
            if code == 15 { ((((edx & 0x3ffc_0000) << 1) as u64) / ((edx & 0xff).max(1) as u64)) as i64 } else { amd_assoc_code(code) }
        }
        SC_LEVEL3_CACHE_LINESIZE => {
            if edx & 0xf000 == 0 {
                0
            } else {
                (edx & 0xff) as i64
            }
        }
        _ => -1,
    }
}

fn handle_intel(name: c_int) -> i64 {
    let (level, want_type) = match name {
        SC_LEVEL1_ICACHE_SIZE | SC_LEVEL1_ICACHE_ASSOC | SC_LEVEL1_ICACHE_LINESIZE => (1, 2),
        SC_LEVEL1_DCACHE_SIZE | SC_LEVEL1_DCACHE_ASSOC | SC_LEVEL1_DCACHE_LINESIZE => (1, 1),
        SC_LEVEL2_CACHE_SIZE | SC_LEVEL2_CACHE_ASSOC | SC_LEVEL2_CACHE_LINESIZE => (2, 0),
        SC_LEVEL3_CACHE_SIZE | SC_LEVEL3_CACHE_ASSOC | SC_LEVEL3_CACHE_LINESIZE => (3, 0),
        _ => (4, 0),
    };
    if __cpuid(0).eax < 4 {
        return -1;
    }
    for i in 0..16 {
        let r = __cpuid_count(4, i);
        let kind = r.eax & 0x1f;
        if kind == 0 {
            break;
        }
        let lvl = (r.eax >> 5) & 7;
        if lvl != level || (want_type != 0 && kind != want_type) || (want_type == 0 && kind == 2) {
            continue;
        }
        let ways = (r.ebx >> 22) as i64 + 1;
        let line = (r.ebx & 0xfff) as i64 + 1;
        let parts = ((r.ebx >> 12) & 0x3ff) as i64 + 1;
        let sets = r.ecx as i64 + 1;
        return if is_assoc(name) {
            ways
        } else if is_line(name) {
            line
        } else {
            ways * parts * line * sets
        };
    }
    0
}

fn cache_sysconf(name: c_int) -> i64 {
    if name == SC_LEVEL1_ICACHE_ASSOC || name == SC_LEVEL4_CACHE_ASSOC || name == SC_LEVEL4_CACHE_LINESIZE {
        return -1;
    }
    let v = vendor();
    if &v == b"AuthenticAMD" || &v == b"HygonGenuine" {
        handle_amd(name)
    } else if &v == b"GenuineIntel" {
        handle_intel(name)
    } else {
        0
    }
}

fn minsigstksz() -> i64 {
    let mut buf = [0u8; 2048];
    let n = read_file(c"/proc/self/auxv", &mut buf);
    let mut i = 0;
    while i + 16 <= n {
        let key = u64::from_ne_bytes(buf[i..i + 8].try_into().unwrap());
        let val = u64::from_ne_bytes(buf[i + 8..i + 16].try_into().unwrap());
        if key == 51 && val != 0 {
            return val as i64;
        }
        if key == 0 {
            break;
        }
        i += 16;
    }
    2048
}

fn read_ngroups_max() -> Option<i64> {
    let mut buf = [0u8; 32];
    let n = read_file(c"/proc/sys/kernel/ngroups_max", &mut buf);
    if n == 0 {
        return None;
    }
    let (v, k) = parse_uint(&buf[..n])?;
    if k < n && buf[k] != b'\n' { None } else { Some(v as i64) }
}

pub fn sysconf_value(name: c_int) -> Result<i64, i32> {
    if (SC_LEVEL1_ICACHE_SIZE..=SC_LEVEL4_CACHE_LINESIZE).contains(&name) {
        return Ok(cache_sysconf(name));
    }
    match name {
        SC_ARG_MAX => {
            return Ok(match getrlimit(RLIMIT_STACK) {
                Some(cur) => (cur / 4).clamp(131072, 6 * 1024 * 1024) as i64,
                None => 131072,
            });
        }
        SC_CHILD_MAX => {
            return Ok(match getrlimit(RLIMIT_NPROC) {
                Some(RLIM_INFINITY) | None => -1,
                Some(v) => v as i64,
            });
        }
        SC_NGROUPS_MAX => return Ok(read_ngroups_max().unwrap_or(65536)),
        SC_OPEN_MAX => return Ok(unistd::getdtablesize() as i64),
        SC_SIGQUEUE_MAX => {
            if let Some(v) = getrlimit(RLIMIT_SIGPENDING) {
                return Ok(v as i64);
            }
            return Ok(-1);
        }
        SC_NPROCESSORS_CONF => return Ok(get_nprocs_conf() as i64),
        SC_NPROCESSORS_ONLN => return Ok(get_nprocs() as i64),
        SC_PHYS_PAGES => return Ok(get_phys_pages()),
        SC_AVPHYS_PAGES => return Ok(get_avphys_pages()),
        SC_MINSIGSTKSZ => return Ok(minsigstksz()),
        SC_SIGSTKSZ => {
            let m = minsigstksz().max(2048);
            return Ok((m * 4).max(8192));
        }
        _ => {}
    }
    if !(0..=250).contains(&name) {
        return Err(EINVAL);
    }
    match TABLE[name as usize] {
        E => Err(EINVAL),
        D => Err(EINVAL),
        v => Ok(v),
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn __sysconf(name: c_int) -> c_long {
    sysconf(name)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn sysconf(name: c_int) -> c_long {
    match sysconf_value(name) {
        Ok(v) => v as c_long,
        Err(e) => fail(e) as c_long,
    }
}

static CONFSTR: &[(c_int, &[u8])] = &[
    (0, b"/usr/bin"),
    (1, b"POSIX_V6_ILP32_OFF32\nPOSIX_V6_ILP32_OFFBIG\nPOSIX_V6_LP64_OFF64"),
    (2, b"glibc 2.43"),
    (3, b"NPTL 2.43"),
    (4, b"XBS5_ILP32_OFF32\nXBS5_ILP32_OFFBIG\nXBS5_LP64_OFF64"),
    (5, b"POSIX_V7_ILP32_OFF32\nPOSIX_V7_ILP32_OFFBIG\nPOSIX_V7_LP64_OFF64"),
    (1000, b""),
    (1001, b""),
    (1002, b""),
    (1003, b""),
    (1004, b"-D_LARGEFILE64_SOURCE"),
    (1005, b""),
    (1006, b""),
    (1007, b"-D_LARGEFILE64_SOURCE"),
    (1100, b"-m32"),
    (1101, b"-m32"),
    (1102, b""),
    (1103, b""),
    (1104, b"-m32 -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64"),
    (1105, b"-m32"),
    (1106, b""),
    (1107, b""),
    (1108, b"-m64"),
    (1109, b"-m64"),
    (1110, b""),
    (1111, b""),
    (1112, b""),
    (1113, b""),
    (1114, b""),
    (1115, b""),
    (1116, b"-m32"),
    (1117, b"-m32"),
    (1118, b""),
    (1119, b""),
    (1120, b"-m32 -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64"),
    (1121, b"-m32"),
    (1122, b""),
    (1123, b""),
    (1124, b"-m64"),
    (1125, b"-m64"),
    (1126, b""),
    (1127, b""),
    (1128, b""),
    (1129, b""),
    (1130, b""),
    (1131, b""),
    (1132, b"-m32"),
    (1133, b"-m32"),
    (1134, b""),
    (1135, b""),
    (1136, b"-m32 -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64"),
    (1137, b"-m32"),
    (1138, b""),
    (1139, b""),
    (1140, b"-m64"),
    (1141, b"-m64"),
    (1142, b""),
    (1143, b""),
    (1144, b""),
    (1145, b""),
    (1146, b""),
    (1147, b""),
    (1148, b"POSIXLY_CORRECT=1"),
    (1149, b"POSIXLY_CORRECT=1"),
];

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn confstr(name: c_int, buf: *mut c_char, len: usize) -> usize {
    let Some(&(_, s)) = CONFSTR.iter().find(|(n, _)| *n == name) else {
        errno::set(EINVAL);
        return 0;
    };
    let total = s.len() + 1;
    if len > 0 && !buf.is_null() {
        unsafe {
            if total <= len {
                core::ptr::copy_nonoverlapping(s.as_ptr(), buf.cast::<u8>(), s.len());
                *buf.add(s.len()) = 0;
            } else {
                core::ptr::copy_nonoverlapping(s.as_ptr(), buf.cast::<u8>(), len - 1);
                *buf.add(len - 1) = 0;
            }
        }
    }
    total
}

const LINUX_LINK_MAX: i64 = 127;
const EXT2_LINK_MAX: i64 = 32000;
const EXT4_LINK_MAX: i64 = 65000;

fn magic_link_max(t: i64) -> Option<i64> {
    Some(match t as u64 & 0xffff_ffff {
        0xf2f5_2010 => 32000,
        0x137f | 0x138f => 250,
        0x2468 | 0x2478 => 65530,
        0x012f_f7b4 => 126,
        0x012f_f7b5 | 0x012f_f7b6 => 126,
        0x012f_f7b7 => 10000,
        0x0001_1954 | 0x5419_0100 => 32000,
        0x5265_4973 => 64535,
        0x5846_5342 => 2147483647,
        0x0bd0_0bd0 => EXT4_LINK_MAX,
        0x9123_683e => 65535,
        _ => return None,
    })
}

fn distinguish_ext(path: *const c_char, fd: c_int) -> i64 {
    let mut st = crate::stat::Stat::zeroed();
    let r = unsafe {
        if path.is_null() { crate::stat::fstat(fd, &mut st) } else { crate::stat::stat(path, &mut st) }
    };
    if r != 0 {
        return EXT2_LINK_MAX;
    }
    let major = crate::stat::gnu_dev_major(st.st_dev);
    let minor = crate::stat::gnu_dev_minor(st.st_dev);
    let mut link = [0u8; 64];
    let pre = b"/sys/dev/block/";
    link[..pre.len()].copy_from_slice(pre);
    let mut w = pre.len();
    w += unistd::put_dec(major as u64, &mut link[w..]);
    link[w] = b':';
    w += 1;
    w += unistd::put_dec(minor as u64, &mut link[w..]);
    let _ = w;
    let mut target = [0u8; 4096];
    let n = unsafe { syscall::syscall4(nr::READLINKAT, unistd::AT_FDCWD as usize, link.as_ptr() as usize, target.as_mut_ptr() as usize, target.len()) };
    if let Ok(n) = syscall::check(n)
        && n < target.len()
    {
        let t = &target[..n];
        let base = &t[t.iter().rposition(|&c| c == b'/').map_or(0, |i| i + 1)..];
        let mut p = [0u8; 4096];
        let pre = b"/sys/fs/ext4/";
        p[..pre.len()].copy_from_slice(pre);
        p[pre.len()..pre.len() + base.len()].copy_from_slice(base);
        let ok = unsafe { unistd::access(p.as_ptr().cast(), 0) } == 0;
        return if ok { EXT4_LINK_MAX } else { EXT2_LINK_MAX };
    }
    let mut mounts = [0u8; 65536];
    let n = read_file(c"/proc/mounts", &mut mounts);
    let mut result = EXT2_LINK_MAX;
    for line in mounts[..n].split(|&c| c == b'\n') {
        let mut f = line.split(|&c| c == b' ');
        let (_dev, Some(dir), Some(ty)) = (f.next(), f.next(), f.next()) else { continue };
        if ty != b"ext2" && ty != b"ext3" && ty != b"ext4" {
            continue;
        }
        let mut d = [0u8; 4096];
        let mut k = 0;
        let mut i = 0;
        while i < dir.len() && k < 4095 {
            if dir[i] == b'\\' && i + 3 < dir.len() && dir[i + 1..i + 4].iter().all(|c| (b'0'..=b'7').contains(c)) {
                d[k] = ((dir[i + 1] - b'0') << 6) | ((dir[i + 2] - b'0') << 3) | (dir[i + 3] - b'0');
                i += 4;
            } else {
                d[k] = dir[i];
                i += 1;
            }
            k += 1;
        }
        let mut fs = crate::stat::Stat::zeroed();
        if unsafe { crate::stat::stat(d.as_ptr().cast(), &mut fs) } >= 0 && fs.st_dev == st.st_dev {
            if ty == b"ext4" {
                result = EXT4_LINK_MAX;
            }
            break;
        }
    }
    result
}

fn statfs_link_max(r: Result<crate::stat::Statfs, Errno>, path: *const c_char, fd: c_int) -> i64 {
    match r {
        Err(Errno(ENOSYS)) => LINUX_LINK_MAX,
        Err(e) => fail(e.0) as i64,
        Ok(fs) => {
            if fs.f_type as u64 & 0xffff_ffff == 0xef53 {
                return distinguish_ext(path, fd);
            }
            magic_link_max(fs.f_type).unwrap_or(LINUX_LINK_MAX)
        }
    }
}

fn statfs_filesize_max(r: Result<crate::stat::Statfs, Errno>) -> i64 {
    match r {
        Err(Errno(ENOSYS)) => 32,
        Err(e) => fail(e.0) as i64,
        Ok(fs) => match fs.f_type as u64 & 0xffff_ffff {
            0xf2f5_2010 => 256,
            0x9123_683e => 255,
            0xef53 | 0x0001_1954 | 0x5419_0100 | 0x5265_4973 | 0x5846_5342 | 0x517b | 0x5346_544e | 0x1501_3346 | 0x3153_464a | 0xa501_fcf5 | 0x0027_e0eb | 0x0bd0_0bd0 => 64,
            _ => 32,
        },
    }
}

fn statfs_symlinks(r: Result<crate::stat::Statfs, Errno>) -> i64 {
    match r {
        Err(Errno(ENOSYS)) => 1,
        Err(e) => fail(e.0) as i64,
        Ok(fs) => match fs.f_type as u64 & 0xffff_ffff {
            0xadf5 | 0x1bad_face | 0x28cd_3d45 | 0x1cd1 | 0x0041_4a53 | 0x0007_2959 | 0x4d44 | 0x5346_544e | 0x002f | 0x7275 => 0,
            _ => 1,
        },
    }
}

fn statfs_chown_restricted(r: Result<crate::stat::Statfs, Errno>) -> i64 {
    match r {
        Err(Errno(ENOSYS)) => 1,
        Err(e) => fail(e.0) as i64,
        Ok(_) => 1,
    }
}

fn posix_conf(name: c_int, fs: &dyn Fn() -> Result<crate::stat::Statfs, Errno>, fd_errors: bool) -> i64 {
    let statvfs = || -> Result<(i64, i64, i64), Errno> {
        let f = fs()?;
        Ok((f.f_bsize, if f.f_frsize != 0 { f.f_frsize } else { f.f_bsize }, f.f_namelen))
    };
    match name {
        PC_MAX_CANON | PC_MAX_INPUT => 255,
        PC_NAME_MAX => {
            let saved = errno::get();
            match statvfs() {
                Ok(v) => v.2,
                Err(Errno(ENOSYS)) => {
                    errno::set(saved);
                    255
                }
                Err(e) => {
                    if fd_errors && e.0 == 19 {
                        return fail(EINVAL) as i64;
                    }
                    fail(e.0) as i64
                }
            }
        }
        PC_PATH_MAX | PC_PIPE_BUF => 4096,
        PC_NO_TRUNC => 1,
        PC_VDISABLE => 0,
        PC_SYNC_IO | PC_PRIO_IO | PC_SOCK_MAXBUF => -1,
        PC_REC_INCR_XFER_SIZE | PC_REC_MAX_XFER_SIZE | PC_SYMLINK_MAX => -1,
        PC_REC_MIN_XFER_SIZE => statvfs().map_or_else(|e| fail(e.0) as i64, |v| v.0),
        PC_REC_XFER_ALIGN | PC_ALLOC_SIZE_MIN => statvfs().map_or_else(|e| fail(e.0) as i64, |v| v.1),
        _ => fail(EINVAL) as i64,
    }
}

fn async_io_conf(st: crate::stat::Stat, ok: bool) -> i64 {
    if ok && (st.is_reg() || st.file_type() == crate::stat::S_IFBLK) { 1 } else { -1 }
}

unsafe fn pathconf_value(path: *const c_char, name: c_int) -> i64 {
    unsafe {
        let fs = || crate::stat::statfs_path(path);
        match name {
            PC_LINK_MAX => return statfs_link_max(fs(), path, -1),
            PC_FILESIZEBITS => return statfs_filesize_max(fs()),
            PC_2_SYMLINKS => return statfs_symlinks(fs()),
            PC_CHOWN_RESTRICTED => return statfs_chown_restricted(fs()),
            _ => {}
        }
        if *path == 0 {
            return fail(ENOENT) as i64;
        }
        if name == PC_ASYNC_IO {
            let mut st = crate::stat::Stat::zeroed();
            let ok = crate::stat::stat(path, &mut st) == 0;
            return async_io_conf(st, ok);
        }
        posix_conf(name, &fs, false)
    }
}

fn fpathconf_value(fd: c_int, name: c_int) -> i64 {
    let fs = || crate::stat::statfs_fd(fd);
    match name {
        PC_LINK_MAX => return statfs_link_max(fs(), core::ptr::null(), fd),
        PC_FILESIZEBITS => return statfs_filesize_max(fs()),
        PC_2_SYMLINKS => return statfs_symlinks(fs()),
        PC_CHOWN_RESTRICTED => return statfs_chown_restricted(fs()),
        PC_ASYNC_IO => {
            let mut st = crate::stat::Stat::zeroed();
            let ok = unsafe { crate::stat::fstat(fd, &mut st) } == 0;
            return async_io_conf(st, ok);
        }
        _ => {}
    }
    if fd < 0 {
        return fail(EBADF) as i64;
    }
    posix_conf(name, &fs, true)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pathconf(path: *const c_char, name: c_int) -> c_long {
    unsafe { pathconf_value(path, name) as c_long }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn fpathconf(fd: c_int, name: c_int) -> c_long {
    fpathconf_value(fd, name) as c_long
}

pub mod rs {
    use super::*;
    use core::ffi::CStr;

    fn opt(v: i64, before: i32) -> Result<Option<i64>, Errno> {
        if v == -1 {
            let e = errno::get();
            if e != before {
                return Err(Errno(e));
            }
            return Ok(None);
        }
        Ok(Some(v))
    }
    pub fn sysconf(name: i32) -> Result<Option<i64>, Errno> {
        match sysconf_value(name) {
            Ok(-1) => Ok(None),
            Ok(v) => Ok(Some(v)),
            Err(e) => Err(Errno(e)),
        }
    }
    pub fn pathconf(path: &CStr, name: i32) -> Result<Option<i64>, Errno> {
        let before = errno::get();
        errno::set(0);
        let r = opt(unsafe { pathconf_value(path.as_ptr(), name) }, 0);
        if r.is_ok() {
            errno::set(before);
        }
        r
    }
    pub fn fpathconf(fd: i32, name: i32) -> Result<Option<i64>, Errno> {
        let before = errno::get();
        errno::set(0);
        let r = opt(fpathconf_value(fd, name), 0);
        if r.is_ok() {
            errno::set(before);
        }
        r
    }
    pub fn confstr(name: i32) -> Option<&'static [u8]> {
        CONFSTR.iter().find(|(n, _)| *n == name).map(|&(_, s)| s)
    }
    pub fn nprocs_online() -> usize {
        get_nprocs() as usize
    }
    pub fn nprocs_configured() -> usize {
        get_nprocs_conf() as usize
    }
    pub fn phys_pages() -> i64 {
        get_phys_pages()
    }
    pub fn avphys_pages() -> i64 {
        get_avphys_pages()
    }
}

