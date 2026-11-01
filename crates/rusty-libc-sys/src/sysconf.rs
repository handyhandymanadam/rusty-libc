//! unistd.h configuration queries: sysconf, confstr, pathconf, fpathconf; and the sys/sysinfo.h
//! helpers they rest on (get_nprocs, get_nprocs_conf, get_phys_pages, get_avphys_pages).
//!
//! The sysconf table was taken from glibc 2.43 on x86-64 Linux (every name 0..=250 is compared
//! with the host in the tests). Run-time values: ARG_MAX (stack limit), CHILD_MAX, OPEN_MAX and
//! SIGQUEUE_MAX (rlimits), NGROUPS_MAX (/proc), processor counts (/sys, /proc/stat,
//! sched_getaffinity), memory (sysinfo), cache geometry (cpuid), signal stack sizes (auxv).
use crate::unistd::{self, EBADF, EINVAL, ENOENT, ENOSYS, fail, nr};
use core::arch::x86_64::CpuidResult;
use core::ffi::{c_char, c_int, c_long};
use crate::kernel::plain;
use rusty_libc_core::sync_cell::SyncCell;
use rusty_libc_core::{Errno, errno, syscall};

// ---- the names (from <bits/confname.h>)
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

const E: i64 = i64::MIN; // EINVAL
const D: i64 = i64::MIN + 1; // computed at run time

/// sysconf values by name 0..=250 (glibc 2.43, x86-64 Linux). -1 means "no limit / unsupported".
static TABLE: [i64; 251] = [
    D, // 0 SC_ARG_MAX
    D, // 1 SC_CHILD_MAX
    100, // 2 SC_CLK_TCK
    D, // 3 SC_NGROUPS_MAX
    D, // 4 SC_OPEN_MAX
    16, // 5 SC_STREAM_MAX
    -1, // 6 SC_TZNAME_MAX
    1, // 7 SC_JOB_CONTROL
    1, // 8 SC_SAVED_IDS
    200809, // 9 SC_REALTIME_SIGNALS
    200809, // 10 SC_PRIORITY_SCHEDULING
    200809, // 11 SC_TIMERS
    200809, // 12 SC_ASYNCHRONOUS_IO
    200809, // 13 SC_PRIORITIZED_IO
    200809, // 14 SC_SYNCHRONIZED_IO
    200809, // 15 SC_FSYNC
    200809, // 16 SC_MAPPED_FILES
    200809, // 17 SC_MEMLOCK
    200809, // 18 SC_MEMLOCK_RANGE
    200809, // 19 SC_MEMORY_PROTECTION
    200809, // 20 SC_MESSAGE_PASSING
    200809, // 21 SC_SEMAPHORES
    200809, // 22 SC_SHARED_MEMORY_OBJECTS
    -1, // 23 SC_AIO_LISTIO_MAX
    -1, // 24 SC_AIO_MAX
    20, // 25 SC_AIO_PRIO_DELTA_MAX
    2147483647, // 26 SC_DELAYTIMER_MAX
    -1, // 27 SC_MQ_OPEN_MAX
    32768, // 28 SC_MQ_PRIO_MAX
    200809, // 29 SC_VERSION
    4096, // 30 SC_PAGESIZE
    32, // 31 SC_RTSIG_MAX
    -1, // 32 SC_SEM_NSEMS_MAX
    2147483647, // 33 SC_SEM_VALUE_MAX
    D, // 34 SC_SIGQUEUE_MAX
    -1, // 35 SC_TIMER_MAX
    99, // 36 SC_BC_BASE_MAX
    2048, // 37 SC_BC_DIM_MAX
    99, // 38 SC_BC_SCALE_MAX
    1000, // 39 SC_BC_STRING_MAX
    255, // 40 SC_COLL_WEIGHTS_MAX
    E, // 41 SC_EQUIV_CLASS_MAX
    32, // 42 SC_EXPR_NEST_MAX
    2048, // 43 SC_LINE_MAX
    32767, // 44 SC_RE_DUP_MAX
    2048, // 45 SC_CHARCLASS_NAME_MAX
    200809, // 46 SC_2_VERSION
    200809, // 47 SC_2_C_BIND
    200809, // 48 SC_2_C_DEV
    -1, // 49 SC_2_FORT_DEV
    -1, // 50 SC_2_FORT_RUN
    200809, // 51 SC_2_SW_DEV
    200809, // 52 SC_2_LOCALEDEF
    -1, // 53 SC_PII
    -1, // 54 SC_PII_XTI
    -1, // 55 SC_PII_SOCKET
    -1, // 56 SC_PII_INTERNET
    -1, // 57 SC_PII_OSI
    -1, // 58 SC_POLL
    -1, // 59 SC_SELECT
    1024, // 60 SC_IOV_MAX
    -1, // 61 SC_PII_INTERNET_STREAM
    -1, // 62 SC_PII_INTERNET_DGRAM
    -1, // 63 SC_PII_OSI_COTS
    -1, // 64 SC_PII_OSI_CLTS
    -1, // 65 SC_PII_OSI_M
    -1, // 66 SC_T_IOV_MAX
    200809, // 67 SC_THREADS
    200809, // 68 SC_THREAD_SAFE_FUNCTIONS
    1024, // 69 SC_GETGR_R_SIZE_MAX
    1024, // 70 SC_GETPW_R_SIZE_MAX
    256, // 71 SC_LOGIN_NAME_MAX
    32, // 72 SC_TTY_NAME_MAX
    4, // 73 SC_THREAD_DESTRUCTOR_ITERATIONS
    1024, // 74 SC_THREAD_KEYS_MAX
    16384, // 75 SC_THREAD_STACK_MIN
    -1, // 76 SC_THREAD_THREADS_MAX
    200809, // 77 SC_THREAD_ATTR_STACKADDR
    200809, // 78 SC_THREAD_ATTR_STACKSIZE
    200809, // 79 SC_THREAD_PRIORITY_SCHEDULING
    200809, // 80 SC_THREAD_PRIO_INHERIT
    200809, // 81 SC_THREAD_PRIO_PROTECT
    200809, // 82 SC_THREAD_PROCESS_SHARED
    D, // 83 SC_NPROCESSORS_CONF
    D, // 84 SC_NPROCESSORS_ONLN
    D, // 85 SC_PHYS_PAGES
    D, // 86 SC_AVPHYS_PAGES
    2147483647, // 87 SC_ATEXIT_MAX
    8192, // 88 SC_PASS_MAX
    700, // 89 SC_XOPEN_VERSION
    4, // 90 SC_XOPEN_XCU_VERSION
    1, // 91 SC_XOPEN_UNIX
    -1, // 92 SC_XOPEN_CRYPT
    1, // 93 SC_XOPEN_ENH_I18N
    1, // 94 SC_XOPEN_SHM
    200809, // 95 SC_2_CHAR_TERM
    200809, // 96 SC_2_C_VERSION
    -1, // 97 SC_2_UPE
    1, // 98 SC_XOPEN_XPG2
    1, // 99 SC_XOPEN_XPG3
    1, // 100 SC_XOPEN_XPG4
    8, // 101 SC_CHAR_BIT
    127, // 102 SC_CHAR_MAX
    -128, // 103 SC_CHAR_MIN
    2147483647, // 104 SC_INT_MAX
    -2147483648, // 105 SC_INT_MIN
    64, // 106 SC_LONG_BIT
    32, // 107 SC_WORD_BIT
    16, // 108 SC_MB_LEN_MAX
    20, // 109 SC_NZERO
    32767, // 110 SC_SSIZE_MAX
    127, // 111 SC_SCHAR_MAX
    -128, // 112 SC_SCHAR_MIN
    32767, // 113 SC_SHRT_MAX
    -32768, // 114 SC_SHRT_MIN
    255, // 115 SC_UCHAR_MAX
    4294967295, // 116 SC_UINT_MAX
    -1, // 117 SC_ULONG_MAX
    65535, // 118 SC_USHRT_MAX
    4096, // 119 SC_NL_ARGMAX
    2048, // 120 SC_NL_LANGMAX
    2147483647, // 121 SC_NL_MSGMAX
    2147483647, // 122 SC_NL_NMAX
    2147483647, // 123 SC_NL_SETMAX
    2147483647, // 124 SC_NL_TEXTMAX
    D, // 125 SC_XBS5_ILP32_OFF32 (spec file, see ilp32_env)
    D, // 126 SC_XBS5_ILP32_OFFBIG (spec file, see ilp32_env)
    1, // 127 SC_XBS5_LP64_OFF64
    -1, // 128 SC_XBS5_LPBIG_OFFBIG
    1, // 129 SC_XOPEN_LEGACY
    1, // 130 SC_XOPEN_REALTIME
    1, // 131 SC_XOPEN_REALTIME_THREADS
    200809, // 132 SC_ADVISORY_INFO
    200809, // 133 SC_BARRIERS
    -1, // 134 SC_BASE
    -1, // 135 SC_C_LANG_SUPPORT
    -1, // 136 SC_C_LANG_SUPPORT_R
    200809, // 137 SC_CLOCK_SELECTION
    200809, // 138 SC_CPUTIME
    200809, // 139 SC_THREAD_CPUTIME
    -1, // 140 SC_DEVICE_IO
    -1, // 141 SC_DEVICE_SPECIFIC
    -1, // 142 SC_DEVICE_SPECIFIC_R
    -1, // 143 SC_FD_MGMT
    -1, // 144 SC_FIFO
    -1, // 145 SC_PIPE
    -1, // 146 SC_FILE_ATTRIBUTES
    -1, // 147 SC_FILE_LOCKING
    -1, // 148 SC_FILE_SYSTEM
    200809, // 149 SC_MONOTONIC_CLOCK
    -1, // 150 SC_MULTI_PROCESS
    -1, // 151 SC_SINGLE_PROCESS
    -1, // 152 SC_NETWORKING
    200809, // 153 SC_READER_WRITER_LOCKS
    200809, // 154 SC_SPIN_LOCKS
    1, // 155 SC_REGEXP
    -1, // 156 SC_REGEX_VERSION
    1, // 157 SC_SHELL
    -1, // 158 SC_SIGNALS
    200809, // 159 SC_SPAWN
    -1, // 160 SC_SPORADIC_SERVER
    -1, // 161 SC_THREAD_SPORADIC_SERVER
    -1, // 162 SC_SYSTEM_DATABASE
    -1, // 163 SC_SYSTEM_DATABASE_R
    200809, // 164 SC_TIMEOUTS
    -1, // 165 SC_TYPED_MEMORY_OBJECTS
    -1, // 166 SC_USER_GROUPS
    -1, // 167 SC_USER_GROUPS_R
    -1, // 168 SC_2_PBS
    -1, // 169 SC_2_PBS_ACCOUNTING
    -1, // 170 SC_2_PBS_LOCATE
    -1, // 171 SC_2_PBS_MESSAGE
    -1, // 172 SC_2_PBS_TRACK
    -1, // 173 SC_SYMLOOP_MAX
    -1, // 174 SC_STREAMS
    -1, // 175 SC_2_PBS_CHECKPOINT
    D, // 176 SC_V6_ILP32_OFF32 (spec file, see ilp32_env)
    D, // 177 SC_V6_ILP32_OFFBIG (spec file, see ilp32_env)
    1, // 178 SC_V6_LP64_OFF64
    -1, // 179 SC_V6_LPBIG_OFFBIG
    64, // 180 SC_HOST_NAME_MAX
    -1, // 181 SC_TRACE
    -1, // 182 SC_TRACE_EVENT_FILTER
    -1, // 183 SC_TRACE_INHERIT
    -1, // 184 SC_TRACE_LOG
    D, // 185 SC_LEVEL1_ICACHE_SIZE
    D, // 186 SC_LEVEL1_ICACHE_ASSOC
    D, // 187 SC_LEVEL1_ICACHE_LINESIZE
    D, // 188 SC_LEVEL1_DCACHE_SIZE
    D, // 189 SC_LEVEL1_DCACHE_ASSOC
    D, // 190 SC_LEVEL1_DCACHE_LINESIZE
    D, // 191 SC_LEVEL2_CACHE_SIZE
    D, // 192 SC_LEVEL2_CACHE_ASSOC
    D, // 193 SC_LEVEL2_CACHE_LINESIZE
    D, // 194 SC_LEVEL3_CACHE_SIZE
    D, // 195 SC_LEVEL3_CACHE_ASSOC
    D, // 196 SC_LEVEL3_CACHE_LINESIZE
    D, // 197 SC_LEVEL4_CACHE_SIZE
    D, // 198 SC_LEVEL4_CACHE_ASSOC
    D, // 199 SC_LEVEL4_CACHE_LINESIZE
    E, // 200 ?
    E, // 201 ?
    E, // 202 ?
    E, // 203 ?
    E, // 204 ?
    E, // 205 ?
    E, // 206 ?
    E, // 207 ?
    E, // 208 ?
    E, // 209 ?
    E, // 210 ?
    E, // 211 ?
    E, // 212 ?
    E, // 213 ?
    E, // 214 ?
    E, // 215 ?
    E, // 216 ?
    E, // 217 ?
    E, // 218 ?
    E, // 219 ?
    E, // 220 ?
    E, // 221 ?
    E, // 222 ?
    E, // 223 ?
    E, // 224 ?
    E, // 225 ?
    E, // 226 ?
    E, // 227 ?
    E, // 228 ?
    E, // 229 ?
    E, // 230 ?
    E, // 231 ?
    E, // 232 ?
    E, // 233 ?
    E, // 234 ?
    200809, // 235 SC_IPV6
    200809, // 236 SC_RAW_SOCKETS
    D, // 237 SC_V7_ILP32_OFF32 (spec file, see ilp32_env)
    D, // 238 SC_V7_ILP32_OFFBIG (spec file, see ilp32_env)
    1, // 239 SC_V7_LP64_OFF64
    -1, // 240 SC_V7_LPBIG_OFFBIG
    E, // 241 SC_SS_REPL_MAX
    -1, // 242 SC_TRACE_EVENT_NAME_MAX
    -1, // 243 SC_TRACE_NAME_MAX
    -1, // 244 SC_TRACE_SYS_MAX
    -1, // 245 SC_TRACE_USER_EVENT_MAX
    -1, // 246 SC_XOPEN_STREAMS
    E, // 247 SC_THREAD_ROBUST_PRIO_INHERIT
    E, // 248 SC_THREAD_ROBUST_PRIO_PROTECT
    D, // 249 SC_MINSIGSTKSZ
    D, // 250 SC_SIGSTKSZ
];

const RLIMIT_STACK: c_int = 3;
const RLIMIT_NPROC: c_int = 6;
const RLIMIT_SIGPENDING: c_int = 11;
const RLIM_INFINITY: u64 = u64::MAX;

fn getrlimit(res: c_int) -> Option<u64> {
    let mut lim = [0u64; 2];
    // SAFETY: no new limit; the kernel writes one `struct rlimit` (two words) into the local `lim`.
    let r = unsafe { syscall::syscall4(nr::PRLIMIT64, 0, res as usize, 0, lim.as_mut_ptr() as usize) };
    if r == 0 { Some(lim[0]) } else { None }
}

/// Read up to `buf.len()` bytes of a file; the count read (0 if it cannot be opened).
fn read_file(path: &core::ffi::CStr, buf: &mut [u8]) -> usize {
    let fd = crate::kernel::open_nocancel(path, 0o2000000, 0);
    if syscall::check(fd).is_err() {
        return 0;
    }
    let mut n = 0;
    while n < buf.len() {
        match syscall::check(crate::kernel::read_nocancel(fd, &mut buf[n..])) {
            Ok(0) | Err(_) => break,
            Ok(k) => n += k,
        }
    }
    plain!(nr::CLOSE, fd);
    n
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

/// get_nprocs(3): online processors (rusty-libc-rs-core's `cpus::online`, glibc 2.43's steps; the exported symbol is
/// misc.rs's, the same function).
pub extern "C" fn get_nprocs() -> c_int {
    rusty_libc_rs_core::cpus::online()
}

/// get_nprocs_conf(3): configured processors (rusty-libc-rs-core's `cpus::configured`).
pub extern "C" fn get_nprocs_conf() -> c_int {
    rusty_libc_rs_core::cpus::configured()
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
    // SAFETY: the kernel writes one `struct sysinfo` into the local `si`.
    unsafe { syscall::syscall1(nr::SYSINFO, &mut si as *mut SysInfo as usize) };
    si
}

/// get_phys_pages(3): physical memory in pages.
pub extern "C" fn get_phys_pages() -> c_long {
    let si = sysinfo();
    mempages(si.totalram, si.mem_unit)
}

/// get_avphys_pages(3): free physical memory in pages.
pub extern "C" fn get_avphys_pages() -> c_long {
    let si = sysinfo();
    mempages(si.freeram, si.mem_unit)
}

// ---- cache geometry (x86 cpuid, as glibc's handle_amd; Intel from the deterministic leaf 4)

// ---- the CPUID leaves of the cache values, as at process start
//
// glibc computes the cache values once, when the process starts (init_cpu_features / dl_init_cacheinfo), so sysconf reports
// the caches of the core the process started on. On a hybrid CPU (Intel's P- and E-cores have different L1 caches) a
// process the scheduler moves to the other kind of core would otherwise see other values. The startup code
// (rusty_libc_core::start::run_hooks_auxv) calls `__rusty_libc_init_cacheinfo`, which keeps the few CPUID leaves the cache
// code reads (about 7, a few hundred cycles each; recomputing every value at startup would take about 70); a program that
// did not run our startup code (a Rust test binary) takes the snapshot at its first cache query.

const SNAP_MAX: usize = 24;
static SNAP_STATE: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0); // 0 none, 1 being taken, 2 ready
/// The leaves (leaf, subleaf, eax..edx) and how many are used. Synchronisation: written once, by the thread that moved
/// SNAP_STATE from 0 to 1, before its Release store of 2; read only after an Acquire load of 2; never written again.
type Snapshot = ([(u32, u32, [u32; 4]); SNAP_MAX], usize);
static SNAP: SyncCell<Snapshot> = SyncCell::new(([(0, 0, [0; 4]); SNAP_MAX], 0));

fn cpuid_now(leaf: u32, sub: u32) -> CpuidResult {
    core::arch::x86_64::__cpuid_count(leaf, sub)
}

/// Keep the CPUID leaves the cache values come from (startup hook; also run by the first cache query without one).
#[unsafe(no_mangle)]
pub extern "C" fn __rusty_libc_init_cacheinfo() {
    use core::sync::atomic::Ordering::{Acquire, Release};
    if SNAP_STATE.compare_exchange(0, 1, Acquire, Acquire).is_err() {
        return;
    }
    let mut t = [(0u32, 0u32, [0u32; 4]); SNAP_MAX];
    let mut n = 0;
    let mut keep = |leaf: u32, sub: u32| -> CpuidResult {
        let r = cpuid_now(leaf, sub);
        if n < SNAP_MAX {
            t[n] = (leaf, sub, [r.eax, r.ebx, r.ecx, r.edx]);
            n += 1;
        }
        r
    };
    let r0 = keep(0, 0);
    let v = [r0.ebx, r0.edx, r0.ecx];
    if v == [0x756e_6547, 0x4965_6e69, 0x6c65_746e] {
        // GenuineIntel: leaf 2, and leaf 4 up to its terminating entry
        if r0.eax >= 2 {
            keep(2, 0);
        }
        if r0.eax >= 4 {
            for i in 0..16 {
                if keep(4, i).eax & 0x1f == 0 {
                    break;
                }
            }
        }
    } else if v == [0x6874_7541, 0x6974_6e65, 0x444d_4163] || v == [0x6f67_7948, 0x656e_6975, 0x6e65_4965] {
        // AuthenticAMD, HygonGenuine
        keep(1, 0);
        let max_ext = keep(0x8000_0000, 0).eax;
        for leaf in [0x8000_0005, 0x8000_0006, 0x8000_0008] {
            if max_ext >= leaf {
                keep(leaf, 0);
            }
        }
        if max_ext >= 0x8000_001d {
            for i in 0..4 {
                keep(0x8000_001d, i);
            }
        }
    }
    // SAFETY: only the thread that won the state change writes, once, before publishing with Release; no reader looks
    // before state 2.
    unsafe { SNAP.write((t, n)) };
    SNAP_STATE.store(2, Release);
}

/// A Rust test binary runs no startup code of ours: take the snapshot when it is loaded, close to where the host glibc in
/// the same process takes its own, so the tests that compare the two see the same core.
#[cfg(test)]
#[used]
#[unsafe(link_section = ".init_array")]
static TEST_INIT_CACHEINFO: extern "C" fn() = __rusty_libc_init_cacheinfo;

/// CPUID as at process start: from the snapshot when it holds the leaf, otherwise read now.
fn __cpuid_count(leaf: u32, sub: u32) -> CpuidResult {
    use core::sync::atomic::Ordering::Acquire;
    if SNAP_STATE.load(Acquire) == 0 {
        __rusty_libc_init_cacheinfo();
    }
    if SNAP_STATE.load(Acquire) == 2 {
        // SAFETY: written once before the Release store of state 2 (seen by the Acquire load above), never again.
        let (t, n): &Snapshot = unsafe { &*SNAP.as_ptr() };
        if let Some(&(_, _, r)) = t[..*n].iter().find(|e| e.0 == leaf && e.1 == sub) {
            return CpuidResult { eax: r[0], ebx: r[1], ecx: r[2], edx: r[3] };
        }
    }
    cpuid_now(leaf, sub)
}

fn __cpuid(leaf: u32) -> CpuidResult {
    __cpuid_count(leaf, 0)
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
    // legacy CPUs (and hypervisors that zero leaf 0x8000001d)
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

/// Intel caches as glibc 2.43's handle_intel: CPUID leaf 2 first; when it defers to leaf 4 (its first byte is not 1, or a
/// descriptor byte is 0xff, which every recent Intel CPU reports), leaf 4 lists every cache and a level it does not
/// list is -1 (e.g. no level 4 cache). CPUs that describe their caches with leaf 2 descriptor bytes only (before about
/// 2008) are read from leaf 4 as well (glibc's descriptor table is not kept), a level not found there being 0.
fn handle_intel(name: c_int) -> i64 {
    if __cpuid(0).eax < 2 {
        return -1;
    }
    let r2 = __cpuid(2);
    if r2.eax & 0xff != 1 {
        return intel_leaf4(name).unwrap_or(-1);
    }
    for reg in [r2.eax & 0xffff_ff00, r2.ebx, r2.ecx, r2.edx] {
        if reg & 0x8000_0000 != 0 {
            continue; // reserved
        }
        let mut v = reg;
        while v != 0 {
            if v & 0xff == 0xff {
                return intel_leaf4(name).unwrap_or(-1);
            }
            v >>= 8;
        }
    }
    if __cpuid(0).eax < 4 {
        return -1;
    }
    intel_leaf4(name).unwrap_or(0)
}

/// The value for `name` from CPUID leaf 4, or None when leaf 4 does not list that cache.
fn intel_leaf4(name: c_int) -> Option<i64> {
    // (level, 1 data / 2 instruction / 0 any) for each name, as glibc's intel_check_word
    let (level, want_type) = match name {
        SC_LEVEL1_ICACHE_SIZE | SC_LEVEL1_ICACHE_ASSOC | SC_LEVEL1_ICACHE_LINESIZE => (1, 2),
        SC_LEVEL1_DCACHE_SIZE | SC_LEVEL1_DCACHE_ASSOC | SC_LEVEL1_DCACHE_LINESIZE => (1, 1),
        SC_LEVEL2_CACHE_SIZE | SC_LEVEL2_CACHE_ASSOC | SC_LEVEL2_CACHE_LINESIZE => (2, 0),
        SC_LEVEL3_CACHE_SIZE | SC_LEVEL3_CACHE_ASSOC | SC_LEVEL3_CACHE_LINESIZE => (3, 0),
        _ => (4, 0),
    };
    for i in 0..64 {
        let r = __cpuid_count(4, i);
        let kind = r.eax & 0x1f;
        if kind == 0 {
            break;
        }
        let lvl = (r.eax >> 5) & 7;
        if lvl != level || (want_type != 0 && kind != want_type) {
            continue;
        }
        let ways = (r.ebx >> 22) as i64 + 1;
        let line = (r.ebx & 0xfff) as i64 + 1;
        let parts = ((r.ebx >> 12) & 0x3ff) as i64 + 1;
        let sets = r.ecx as i64 + 1;
        return Some(if is_assoc(name) {
            ways
        } else if is_line(name) {
            line
        } else {
            ways * parts * line * sets
        });
    }
    None
}

fn cache_sysconf(name: c_int) -> i64 {
    if name == SC_LEVEL1_ICACHE_ASSOC || name == SC_LEVEL4_CACHE_ASSOC || name == SC_LEVEL4_CACHE_LINESIZE {
        return -1; // glibc keeps no such value
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

/// AT_MINSIGSTKSZ from the auxiliary vector (the one the startup code saved, as glibc reads it from memory; no
/// /proc/self/auxv), else MINSIGSTKSZ.
fn minsigstksz() -> i64 {
    match rusty_libc_core::vdso::auxv_entry(51) {
        0 => 2048,
        v => v as i64,
    }
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

/// Is the 32-bit programming environment ILP32_OFF32 (`offbig` false) or ILP32_OFFBIG available? glibc on x86-64 does not
/// know (another libc on the system may provide it with `-m32`), so like its `__sysconf_check_spec` this asks whether
/// getconf has a spec file for it: `$GETCONF_DIR/POSIX_V6_ILP32_OFF32` or `..._OFFBIG` (the V6 name for the XBS5, V6 and
/// V7 queries alike; GETCONF_DIR is ignored in a set-user-ID program, as with secure_getenv; default
/// /usr/libexec/getconf). Fedora installs only the LP64 files, so both are normally absent (-1).
fn ilp32_env(offbig: bool) -> bool {
    let secure = rusty_libc_core::lock::at_secure().unwrap_or_else(|| {
        plain!(syscall::SYS_GETUID) != plain!(syscall::SYS_GETEUID) || plain!(104) != plain!(108) // getgid, getegid
    });
    let env = if secure {
        core::ptr::null_mut()
    } else {
        // SAFETY: getenv reads the environment, which no other thread changes meanwhile (the C rule for getenv).
        unsafe { rusty_libc_core::env::getenv(b"GETCONF_DIR") }
    };
    let dir: &[u8] = if env.is_null() {
        b"/usr/libexec/getconf"
    } else {
        // SAFETY: a non-NULL getenv result is a NUL-terminated string in the environment.
        unsafe { rusty_libc_core::ffi::cstr_bytes(env) }
    };
    let spec: &[u8] = if offbig { b"/POSIX_V6_ILP32_OFFBIG\0" } else { b"/POSIX_V6_ILP32_OFF32\0" };
    let mut path = [0u8; 4096];
    if dir.len() + spec.len() > path.len() {
        return false;
    }
    path[..dir.len()].copy_from_slice(dir);
    path[dir.len()..dir.len() + spec.len()].copy_from_slice(spec);
    let Ok(path) = core::ffi::CStr::from_bytes_until_nul(&path) else { return false };
    let mut st = [0u64; 18]; // struct stat (144 bytes)
    // (a raw system call: errno stays as it was, as glibc restores it)
    let r = crate::kernel::fstatat(unistd::AT_FDCWD as usize, path, &mut st, 0);
    r <= usize::MAX - 4095
}

/// The string for `confstr(name)` without the NUL, or `None` for an unknown name: the table and rules are the Rust face's
/// (rusty-libc-rs-core `confstr`, FIXLIST #127: one implementation for both faces); this face supplies the ILP32 probe.
// kept out of line, as before the move (two callers; `confstr` stays small)
#[inline(never)]
fn confstr_str(name: c_int) -> Option<&'static [u8]> {
    rusty_libc_rs_core::confstr::value(name, ilp32_env)
}

/// The value of `sysconf(name)`: `Ok(-1)` for "no limit / not supported" (errno untouched),
/// `Err(errno)` for an unknown name.
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
        SC_XBS5_ILP32_OFF32 | SC_V6_ILP32_OFF32 | SC_V7_ILP32_OFF32 => return Ok(if ilp32_env(false) { 1 } else { -1 }),
        SC_XBS5_ILP32_OFFBIG | SC_V6_ILP32_OFFBIG | SC_V7_ILP32_OFFBIG => return Ok(if ilp32_env(true) { 1 } else { -1 }),
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

/// glibc's internal name for `sysconf`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn __sysconf(name: c_int) -> c_long {
    sysconf(name)
}

/// sysconf(3).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn sysconf(name: c_int) -> c_long {
    match sysconf_value(name) {
        Ok(v) => v as c_long,
        Err(e) => fail(e) as c_long,
    }
}

// ---------------------------------------------------------------- confstr

/// confstr(3): the string (with its NUL) is truncated to `len`; the full length with the NUL is
/// returned; unknown names give 0 with errno EINVAL.
///
/// # Safety
/// `buf` must be NULL or valid for `len` bytes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn confstr(name: c_int, buf: *mut c_char, len: usize) -> usize {
    let Some(s) = confstr_str(name) else {
        errno::set(EINVAL);
        return 0;
    };
    let total = s.len() + 1;
    if len > 0 && !buf.is_null() {
        // SAFETY: `buf` is not NULL, so it has `len` writable bytes (contract).
        let out = unsafe { rusty_libc_core::ffi::bytes_mut(buf.cast::<u8>(), len) };
        let n = s.len().min(len - 1);
        out[..n].copy_from_slice(&s[..n]);
        out[n] = 0;
    }
    total
}

// ---------------------------------------------------------------- pathconf, fpathconf

const LINUX_LINK_MAX: i64 = 127;
const EXT2_LINK_MAX: i64 = 32000;
const EXT4_LINK_MAX: i64 = 65000;

fn magic_link_max(t: i64) -> Option<i64> {
    Some(match t as u64 & 0xffff_ffff {
        0xf2f5_2010 => 32000,                // f2fs
        0x137f | 0x138f => 250,              // minix
        0x2468 | 0x2478 => 65530,            // minix v2
        0x012f_f7b4 => 126,                  // xenix
        0x012f_f7b5 | 0x012f_f7b6 => 126,    // sysv
        0x012f_f7b7 => 10000,                // coherent
        0x0001_1954 | 0x5419_0100 => 32000,  // ufs
        0x5265_4973 => 64535,                // reiserfs
        0x5846_5342 => 2147483647,           // xfs
        0x0bd0_0bd0 => EXT4_LINK_MAX,        // lustre
        0x9123_683e => 65535,                // btrfs
        _ => return None,
    })
}

/// ext2, ext3 or ext4 (same magic): ext4 allows more links; ask sysfs, then /proc/mounts.
/// # Safety
/// `path` is NULL (then `fd` is used) or a NUL-terminated string.
unsafe fn distinguish_ext(path: *const c_char, fd: c_int) -> i64 {
    let mut st = crate::stat::Stat::zeroed();
    let r = if path.is_null() {
        unistd::rc(crate::kernel::fstat(fd as usize, &mut st))
    } else {
        // SAFETY: `path` is a C string (contract); `st` is a local.
        unsafe { crate::stat::stat(path, &mut st) }
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
    // SAFETY: `link` is NUL-terminated (at most 15 + 10 + 1 + 10 bytes of 64, the rest zeros) and only read; the kernel
    // writes at most `target.len()` bytes into the local `target`.
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
        // SAFETY: `p` is NUL-terminated (13 + fewer than 4096 - 13 bytes, the rest zeros).
        let ok = unsafe { unistd::access(p.as_ptr().cast(), 0) } == 0;
        return if ok { EXT4_LINK_MAX } else { EXT2_LINK_MAX };
    }
    // no sysfs: look for the file system in /proc/mounts
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
        // SAFETY: `d` is NUL-terminated (at most 4095 bytes written of 4096) and only read; `fs` is a local.
        if unsafe { crate::stat::stat(d.as_ptr().cast(), &mut fs) } >= 0 && fs.st_dev == st.st_dev {
            if ty == b"ext4" {
                result = EXT4_LINK_MAX;
            }
            break;
        }
    }
    result
}

/// # Safety
/// `path` is NULL (then `fd` is used) or a NUL-terminated string.
unsafe fn statfs_link_max(r: Result<crate::stat::Statfs, Errno>, path: *const c_char, fd: c_int) -> i64 {
    match r {
        Err(Errno(ENOSYS)) => LINUX_LINK_MAX,
        Err(e) => fail(e.0) as i64,
        Ok(fs) => {
            if fs.f_type as u64 & 0xffff_ffff == 0xef53 {
                // SAFETY: the caller's contract.
                return unsafe { distinguish_ext(path, fd) };
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

/// The generic part shared by pathconf and fpathconf; `fs` yields the statfs of the object.
/// `fd_errors`: fpathconf maps ENODEV to EINVAL for NAME_MAX.
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

/// # Safety
/// `path` is a NUL-terminated string (the statfs queries also accept a pointer the kernel faults on: EFAULT).
unsafe fn pathconf_value(path: *const c_char, name: c_int) -> i64 {
    // SAFETY: `path` is the caller's C string, which the kernel only reads (EFAULT for a bad one).
    let fs = || unsafe { crate::stat::statfs_path(path) };
    match name {
        // SAFETY: `path` is a C string (contract).
        PC_LINK_MAX => return unsafe { statfs_link_max(fs(), path, -1) },
        PC_FILESIZEBITS => return statfs_filesize_max(fs()),
        PC_2_SYMLINKS => return statfs_symlinks(fs()),
        PC_CHOWN_RESTRICTED => return statfs_chown_restricted(fs()),
        _ => {}
    }
    // SAFETY: `path` is a C string (contract), so its first byte is readable.
    if unsafe { *path } == 0 {
        return fail(ENOENT) as i64;
    }
    if name == PC_ASYNC_IO {
        let mut st = crate::stat::Stat::zeroed();
        // SAFETY: `path` is a C string (contract); `st` is a local.
        let ok = unsafe { crate::stat::stat(path, &mut st) } == 0;
        return async_io_conf(st, ok);
    }
    posix_conf(name, &fs, false)
}

fn fpathconf_value(fd: c_int, name: c_int) -> i64 {
    let fs = || crate::stat::statfs_fd(fd);
    match name {
        // SAFETY: no path: the descriptor is used.
        PC_LINK_MAX => return unsafe { statfs_link_max(fs(), core::ptr::null(), fd) },
        PC_FILESIZEBITS => return statfs_filesize_max(fs()),
        PC_2_SYMLINKS => return statfs_symlinks(fs()),
        PC_CHOWN_RESTRICTED => return statfs_chown_restricted(fs()),
        PC_ASYNC_IO => {
            let mut st = crate::stat::Stat::zeroed();
            let ok = unistd::rc(crate::kernel::fstat(fd as usize, &mut st)) == 0;
            return async_io_conf(st, ok);
        }
        _ => {}
    }
    if fd < 0 {
        return fail(EBADF) as i64;
    }
    posix_conf(name, &fs, true)
}

/// pathconf(3): -1 with errno untouched means "no limit"; -1 with errno set is an error
/// (ENOENT for a missing or empty path, EINVAL for an unknown name, ...).
///
/// # Safety
/// `path` must be NUL-terminated.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pathconf(path: *const c_char, name: c_int) -> c_long {
    // SAFETY: the caller's contract is pathconf_value's.
    unsafe { pathconf_value(path, name) as c_long }
}

/// fpathconf(3).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn fpathconf(fd: c_int, name: c_int) -> c_long {
    fpathconf_value(fd, name) as c_long
}

// ---------------------------------------------------------------- Rust API

/// The same queries returning `Result<Option<i64>, Errno>`: `None` is "no limit / unsupported"
/// (the C functions' -1 with errno unchanged).
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
        // SAFETY: `path` is a NUL-terminated string.
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
    /// The string for `confstr(name)` without the NUL, or `None` for an unknown name.
    pub fn confstr(name: i32) -> Option<&'static [u8]> {
        confstr_str(name)
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

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
    use super::*;
    use crate::unistd::testutil::*;
    use crate::unistd;
    use core::ffi::CStr;
    use core::ptr::null_mut;

    unsafe extern "C" {
        #[link_name = "get_nprocs"]
        fn host_get_nprocs() -> c_int;
        #[link_name = "get_nprocs_conf"]
        fn host_get_nprocs_conf() -> c_int;
        #[link_name = "get_phys_pages"]
        fn host_get_phys_pages() -> c_long;
        #[link_name = "get_avphys_pages"]
        fn host_get_avphys_pages() -> c_long;
    }

    #[test]
    fn constants_match_the_host() {
        assert_eq!(SC_ARG_MAX, libc::_SC_ARG_MAX);
        assert_eq!(SC_NPROCESSORS_ONLN, libc::_SC_NPROCESSORS_ONLN);
        assert_eq!(SC_PHYS_PAGES, libc::_SC_PHYS_PAGES);
        assert_eq!(SC_LEVEL1_ICACHE_SIZE, libc::_SC_LEVEL1_ICACHE_SIZE);
        assert_eq!(SC_LEVEL4_CACHE_LINESIZE, libc::_SC_LEVEL4_CACHE_LINESIZE);
        assert_eq!(SC_MINSIGSTKSZ, 249);
        assert_eq!(SC_SIGSTKSZ, 250);
        assert_eq!(SC_THREAD_ROBUST_PRIO_PROTECT, libc::_SC_THREAD_ROBUST_PRIO_PROTECT);
        assert_eq!(PC_LINK_MAX, libc::_PC_LINK_MAX);
        assert_eq!(PC_2_SYMLINKS, libc::_PC_2_SYMLINKS);
        assert_eq!(PC_ALLOC_SIZE_MIN, libc::_PC_ALLOC_SIZE_MIN);
        assert_eq!(CS_PATH, libc::_CS_PATH);
        assert_eq!(CS_GNU_LIBPTHREAD_VERSION, libc::_CS_GNU_LIBPTHREAD_VERSION);
        assert_eq!(CS_V7_ENV, 1149);
    }

    #[test]
    fn sysconf_agrees_with_the_host_for_every_name() {
        let _g = lock();
        for name in -5..=300 {
            if (SC_LEVEL1_ICACHE_SIZE..=SC_LEVEL4_CACHE_LINESIZE).contains(&name) {
                continue; // cache_values_agree_with_the_host_on_one_cpu
            }
            if name == SC_AVPHYS_PAGES {
                let ours = sysconf(name);
                let host = unsafe { libc::sysconf(name) };
                assert!(ours > 0 && ours as i64 <= sysconf(SC_PHYS_PAGES) as i64);
                // free memory moves between the two calls
                assert!((ours - host as c_long).abs() < sysconf(SC_PHYS_PAGES) / 20 + 1000, "{ours} vs {host}");
                continue;
            }
            same(&format!("sysconf({name})"), || sysconf(name) as i64, || unsafe { libc::sysconf(name) } as i64);
            if sysconf_value(name).is_err() {
                assert_eq!(errno::get(), EINVAL, "name {name}");
            }
        }
        // a few values spelled out
        assert_eq!(sysconf(SC_PAGESIZE), 4096);
        assert_eq!(sysconf(SC_CLK_TCK), 100);
        assert_eq!(sysconf(SC_NPROCESSORS_ONLN) as i32, unsafe { host_get_nprocs() });
        assert_eq!(sysconf(SC_OPEN_MAX), unistd::getdtablesize() as c_long);
        assert_eq!(sysconf(SC_VERSION), 200809);
        assert_eq!(sysconf(SC_TZNAME_MAX), -1);
    }

    /// The cache values are those of the core a process starts on (glibc's rule, ours too), and the P- and E-cores of a
    /// hybrid CPU have different L1 caches: host glibc takes its values in the loader, ours when this test binary's
    /// constructors run, and the scheduler may move a new process between the two. So the values are compared in a child
    /// started already pinned to one CPU, once on the first and once on the last CPU this process may use (a P-core and
    /// an E-core on an Intel hybrid laptop).
    #[test]
    fn cache_values_agree_with_the_host_on_one_cpu() {
        if std::env::var_os("RUSTY_LIBC_CACHE_CHILD").is_some() {
            for name in SC_LEVEL1_ICACHE_SIZE..=SC_LEVEL4_CACHE_LINESIZE {
                same(&format!("sysconf({name})"), || sysconf(name) as i64, || unsafe { libc::sysconf(name) } as i64);
            }
            return;
        }
        let mut set: libc::cpu_set_t = unsafe { core::mem::zeroed() };
        assert_eq!(unsafe { libc::sched_getaffinity(0, size_of::<libc::cpu_set_t>(), &mut set) }, 0);
        let cpus: Vec<usize> = (0..libc::CPU_SETSIZE as usize).filter(|&c| unsafe { libc::CPU_ISSET(c, &set) }).collect();
        let mut tried = vec![cpus[0], *cpus.last().unwrap()];
        tried.dedup();
        for cpu in tried {
            use std::os::unix::process::CommandExt;
            let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
            cmd.args(["--exact", "sysconf::tests::cache_values_agree_with_the_host_on_one_cpu", "--test-threads=1"]);
            cmd.env("RUSTY_LIBC_CACHE_CHILD", "1");
            unsafe {
                cmd.pre_exec(move || {
                    let mut one: libc::cpu_set_t = core::mem::zeroed();
                    libc::CPU_SET(cpu, &mut one);
                    libc::sched_setaffinity(0, size_of::<libc::cpu_set_t>(), &one);
                    Ok(())
                });
            }
            let out = cmd.output().unwrap();
            assert!(out.status.success(), "cpu {cpu}: {}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
            assert!(String::from_utf8_lossy(&out.stdout).contains("1 passed"), "cpu {cpu}: the child ran no test");
        }
    }

    /// Run `check` in a child after `setup` has changed an rlimit through the host libc.
    fn in_child_with_limit(res: libc::__rlimit_resource_t, soft: u64, check: fn() -> bool) {
        let st = run_child(move || unsafe {
            let mut h: libc::rlimit = core::mem::zeroed();
            libc::getrlimit(res, &mut h);
            let new = libc::rlimit { rlim_cur: soft.min(h.rlim_max), rlim_max: h.rlim_max };
            if libc::setrlimit(res, &new) != 0 {
                return 2;
            }
            if check() { 0 } else { 1 }
        });
        assert_eq!(exit_code(st), 0);
    }

    #[test]
    fn run_time_values_follow_the_limits() {
        let _g = lock();
        // ARG_MAX: stack limit / 4, at least 128 KiB, at most 6 MiB
        for stack in [100_000u64, 1 << 20, 4 << 20, 8 << 20, 64 << 20] {
            in_child_with_limit(libc::RLIMIT_STACK, stack, || sysconf(SC_ARG_MAX) as i64 == unsafe { libc::sysconf(libc::_SC_ARG_MAX) } as i64);
        }
        in_child_with_limit(libc::RLIMIT_STACK, 1 << 20, || sysconf(SC_ARG_MAX) == 262144);
        in_child_with_limit(libc::RLIMIT_STACK, 100_000, || sysconf(SC_ARG_MAX) == 131072);
        in_child_with_limit(libc::RLIMIT_NOFILE, 77, || sysconf(SC_OPEN_MAX) == 77 && unsafe { libc::sysconf(libc::_SC_OPEN_MAX) } == 77);
        in_child_with_limit(libc::RLIMIT_NPROC, 4321, || sysconf(SC_CHILD_MAX) == 4321 && unsafe { libc::sysconf(libc::_SC_CHILD_MAX) } == 4321);
        in_child_with_limit(libc::RLIMIT_SIGPENDING, 999, || sysconf(SC_SIGQUEUE_MAX) == 999 && unsafe { libc::sysconf(libc::_SC_SIGQUEUE_MAX) } == 999);
    }

    #[test]
    fn processor_and_memory_counts() {
        let _g = lock();
        assert_eq!(get_nprocs(), unsafe { host_get_nprocs() });
        assert_eq!(get_nprocs_conf(), unsafe { host_get_nprocs_conf() });
        assert_eq!(get_phys_pages(), unsafe { host_get_phys_pages() });
        let (a, b) = (get_avphys_pages(), unsafe { host_get_avphys_pages() });
        assert!(a > 0 && (a - b).abs() < get_phys_pages() / 20 + 1000, "{a} vs {b}");
        assert!(rs::nprocs_online() >= 1);
        assert!(rs::nprocs_configured() >= rs::nprocs_online());
        assert_eq!(rs::phys_pages(), get_phys_pages());
        assert!(rs::avphys_pages() > 0);
        // sched_getaffinity agrees with a restricted mask: one CPU in a child
        let st = run_child(|| unsafe {
            let mut set: libc::cpu_set_t = core::mem::zeroed();
            libc::CPU_SET(0, &mut set);
            if libc::sched_setaffinity(0, core::mem::size_of::<libc::cpu_set_t>(), &set) != 0 {
                return 2;
            }
            // the online count comes from sysfs, not the mask, like glibc
            if get_nprocs() != host_get_nprocs() { 1 } else { 0 }
        });
        assert_eq!(exit_code(st), 0);
        assert_eq!(rusty_libc_rs_core::cpus::from_affinity() as usize, rs::nprocs_online().min(rusty_libc_rs_core::cpus::from_affinity() as usize));
        assert!(rusty_libc_rs_core::cpus::from_proc_stat() >= 1);
    }

    #[test]
    fn sysfs_range_lists() {
        let _g = lock();
        let d = tmpdir("ranges");
        let check = |text: &str, want: i32| {
            let p = format!("{d}/r");
            std::fs::write(&p, text).unwrap();
            let c = cs(&p);
            assert_eq!(rusty_libc_rs_core::cpus::from_sysfs(&c), want, "{text:?}");
        };
        check("0\n", 1);
        check("0-3\n", 4);
        check("0,2,4-5\n", 4);
        check("0-7,9\n", 9);
        check("0-15", 16);
        check("5-5\n", 1);
        check("", 0);
        check("x\n", 0);
        check("3-1\n", 0);
        check("1-\n", 0);
        assert_eq!(rusty_libc_rs_core::cpus::from_sysfs(c"/nonexistent/online"), 0);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn mempages_formula() {
        assert_eq!(mempages(1000, 1), 1000 / 4096);
        assert_eq!(mempages(1000, 4096), 1000);
        assert_eq!(mempages(1000, 1024), 250);
        assert_eq!(mempages(1 << 20, 1), 256);
    }

    #[test]
    fn confstr_agrees_with_the_host() {
        let _g = lock();
        unsafe {
            for name in -1..=1200 {
                same(&format!("confstr({name}) size"), || confstr(name, null_mut(), 0) as i64, || libc::confstr(name, core::ptr::null_mut(), 0) as i64);
                let n = libc::confstr(name, core::ptr::null_mut(), 0);
                if n == 0 {
                    assert_eq!(confstr(name, null_mut(), 0), 0);
                    assert_eq!(errno::get(), EINVAL);
                    continue;
                }
                for len in [1usize, 2, 5, 9, 10, 12, 50, 64, 100] {
                    let mut a = [0x55 as c_char; 128];
                    let mut b = [0x55 as c_char; 128];
                    let ra = confstr(name, a.as_mut_ptr(), len);
                    let rb = libc::confstr(name, b.as_mut_ptr(), len);
                    assert_eq!(ra, rb, "confstr({name}, len {len})");
                    assert_eq!(a, b, "confstr({name}, len {len}) buffer");
                }
                // a buffer but zero length leaves it alone; NULL with a length too
                let mut a = [0x55 as c_char; 8];
                assert_eq!(confstr(name, a.as_mut_ptr(), 0), n);
                assert_eq!(a, [0x55 as c_char; 8]);
                assert_eq!(confstr(name, null_mut(), 8), n);
                assert_eq!(rs::confstr(name).map(|s| s.len() + 1), Some(n));
            }
            assert_eq!(rs::confstr(-1), None);
            assert_eq!(rs::confstr(CS_PATH), Some(&b"/usr/bin"[..]));
            let mut b = [0 as c_char; 32];
            assert_eq!(confstr(CS_GNU_LIBC_VERSION, b.as_mut_ptr(), 32), 11);
            assert_eq!(CStr::from_ptr(b.as_ptr()).to_str().unwrap(), "glibc 2.43");
        }
    }

    fn path_cases(d: &str) -> Vec<String> {
        let f = format!("{d}/file");
        std::fs::write(&f, b"x").unwrap();
        let _ = std::process::Command::new("mkfifo").arg(format!("{d}/fifo")).status();
        std::fs::create_dir_all(format!("{d}/dir")).unwrap();
        vec![
            "/".into(),
            "/tmp".into(),
            "/home".into(),
            "/proc".into(),
            "/proc/self/status".into(),
            "/dev".into(),
            "/dev/null".into(),
            "/dev/pts".into(),
            "/sys".into(),
            "/usr".into(),
            "/usr/bin/env".into(),
            "/run".into(),
            "/boot".into(),
            "/dev/shm".into(),
            "/nonexistent".into(),
            String::new(),
            f,
            format!("{d}/dir"),
            format!("{d}/fifo"),
            format!("{d}/file/child"),
        ]
    }

    #[test]
    fn pathconf_agrees_with_the_host() {
        let _g = lock();
        let d = tmpdir("pathconf");
        unsafe {
            for p in path_cases(&d) {
                let c = cs(&p);
                for name in -2..=25 {
                    same(&format!("pathconf({p:?}, {name})"), || pathconf(c.as_ptr(), name) as i64, || libc::pathconf(c.as_ptr(), name) as i64);
                }
            }
            assert_eq!(rs::pathconf(&cs("/"), PC_NAME_MAX), Ok(Some(255)));
            assert_eq!(rs::pathconf(&cs("/"), PC_MAX_CANON), Ok(Some(255)));
            assert_eq!(rs::pathconf(&cs("/"), PC_SYMLINK_MAX), Ok(None));
            assert_eq!(rs::pathconf(&cs("/nonexistent"), PC_NAME_MAX), Err(Errno(ENOENT)));
            assert_eq!(rs::pathconf(&cs("/nonexistent"), PC_LINK_MAX), Err(Errno(ENOENT)));
            assert_eq!(rs::pathconf(&cs("/"), 99), Err(Errno(EINVAL)));
            assert_eq!(rs::pathconf(&cs(""), PC_NAME_MAX), Err(Errno(ENOENT)));
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn fpathconf_agrees_with_the_host() {
        let _g = lock();
        let d = tmpdir("fpathconf");
        unsafe {
            let mut fds = vec![-1, 9999, 0, 1, 2];
            for p in path_cases(&d) {
                let c = cs(&p);
                let fd = libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOCTTY);
                if fd >= 0 {
                    fds.push(fd);
                }
                let pfd = libc::open(c.as_ptr(), libc::O_PATH);
                if pfd >= 0 {
                    fds.push(pfd);
                }
            }
            let mut p = [0i32; 2];
            unistd::pipe(p.as_mut_ptr());
            fds.push(p[0]);
            fds.push(p[1]);
            for &fd in &fds {
                for name in -2..=25 {
                    same(&format!("fpathconf({fd}, {name})"), || fpathconf(fd, name) as i64, || libc::fpathconf(fd, name) as i64);
                }
            }
            assert_eq!(rs::fpathconf(-1, PC_NAME_MAX), Err(Errno(EBADF)));
            assert_eq!(rs::fpathconf(p[0], PC_PIPE_BUF), Ok(Some(4096)));
            for &fd in &fds[5..] {
                unistd::close(fd);
            }
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn link_max_tables() {
        assert_eq!(magic_link_max(0xf2f52010), Some(32000)); // f2fs
        assert_eq!(magic_link_max(0x9123683e), Some(65535)); // btrfs
        assert_eq!(magic_link_max(0x58465342), Some(2147483647)); // xfs
        assert_eq!(magic_link_max(0x52654973), Some(64535)); // reiserfs
        assert_eq!(magic_link_max(0x137f), Some(250));
        assert_eq!(magic_link_max(0x2468), Some(65530));
        assert_eq!(magic_link_max(0x012ff7b7), Some(10000));
        assert_eq!(magic_link_max(0x01021994), None); // tmpfs: the generic 127
        assert_eq!(magic_link_max(0x6969), None);
        assert_eq!(unsafe { statfs_link_max(Err(Errno(ENOSYS)), core::ptr::null(), -1) }, 127);
        assert_eq!(statfs_filesize_max(Err(Errno(ENOSYS))), 32);
        assert_eq!(statfs_symlinks(Err(Errno(ENOSYS))), 1);
        assert_eq!(statfs_chown_restricted(Err(Errno(ENOSYS))), 1);
        let mut fs = crate::stat::Statfs { f_type: 0x9123683e, ..Default::default() };
        assert_eq!(statfs_filesize_max(Ok(fs)), 255);
        fs.f_type = 0xf2f52010;
        assert_eq!(statfs_filesize_max(Ok(fs)), 256);
        fs.f_type = 0xef53;
        assert_eq!(statfs_filesize_max(Ok(fs)), 64);
        fs.f_type = 0x4d44; // msdos
        assert_eq!(statfs_symlinks(Ok(fs)), 0);
        assert_eq!(statfs_filesize_max(Ok(fs)), 32);
        fs.f_type = 0x1cd1; // devpts
        assert_eq!(statfs_symlinks(Ok(fs)), 0);
        fs.f_type = 0x01021994;
        assert_eq!(statfs_symlinks(Ok(fs)), 1);
        assert_eq!(statfs_chown_restricted(Ok(fs)), 1);
    }

    #[test]
    fn ext_link_max_follows_sysfs_or_mounts() {
        let _g = lock();
        // whatever file system "/" is, the answer matches the host
        let mut st = crate::stat::Stat::zeroed();
        assert_eq!(unsafe { crate::stat::stat(c"/".as_ptr(), &mut st) }, 0);
        let ours = unsafe { distinguish_ext(c"/".as_ptr(), -1) };
        assert!(ours == 32000 || ours == 65000);
        let fd = unsafe { libc::open(c"/".as_ptr(), libc::O_RDONLY) };
        assert_eq!(unsafe { distinguish_ext(core::ptr::null(), fd) }, ours);
        unsafe { libc::close(fd) };
        assert_eq!(unsafe { distinguish_ext(c"/nonexistent".as_ptr(), -1) }, 32000);
        // a root on ext4 must say 65000 like glibc does
        let mut fs: libc::statfs = unsafe { core::mem::zeroed() };
        unsafe { libc::statfs(c"/".as_ptr(), &mut fs) };
        if fs.f_type as u64 == 0xef53 {
            assert_eq!(unsafe { libc::pathconf(c"/".as_ptr(), libc::_PC_LINK_MAX) } as i64, ours);
        }
    }

    #[test]
    fn rust_api() {
        let _g = lock();
        assert_eq!(rs::sysconf(SC_PAGESIZE), Ok(Some(4096)));
        assert_eq!(rs::sysconf(SC_TZNAME_MAX), Ok(None));
        assert_eq!(rs::sysconf(-1), Err(Errno(EINVAL)));
        assert_eq!(rs::sysconf(SC_EQUIV_CLASS_MAX), Err(Errno(EINVAL)));
        assert_eq!(rs::sysconf(1000), Err(Errno(EINVAL)));
        // the C function and sysconf_value agree
        for name in 0..=250 {
            match sysconf_value(name) {
                Ok(v) => assert_eq!(sysconf(name) as i64, v),
                Err(e) => assert_eq!(e, EINVAL),
            }
        }
    }

    #[test]
    fn cache_geometry_is_sane() {
        let _g = lock();
        // L1 data cache: size = ways * line * sets, so size is a multiple of ways * line
        let size = sysconf(SC_LEVEL1_DCACHE_SIZE);
        let ways = sysconf(SC_LEVEL1_DCACHE_ASSOC);
        let line = sysconf(SC_LEVEL1_DCACHE_LINESIZE);
        assert!(size > 0 && ways > 0 && line > 0);
        assert_eq!(size % (ways * line), 0);
        assert_eq!(sysconf(SC_LEVEL1_ICACHE_ASSOC), -1);
        assert_eq!(sysconf(SC_LEVEL4_CACHE_ASSOC), -1);
        assert_eq!(sysconf(SC_LEVEL4_CACHE_LINESIZE), -1);
        assert!(sysconf(SC_LEVEL2_CACHE_SIZE) >= size);
        assert!(minsigstksz() >= 2048);
        assert_eq!(sysconf(SC_MINSIGSTKSZ) as i64, minsigstksz());
        assert_eq!(sysconf(SC_SIGSTKSZ) as i64, (minsigstksz() * 4).max(8192));
    }
}
