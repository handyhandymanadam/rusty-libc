pub const ERRLIST: [&str; 135] = [
    "Success",
    "Operation not permitted",
    "No such file or directory",
    "No such process",
    "Interrupted system call",
    "Input/output error",
    "No such device or address",
    "Argument list too long",
    "Exec format error",
    "Bad file descriptor",
    "No child processes",
    "Resource temporarily unavailable",
    "Cannot allocate memory",
    "Permission denied",
    "Bad address",
    "Block device required",
    "Device or resource busy",
    "File exists",
    "Invalid cross-device link",
    "No such device",
    "Not a directory",
    "Is a directory",
    "Invalid argument",
    "Too many open files in system",
    "Too many open files",
    "Inappropriate ioctl for device",
    "Text file busy",
    "File too large",
    "No space left on device",
    "Illegal seek",
    "Read-only file system",
    "Too many links",
    "Broken pipe",
    "Numerical argument out of domain",
    "Numerical result out of range",
    "Resource deadlock avoided",
    "File name too long",
    "No locks available",
    "Function not implemented",
    "Directory not empty",
    "Too many levels of symbolic links",
    "",
    "No message of desired type",
    "Identifier removed",
    "Channel number out of range",
    "Level 2 not synchronized",
    "Level 3 halted",
    "Level 3 reset",
    "Link number out of range",
    "Protocol driver not attached",
    "No CSI structure available",
    "Level 2 halted",
    "Invalid exchange",
    "Invalid request descriptor",
    "Exchange full",
    "No anode",
    "Invalid request code",
    "Invalid slot",
    "",
    "Bad font file format",
    "Device not a stream",
    "No data available",
    "Timer expired",
    "Out of streams resources",
    "Machine is not on the network",
    "Package not installed",
    "Object is remote",
    "Link has been severed",
    "Advertise error",
    "Srmount error",
    "Communication error on send",
    "Protocol error",
    "Multihop attempted",
    "RFS specific error",
    "Bad message",
    "Value too large for defined data type",
    "Name not unique on network",
    "File descriptor in bad state",
    "Remote address changed",
    "Can not access a needed shared library",
    "Accessing a corrupted shared library",
    ".lib section in a.out corrupted",
    "Attempting to link in too many shared libraries",
    "Cannot exec a shared library directly",
    "Invalid or incomplete multibyte or wide character",
    "Interrupted system call should be restarted",
    "Streams pipe error",
    "Too many users",
    "Socket operation on non-socket",
    "Destination address required",
    "Message too long",
    "Protocol wrong type for socket",
    "Protocol not available",
    "Protocol not supported",
    "Socket type not supported",
    "Operation not supported",
    "Protocol family not supported",
    "Address family not supported by protocol",
    "Address already in use",
    "Cannot assign requested address",
    "Network is down",
    "Network is unreachable",
    "Network dropped connection on reset",
    "Software caused connection abort",
    "Connection reset by peer",
    "No buffer space available",
    "Transport endpoint is already connected",
    "Transport endpoint is not connected",
    "Cannot send after transport endpoint shutdown",
    "Too many references: cannot splice",
    "Connection timed out",
    "Connection refused",
    "Host is down",
    "No route to host",
    "Operation already in progress",
    "Operation now in progress",
    "Stale file handle",
    "Structure needs cleaning",
    "Not a XENIX named type file",
    "No XENIX semaphores available",
    "Is a named type file",
    "Remote I/O error",
    "Disk quota exceeded",
    "No medium found",
    "Wrong medium type",
    "Operation canceled",
    "Required key not available",
    "Key has expired",
    "Key has been revoked",
    "Key was rejected by service",
    "Owner died",
    "State not recoverable",
    "Operation not possible due to RF-kill",
    "Memory page has hardware error",
    "Inappropriate file type or format",
]; 

pub const SIGLIST: [&str; 65] = [
    "",
    "Hangup",
    "Interrupt",
    "Quit",
    "Illegal instruction",
    "Trace/breakpoint trap",
    "Aborted",
    "Bus error",
    "Floating point exception",
    "Killed",
    "User defined signal 1",
    "Segmentation fault",
    "User defined signal 2",
    "Broken pipe",
    "Alarm clock",
    "Terminated",
    "Stack fault",
    "Child exited",
    "Continued",
    "Stopped (signal)",
    "Stopped",
    "Stopped (tty input)",
    "Stopped (tty output)",
    "Urgent I/O condition",
    "CPU time limit exceeded",
    "File size limit exceeded",
    "Virtual timer expired",
    "Profiling timer expired",
    "Window changed",
    "I/O possible",
    "Power failure",
    "Bad system call",
    "",
    "",
    "Real-time signal 0",
    "Real-time signal 1",
    "Real-time signal 2",
    "Real-time signal 3",
    "Real-time signal 4",
    "Real-time signal 5",
    "Real-time signal 6",
    "Real-time signal 7",
    "Real-time signal 8",
    "Real-time signal 9",
    "Real-time signal 10",
    "Real-time signal 11",
    "Real-time signal 12",
    "Real-time signal 13",
    "Real-time signal 14",
    "Real-time signal 15",
    "Real-time signal 16",
    "Real-time signal 17",
    "Real-time signal 18",
    "Real-time signal 19",
    "Real-time signal 20",
    "Real-time signal 21",
    "Real-time signal 22",
    "Real-time signal 23",
    "Real-time signal 24",
    "Real-time signal 25",
    "Real-time signal 26",
    "Real-time signal 27",
    "Real-time signal 28",
    "Real-time signal 29",
    "Real-time signal 30",
];

pub const ERRNAMES: [&str; 135] = [
    "0",
    "EPERM",
    "ENOENT",
    "ESRCH",
    "EINTR",
    "EIO",
    "ENXIO",
    "E2BIG",
    "ENOEXEC",
    "EBADF",
    "ECHILD",
    "EAGAIN",
    "ENOMEM",
    "EACCES",
    "EFAULT",
    "ENOTBLK",
    "EBUSY",
    "EEXIST",
    "EXDEV",
    "ENODEV",
    "ENOTDIR",
    "EISDIR",
    "EINVAL",
    "ENFILE",
    "EMFILE",
    "ENOTTY",
    "ETXTBSY",
    "EFBIG",
    "ENOSPC",
    "ESPIPE",
    "EROFS",
    "EMLINK",
    "EPIPE",
    "EDOM",
    "ERANGE",
    "EDEADLK",
    "ENAMETOOLONG",
    "ENOLCK",
    "ENOSYS",
    "ENOTEMPTY",
    "ELOOP",
    "",
    "ENOMSG",
    "EIDRM",
    "ECHRNG",
    "EL2NSYNC",
    "EL3HLT",
    "EL3RST",
    "ELNRNG",
    "EUNATCH",
    "ENOCSI",
    "EL2HLT",
    "EBADE",
    "EBADR",
    "EXFULL",
    "ENOANO",
    "EBADRQC",
    "EBADSLT",
    "",
    "EBFONT",
    "ENOSTR",
    "ENODATA",
    "ETIME",
    "ENOSR",
    "ENONET",
    "ENOPKG",
    "EREMOTE",
    "ENOLINK",
    "EADV",
    "ESRMNT",
    "ECOMM",
    "EPROTO",
    "EMULTIHOP",
    "EDOTDOT",
    "EBADMSG",
    "EOVERFLOW",
    "ENOTUNIQ",
    "EBADFD",
    "EREMCHG",
    "ELIBACC",
    "ELIBBAD",
    "ELIBSCN",
    "ELIBMAX",
    "ELIBEXEC",
    "EILSEQ",
    "ERESTART",
    "ESTRPIPE",
    "EUSERS",
    "ENOTSOCK",
    "EDESTADDRREQ",
    "EMSGSIZE",
    "EPROTOTYPE",
    "ENOPROTOOPT",
    "EPROTONOSUPPORT",
    "ESOCKTNOSUPPORT",
    "EOPNOTSUPP",
    "EPFNOSUPPORT",
    "EAFNOSUPPORT",
    "EADDRINUSE",
    "EADDRNOTAVAIL",
    "ENETDOWN",
    "ENETUNREACH",
    "ENETRESET",
    "ECONNABORTED",
    "ECONNRESET",
    "ENOBUFS",
    "EISCONN",
    "ENOTCONN",
    "ESHUTDOWN",
    "ETOOMANYREFS",
    "ETIMEDOUT",
    "ECONNREFUSED",
    "EHOSTDOWN",
    "EHOSTUNREACH",
    "EALREADY",
    "EINPROGRESS",
    "ESTALE",
    "EUCLEAN",
    "ENOTNAM",
    "ENAVAIL",
    "EISNAM",
    "EREMOTEIO",
    "EDQUOT",
    "ENOMEDIUM",
    "EMEDIUMTYPE",
    "ECANCELED",
    "ENOKEY",
    "EKEYEXPIRED",
    "EKEYREVOKED",
    "EKEYREJECTED",
    "EOWNERDEAD",
    "ENOTRECOVERABLE",
    "ERFKILL",
    "EHWPOISON",
    "EFTYPE",
];

const fn blob_len(t: &[&str]) -> usize {
    let mut n = 0;
    let mut i = 0;
    while i < t.len() {
        n += t[i].len() + 1;
        i += 1;
    }
    n
}

const fn blob<const N: usize>(t: &[&str]) -> [u8; N] {
    let mut out = [0u8; N];
    let (mut k, mut i) = (0, 0);
    while i < t.len() {
        let b = t[i].as_bytes();
        let mut j = 0;
        while j < b.len() {
            out[k] = b[j];
            k += 1;
            j += 1;
        }
        k += 1;
        i += 1;
    }
    out
}

const fn offsets<const M: usize>(t: &[&str]) -> [u16; M] {
    let mut out = [0u16; M];
    let (mut k, mut i) = (0usize, 0);
    while i < t.len() {
        out[i] = k as u16;
        k += t[i].len() + 1;
        i += 1;
    }
    out
}

const ERR_LEN: usize = blob_len(&ERRLIST);
static ERR_BLOB: [u8; ERR_LEN] = blob(&ERRLIST);
static ERR_OFF: [u16; 135] = offsets(&ERRLIST);
const SIG_LEN: usize = blob_len(&SIGLIST);
static SIG_BLOB: [u8; SIG_LEN] = blob(&SIGLIST);
static SIG_OFF: [u16; 65] = offsets(&SIGLIST);
const NAME_LEN: usize = blob_len(&ERRNAMES);
static NAME_BLOB: [u8; NAME_LEN] = blob(&ERRNAMES);
static NAME_OFF: [u16; 135] = offsets(&ERRNAMES);

#[repr(transparent)]
pub struct ErrPtrs(pub [*const u8; 135]);
unsafe impl Sync for ErrPtrs {}

pub const fn err_ptrs() -> ErrPtrs {
    let mut out = [core::ptr::null(); 135];
    let mut i = 0;
    while i < 135 {
        if !ERRLIST[i].is_empty() {
            out[i] = unsafe { ERR_BLOB.as_ptr().add(ERR_OFF[i] as usize) };
        }
        i += 1;
    }
    ErrPtrs(out)
}


#[inline(never)]
pub fn error_message(code: i32) -> Option<&'static core::ffi::CStr> {
    if (0..ERRLIST.len() as i32).contains(&code) && !ERRLIST[code as usize].is_empty() {
        let at = ERR_OFF[code as usize] as usize;
        Some(unsafe { core::ffi::CStr::from_ptr(ERR_BLOB.as_ptr().add(at).cast()) })
    } else {
        None
    }
}

#[inline(never)]
pub fn error_name(code: i32) -> Option<&'static core::ffi::CStr> {
    if (0..ERRNAMES.len() as i32).contains(&code) && !ERRNAMES[code as usize].is_empty() {
        let at = NAME_OFF[code as usize] as usize;
        Some(unsafe { core::ffi::CStr::from_ptr(NAME_BLOB.as_ptr().add(at).cast()) })
    } else {
        None
    }
}

#[inline(never)]
pub fn signal_message(sig: i32) -> Option<&'static core::ffi::CStr> {
    if (0..SIGLIST.len() as i32).contains(&sig) && !SIGLIST[sig as usize].is_empty() {
        let at = SIG_OFF[sig as usize] as usize;
        Some(unsafe { core::ffi::CStr::from_ptr(SIG_BLOB.as_ptr().add(at).cast()) })
    } else {
        None
    }
}

#[thread_local]
static mut STRERROR_BUF: *mut u8 = core::ptr::null_mut();

pub fn strerror_buf_slot() -> *mut *mut u8 {
    core::ptr::addr_of_mut!(STRERROR_BUF)
}

pub fn write_unknown(buf: &mut [u8], prefix: &[u8], n: i32) -> usize {
    buf[..prefix.len()].copy_from_slice(prefix);
    let mut k = prefix.len();
    let mut tmp = [0u8; 12];
    let mut i = 12;
    let mut v = i64::from(n).unsigned_abs();
    loop {
        i -= 1;
        tmp[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    if n < 0 {
        buf[k] = b'-';
        k += 1;
    }
    buf[k..k + 12 - i].copy_from_slice(&tmp[i..]);
    k += 12 - i;
    buf[k] = 0;
    k
}
