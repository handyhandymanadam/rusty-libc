#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Area {
    ReadOnly,
    Writable,
    Inaccessible,
    OpenFail,
}

fn hex(b: &[u8]) -> Option<(usize, usize)> {
    let mut v = 0usize;
    let mut i = 0;
    while i < b.len() {
        let d = match b[i] {
            c @ b'0'..=b'9' => c - b'0',
            c @ b'a'..=b'f' => c - b'a' + 10,
            c @ b'A'..=b'F' => c - b'A' + 10,
            _ => break,
        };
        v = (v << 4) | d as usize;
        i += 1;
    }
    if i == 0 { None } else { Some((v, i)) }
}

fn line(l: &[u8], ptr: usize, end: usize, size: &mut usize) -> Result<bool, ()> {
    let Some((from, a)) = hex(l) else { return Err(()) };
    if l.get(a) != Some(&b'-') {
        return Err(());
    }
    let Some((to, b)) = hex(&l[a + 1..]) else { return Err(()) };
    if l.get(a + 1 + b) != Some(&b' ') {
        return Err(());
    }
    if from < end && to > ptr {
        let perms = &l[a + b + 2..];
        if perms.first() != Some(&b'r') || perms.get(1) != Some(&b'-') {
            return Err(());
        }
        if from <= ptr && to >= end {
            *size = 0;
            return Ok(false);
        } else if from <= ptr {
            *size -= to - ptr;
        } else if to >= end {
            *size -= end - from;
        } else {
            *size -= to - from;
        }
        if *size == 0 {
            return Ok(false);
        }
    }
    Ok(true)
}

pub fn readonly_area(ptr: *const u8, size: usize) -> Area {
    let start = ptr as usize;
    let end = start.wrapping_add(size);
    let fd = match unsafe { rusty_libc_core::unistd::open(c"/proc/self/maps".as_ptr(), 0o2000000 , 0) } {
        Ok(fd) => fd,
        Err(e) if e.0 == 2 || e.0 == 13 => return Area::Inaccessible,
        Err(_) => return Area::OpenFail,
    };
    let mut remaining = size;
    let mut chunk = [0u8; 1024];
    let mut cur = [0u8; 96];
    let mut cur_len = 0usize;
    let mut skipping = false;
    let mut stop = false;
    'read: loop {
        let n = match rusty_libc_core::unistd::read(fd, &mut chunk) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.0 == 4 => continue,
            Err(_) => break,
        };
        for &c in &chunk[..n] {
            if c == b'\n' {
                match line(&cur[..cur_len], start, end, &mut remaining) {
                    Ok(true) => {}
                    Ok(false) | Err(()) => {
                        stop = true;
                        break 'read;
                    }
                }
                cur_len = 0;
                skipping = false;
            } else if !skipping {
                if cur_len < cur.len() {
                    cur[cur_len] = c;
                    cur_len += 1;
                } else {
                    skipping = true;
                }
            }
        }
    }
    let _ = stop;
    let _ = rusty_libc_core::unistd::close(fd);
    if remaining == 0 { Area::ReadOnly } else { Area::Writable }
}
