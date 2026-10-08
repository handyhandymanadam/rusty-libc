use crate::model::*;

pub static HDR: Header = Header {
    path: "paths.h",
    items: &[
        Item::Guard { name: "_PATHS_H_", value: "", end: "", items: &[
            Item::Blank,
            Item::Consts(&[
                ("_PATH_DEFPATH", V::Txt(r#""/usr/bin:/bin""#)),
            ]),
            Item::Consts(&[
                ("_PATH_STDPATH", V::Txt(r#""/usr/bin:/bin:/usr/sbin:/sbin""#)),
            ]),
            Item::Blank,
            Item::Consts(&[
                ("_PATH_BSHELL", V::Txt(r#""/bin/sh""#)),
                ("_PATH_CONSOLE", V::Txt(r#""/dev/console""#)),
                ("_PATH_CSHELL", V::Txt(r#""/bin/csh""#)),
                ("_PATH_DEVDB", V::Txt(r#""/var/run/dev.db""#)),
                ("_PATH_DEVNULL", V::Txt(r#""/dev/null""#)),
                ("_PATH_DRUM", V::Txt(r#""/dev/drum""#)),
                ("_PATH_GSHADOW", V::Txt(r#""/etc/gshadow""#)),
                ("_PATH_KLOG", V::Txt(r#""/proc/kmsg""#)),
                ("_PATH_KMEM", V::Txt(r#""/dev/kmem""#)),
                ("_PATH_LASTLOG", V::Txt(r#""/var/log/lastlog""#)),
                ("_PATH_MAILDIR", V::Txt(r#""/var/mail""#)),
                ("_PATH_MAN", V::Txt(r#""/usr/share/man""#)),
                ("_PATH_MEM", V::Txt(r#""/dev/mem""#)),
                ("_PATH_MNTTAB", V::Txt(r#""/etc/fstab""#)),
                ("_PATH_MOUNTED", V::Txt(r#""/etc/mtab""#)),
                ("_PATH_NOLOGIN", V::Txt(r#""/etc/nologin""#)),
                ("_PATH_PRESERVE", V::Txt(r#""/var/lib""#)),
                ("_PATH_RWHODIR", V::Txt(r#""/var/spool/rwho""#)),
                ("_PATH_SENDMAIL", V::Txt(r#""/usr/sbin/sendmail""#)),
                ("_PATH_SHADOW", V::Txt(r#""/etc/shadow""#)),
                ("_PATH_SHELLS", V::Txt(r#""/etc/shells""#)),
                ("_PATH_TTY", V::Txt(r#""/dev/tty""#)),
                ("_PATH_UNIX", V::Txt(r#""/boot/vmlinux""#)),
                ("_PATH_UTMP", V::Txt(r#""/var/run/utmp""#)),
                ("_PATH_VI", V::Txt(r#""/usr/bin/vi""#)),
                ("_PATH_WTMP", V::Txt(r#""/var/log/wtmp""#)),
            ]),
            Item::Blank,
            Item::Consts(&[
                ("_PATH_DEV", V::Txt(r#""/dev/""#)),
                ("_PATH_TMP", V::Txt(r#""/tmp/""#)),
                ("_PATH_VARDB", V::Txt(r#""/var/db/""#)),
                ("_PATH_VARRUN", V::Txt(r#""/var/run/""#)),
                ("_PATH_VARTMP", V::Txt(r#""/var/tmp/""#)),
            ]),
            Item::Blank,
        ]},
    ],
};
