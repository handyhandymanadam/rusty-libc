use crate::model::*;

pub static HDR: Header = Header {
    path: "ns_etc.h",
    items: &[
        Item::Comment(r#"/* Shared by the tests of the system databases (gshadow, fstab, ttys, netgroup, hosts.equiv ...): a private user
   and mount namespace in which /etc is a tmpfs that the test fills. Nothing outside the namespace is touched:
   the real /etc stays as it is. enter_etc_ns() returns 0 in the namespace, -1 when it cannot be created
   (the caller then prints SKIP). The process is "root" inside (uid 0 mapped to the real user). */"#),
        Item::Guard { name: "NS_ETC_H", value: "", end: "", items: &[
            Item::Consts(&[
                ("_GNU_SOURCE", V::Dec(1)),
            ]),
            Item::Include("<fcntl.h>"),
            Item::Include("<sched.h>"),
            Item::Include("<stdio.h>"),
            Item::Include("<string.h>"),
            Item::Include("<net/if.h>"),
            Item::Include("<sys/ioctl.h>"),
            Item::Include("<sys/mount.h>"),
            Item::Include("<sys/socket.h>"),
            Item::Include("<unistd.h>"),
            Item::Blank,
            Item::Raw(Reason::StaticInline, r#"static void ns_write_file (const char *path, const char *text)
{
  int fd = open (path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd < 0)
    return;
  if (write (fd, text, strlen (text)) < 0)
    perror ("write");
  close (fd);
}"#),
            Item::Blank,
            Item::Comment(r#"/* with_net: also a private network namespace with only the loopback interface (up), in which the process may bind
   reserved ports */"#),
            Item::Raw(Reason::StaticInline, r#"static int enter_etc_ns_x (int with_net)
{
  uid_t uid = getuid ();
  gid_t gid = getgid ();
  char buf[100];
  int fd;
  if (unshare (CLONE_NEWUSER | CLONE_NEWNS | (with_net ? CLONE_NEWNET : 0)) != 0)
    return -1;
  fd = open ("/proc/self/setgroups", O_WRONLY);
  if (fd >= 0 && write (fd, "deny", 4) < 0)
    perror ("setgroups");
  close (fd);
  snprintf (buf, sizeof buf, "0 %d 1", (int) uid);
  fd = open ("/proc/self/uid_map", O_WRONLY);
  if (fd < 0 || write (fd, buf, strlen (buf)) < 0)
    return -1;
  close (fd);
  snprintf (buf, sizeof buf, "0 %d 1", (int) gid);
  fd = open ("/proc/self/gid_map", O_WRONLY);
  if (fd < 0 || write (fd, buf, strlen (buf)) < 0)
    return -1;
  close (fd);
  if (mount (NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0)
    return -1;
  if (mount ("tmpfs", "/etc", "tmpfs", 0, "mode=755") != 0)
    return -1;
  ns_write_file ("/etc/nsswitch.conf", "passwd: files\ngroup: files\nshadow: files\ngshadow: files\nhosts: files\nnetgroup: files\n");
  if (with_net)
    {
      struct ifreq ifr;
      int s = socket (AF_INET, SOCK_DGRAM, 0);
      memset (&ifr, 0, sizeof ifr);
      strcpy (ifr.ifr_name, "lo");
      if (s < 0 || ioctl (s, SIOCGIFFLAGS, &ifr) < 0)
        return -1;
      ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
      if (ioctl (s, SIOCSIFFLAGS, &ifr) < 0)
        return -1;
      close (s);
    }
  return 0;
}"#),
            Item::Blank,
            Item::Raw(Reason::StaticInline, r#"static int enter_etc_ns (void)
{
  return enter_etc_ns_x (0);
}"#),
        ]},
    ],
};
