/* Offline helper of gen_jp_extra.py: with the host's ISO-2022-JP-2 converter put into a given
 * character set (by first writing a seed character that only that set has), report for every
 * character below U+00FF (and U+203E) what the converter writes for it next: the bytes after the
 * seed's own output. "cp hex" per line. */
#include <iconv.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
static int conv(iconv_t e, uint32_t *in, int n, unsigned char *out) {
    char *ip = (char *)in, *op = (char *)out; size_t il = 4 * n, ol = 64;
    iconv(e, NULL, NULL, NULL, NULL);
    if (iconv(e, &ip, &il, &op, &ol) == (size_t)-1) return -1;
    return 64 - (int)ol;
}
int main(int argc, char **argv) {
    iconv_t e = iconv_open(argv[1], "UCS-4LE");
    uint32_t seed = strtoul(argv[2], 0, 16);
    unsigned char a[64], b[64];
    int na = conv(e, &seed, 1, a);
    if (na < 0) return 3;
    for (uint32_t c = 0; c < 0x10000; c++) {
        if (c >= 0xd800 && c < 0xe000) continue;
        if (c > 0xff && c != 0x203e) continue;
        uint32_t in[2] = {seed, c};
        int nb = conv(e, in, 2, b);
        if (nb < 0 || nb <= na || memcmp(a, b, na)) continue;
        int has_esc = 0; for (int i = na; i < nb; i++) if (b[i] == 0x1b) has_esc = 1;
        if (has_esc || nb - na != 2) continue;
        printf("%x %02x%02x\n", c, b[na], b[na + 1]);
    }
    return 0;
}
