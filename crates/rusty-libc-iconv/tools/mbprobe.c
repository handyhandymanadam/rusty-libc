/* Offline helper of gen_mb.py: asks the host's iconv how a multibyte charset converts.
 *   mbprobe enc CHARSET        : every character U+0000..U+10FFFF (and the surrogate range, skipped)
 *                                converted to the charset; prints "cp hexbytes" for each success
 *   mbprobe dec CHARSET < seqs : for every line (hex bytes) the conversion to UCS-4LE of exactly those
 *                                bytes; prints "hex ok cp[,cp]" (all bytes used), "hex inc" (EINVAL),
 *                                "hex ill n" (EILSEQ with n bytes consumed first... always 0) or "hex part n cp" (stopped
 *                                after n bytes with a character: a shorter match)
 *   mbprobe conv TO FROM < seqs : the conversion FROM -> TO (directly, whatever route glibc takes) of
 *                                every line (hex bytes); prints "hex ok outhex", "hex ill" or "hex inc"
 *   mbprobe decf CHARSET < seqs: like dec, but the converter is flushed after the sequence and the
 *                                characters it releases are listed too (charsets that hold back a
 *                                character in case a combining mark follows)
 * Each probe converts one unit with a fresh state (iconv reset). Stateful charsets are not probed. */
#include <iconv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
int main(int argc, char **argv) {
    if (argc < 3) return 2;
    if (!strcmp(argv[1], "conv")) {
        iconv_t c = iconv_open(argv[2], argv[3]);
        if (c == (iconv_t)-1) return 3;
        char line[256];
        while (fgets(line, sizeof line, stdin)) {
            unsigned char in[64], out[64]; size_t n = 0;
            for (char *p = line; p[0] && p[1] && p[0] != '\n'; p += 2) { unsigned x; sscanf(p, "%2x", &x); in[n++] = x; }
            char *ip = (char *)in, *op = (char *)out; size_t il = n, ol = sizeof out;
            iconv(c, NULL, NULL, NULL, NULL);
            errno = 0;
            size_t r = iconv(c, &ip, &il, &op, &ol);
            for (size_t i = 0; i < n; i++) printf("%02x", in[i]);
            if (r != (size_t)-1 && il == 0) { printf(" ok "); for (size_t i = 0; i < sizeof out - ol; i++) printf("%02x", out[i]); printf("\n"); }
            else if (errno == EINVAL) printf(" inc\n");
            else printf(" ill\n");
        }
        return 0;
    }
    if (!strcmp(argv[1], "enc")) {
        iconv_t e = iconv_open(argv[2], "UCS-4LE");
        if (e == (iconv_t)-1) return 3;
        for (uint32_t c = 0; c <= 0x10ffff; c++) {
            if (c >= 0xd800 && c < 0xe000) continue;
            uint32_t in[1] = {c}; unsigned char out[16];
            char *ip = (char *)in, *op = (char *)out; size_t il = 4, ol = sizeof out;
            iconv(e, NULL, NULL, NULL, NULL);
            size_t r = iconv(e, &ip, &il, &op, &ol);
            if (r == (size_t)-1 || il) continue;
            /* flush: stateful charsets would emit more here */
            size_t fl = ol; r = iconv(e, NULL, NULL, &op, &ol);
            printf("%x ", c);
            for (size_t i = 0; i < sizeof out - ol; i++) printf("%02x", out[i]);
            if (fl != ol) printf(" flush");
            printf("\n");
        }
        return 0;
    }
    int flush = !strcmp(argv[1], "decf");
    iconv_t d = iconv_open("UCS-4LE", argv[2]);
    if (d == (iconv_t)-1) return 3;
    char line[256];
    while (fgets(line, sizeof line, stdin)) {
        unsigned char in[64]; size_t n = 0;
        for (char *p = line; p[0] && p[1] && p[0] != '\n'; p += 2) { unsigned x; sscanf(p, "%2x", &x); in[n++] = x; }
        uint32_t out[8];
        char *ip = (char *)in, *op = (char *)out; size_t il = n, ol = sizeof out;
        iconv(d, NULL, NULL, NULL, NULL);
        errno = 0;
        size_t r = iconv(d, &ip, &il, &op, &ol);
        if (flush && r != (size_t)-1) iconv(d, NULL, NULL, &op, &ol);
        for (size_t i = 0; i < n; i++) printf("%02x", in[i]);
        if (r != (size_t)-1 && il == 0) {
            printf(" ok");
            for (size_t i = 0; i < (sizeof out - ol) / 4; i++) printf("%c%x", i ? ',' : ' ', out[i]);
            printf("\n");
        } else if (errno == EINVAL) printf(" inc\n");
        else if (errno == EILSEQ && il == n) printf(" ill\n");
        else printf(" part %zu %zu\n", n - il, (sizeof out - ol) / 4);
    }
    return 0;
}
