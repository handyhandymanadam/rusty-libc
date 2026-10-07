#include <iconv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
int main(int argc, char **argv) {
    for (int a = 1; a < argc; a++) {
        const char *name = argv[a];
        iconv_t d = iconv_open("UCS-4LE", name), e = iconv_open(name, "UCS-4LE");
        if (d == (iconv_t)-1 || e == (iconv_t)-1) { printf("OTHER %s open\n", name); continue; }
        int dec[256], simple = 1; const char *why = "";
        for (int b = 0; b < 256 && simple; b++) {
            unsigned char in[1] = {b}; uint32_t out[4];
            char *ip = (char *)in, *op = (char *)out; size_t il = 1, ol = sizeof out;
            iconv(d, NULL, NULL, NULL, NULL);
            errno = 0;
            size_t r = iconv(d, &ip, &il, &op, &ol);
            if (r != (size_t)-1 && il == 0 && ol == sizeof out - 4 && r == 0) dec[b] = out[0];
            else if (r == (size_t)-1 && errno == EILSEQ && il == 1 && ol == sizeof out) dec[b] = -1;
            else { simple = 0; why = "decode"; }
        }
        int ne = 0; static uint32_t ent[70000];
        for (uint32_t c = 0; c < 0x30000 && simple; c++) {
            uint32_t in[1] = {c}; unsigned char out[8];
            char *ip = (char *)in, *op = (char *)out; size_t il = 4, ol = sizeof out;
            iconv(e, NULL, NULL, NULL, NULL);
            errno = 0;
            size_t r = iconv(e, &ip, &il, &op, &ol);
            if (r == 0 && il == 0 && ol == sizeof out - 1) ent[ne++] = (c << 8) | out[0];
            else if (r == (size_t)-1 && errno == EILSEQ && il == 4 && ol == sizeof out) ;
            else { simple = 0; why = "encode"; }
        }
        if (!simple) { printf("OTHER %s %s\n", name, why); continue; }
        printf("SIMPLE %s\n", name);
        for (int b = 0; b < 256; b++) printf("D %d\n", dec[b]);
        for (int i = 0; i < ne; i++) printf("E %u %u\n", ent[i] >> 8, ent[i] & 255);
        iconv_close(d); iconv_close(e);
    }
    return 0;
}
