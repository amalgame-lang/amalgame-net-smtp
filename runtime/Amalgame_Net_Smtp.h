/*
 * Amalgame.Net.Smtp — minimal SMTP client (transactional mail).
 * Copyright (c) 2026 Bastien MOUGET
 * Licensed under the Apache License, Version 2.0.
 * https://github.com/amalgame-lang/amalgame-net-smtp
 *
 * One AM class:
 *   Smtp — static send over implicit TLS (SMTPS, port 465).
 *
 * v0.1 scope: outbound transactional mail over implicit TLS only
 * (the ssl0.ovh.net:465 / Gmail:465 case). Plaintext + STARTTLS
 * (port 587) and inbound (IMAP/POP3) are out of scope — see the
 * amalgame ecosystem roadmap (beyond-http.md) for the broader
 * Amalgame.Net.{Smtp server, Imap, Pop3} slice.
 *
 * Requires OpenSSL 3.x (or LibreSSL — drop-in ABI compatible):
 *   Debian/Ubuntu : sudo apt install libssl-dev
 *   Fedora/RHEL   : sudo dnf install openssl-devel
 *   macOS         : brew install openssl@3
 *   Windows/MSYS2 : pacman -S mingw-w64-x86_64-openssl
 *
 * Link with -lssl -lcrypto (handled by amc via the
 * `libs = ["ssl","crypto"]` line in amalgame.toml).
 *
 * If OpenSSL is unavailable, Send returns false and LastError
 * carries a descriptive message — no compile-time crash.
 */

#ifndef AMALGAME_NET_SMTP_H
#define AMALGAME_NET_SMTP_H

#include "_runtime.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/types.h>

/* ── OpenSSL detection (multi-OS, mirrors amalgame-tls) ───────────── */
#if defined(__has_include)
#  if __has_include(<openssl/ssl.h>)
#    include <openssl/ssl.h>
#    include <openssl/err.h>
#    include <openssl/bio.h>
#    define AMALGAME_SMTP_HAVE_SSL 1
#  elif __has_include(</opt/homebrew/opt/openssl@3/include/openssl/ssl.h>)
#    include </opt/homebrew/opt/openssl@3/include/openssl/ssl.h>
#    include </opt/homebrew/opt/openssl@3/include/openssl/err.h>
#    define AMALGAME_SMTP_HAVE_SSL 1
#  elif __has_include(</usr/local/opt/openssl@3/include/openssl/ssl.h>)
#    include </usr/local/opt/openssl@3/include/openssl/ssl.h>
#    include </usr/local/opt/openssl@3/include/openssl/err.h>
#    define AMALGAME_SMTP_HAVE_SSL 1
#  else
#    define AMALGAME_SMTP_HAVE_SSL 0
#  endif
#else
#  include <openssl/ssl.h>
#  include <openssl/err.h>
#  define AMALGAME_SMTP_HAVE_SSL 1
#endif

/* Last error string for the most recent Smtp.Send on this thread. */
static __thread const char* g_amalgame_smtp_last_error = "";

static inline code_string Amalgame_Net_Smtp_LastError(void) {
    return (code_string) g_amalgame_smtp_last_error;
}

/*
 * Smtp.RfcDate — current date as an RFC 5322 header value, e.g.
 * "Tue, 01 Jun 2026 15:30:00 +0000". For AM builders assembling their
 * own message (mail.am). Always available (no OpenSSL needed).
 *
 * AM: public static string RfcDate()
 */
static inline code_string Amalgame_Net_Smtp_RfcDate(void) {
    char* buf = (char*) GC_MALLOC_ATOMIC(64);
    time_t t = time(NULL);
    struct tm gmt;
    gmtime_r(&t, &gmt);
    static const char* days[]   = {"Sun","Mon","Tue","Wed","Thu","Fri","Sat"};
    static const char* months[] = {"Jan","Feb","Mar","Apr","May","Jun",
                                    "Jul","Aug","Sep","Oct","Nov","Dec"};
    snprintf(buf, 64, "%s, %02d %s %04d %02d:%02d:%02d +0000",
             days[gmt.tm_wday], gmt.tm_mday, months[gmt.tm_mon],
             gmt.tm_year + 1900, gmt.tm_hour, gmt.tm_min, gmt.tm_sec);
    return (code_string) buf;
}

/*
 * Smtp.NewMessageId — a unique Message-ID value "<epoch.pid@domain>"
 * for AM builders. Pass the sender's domain (e.g. "example.com").
 *
 * AM: public static string NewMessageId(string domain)
 */
static inline code_string Amalgame_Net_Smtp_NewMessageId(code_string domain) {
    char* buf = (char*) GC_MALLOC_ATOMIC(400);
    snprintf(buf, 400, "<%lld.%d@%s>",
             (long long) time(NULL), (int) getpid(),
             (domain && *domain) ? domain : "localhost");
    return (code_string) buf;
}

#if AMALGAME_SMTP_HAVE_SSL

/* Read a full SMTP reply (which may span several lines) and check its
 * status code begins with `expect` (e.g. '2', '3'). Per RFC 5321, a
 * multi-line reply repeats the 3-digit code with a '-' as the 4th char
 * on every line except the last, where the 4th char is a space. We read
 * byte-by-byte, splitting on CRLF, until we see a final line (4th char
 * not '-'). Returns 1 if that final line's first digit matches `expect`,
 * 0 otherwise. */
static inline int amalgame_smtp_expect(SSL* ssl, char expect) {
    char line[1024];
    int li = 0;
    char first = 0;        /* first char of the most recent line */
    int last_line = 0;     /* set once we read a line whose 4th char != '-' */
    char full[2048];       /* accumulate for the error message */
    int fi = 0;

    while (!last_line) {
        char ch;
        int n = SSL_read(ssl, &ch, 1);
        if (n <= 0) {
            g_amalgame_smtp_last_error = "SMTP: connection closed while reading reply";
            return 0;
        }
        if (fi < (int)sizeof(full) - 1) full[fi++] = ch;
        if (ch == '\r') continue;
        if (ch == '\n') {
            line[li] = 0;
            if (li > 0) first = line[0];
            /* 4th char (index 3) decides continuation: '-' = more lines. */
            if (li < 4 || line[3] != '-') last_line = 1;
            li = 0;
            continue;
        }
        if (li < (int)sizeof(line) - 1) line[li++] = ch;
    }

    full[fi] = 0;
    if (first != expect) {
        size_t len = strlen(full);
        char* msg = (char*) GC_MALLOC_ATOMIC(len + 32);
        snprintf(msg, len + 32, "SMTP rejected: %s", full);
        g_amalgame_smtp_last_error = msg;
        return 0;
    }
    return 1;
}

/* Send a command line (CRLF appended) then expect a reply code. */
static inline int amalgame_smtp_cmd(SSL* ssl, const char* line, char expect) {
    if (line && *line) {
        SSL_write(ssl, line, (int)strlen(line));
        SSL_write(ssl, "\r\n", 2);
    }
    return amalgame_smtp_expect(ssl, expect);
}

/* Extract the domain part of an email address ("a@b.com" → "b.com").
 * Returns a GC string; falls back to "localhost" if there's no '@'. */
static inline char* amalgame_smtp_domain_of(const char* addr) {
    const char* at = addr ? strchr(addr, '@') : NULL;
    if (!at || !at[1]) {
        char* d = (char*) GC_MALLOC_ATOMIC(10);
        strcpy(d, "localhost");
        return d;
    }
    const char* dom = at + 1;
    size_t len = strlen(dom);
    char* d = (char*) GC_MALLOC_ATOMIC(len + 1);
    memcpy(d, dom, len + 1);
    return d;
}

/* RFC 5322 Date header value, e.g. "Tue, 01 Jun 2026 15:30:00 +0000".
 * Uses GMT/+0000 to avoid locale/timezone surprises. */
static inline char* amalgame_smtp_date_now(void) {
    char* buf = (char*) GC_MALLOC_ATOMIC(64);
    time_t t = time(NULL);
    struct tm gmt;
    gmtime_r(&t, &gmt);
    /* Force C-locale day/month names regardless of the process locale. */
    static const char* days[]   = {"Sun","Mon","Tue","Wed","Thu","Fri","Sat"};
    static const char* months[] = {"Jan","Feb","Mar","Apr","May","Jun",
                                    "Jul","Aug","Sep","Oct","Nov","Dec"};
    snprintf(buf, 64, "%s, %02d %s %04d %02d:%02d:%02d +0000",
             days[gmt.tm_wday], gmt.tm_mday, months[gmt.tm_mon],
             gmt.tm_year + 1900, gmt.tm_hour, gmt.tm_min, gmt.tm_sec);
    return buf;
}

/* Base64-encode (for AUTH LOGIN). Returns a GC string. */
static inline char* amalgame_smtp_b64(const char* in) {
    static const char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t ilen = strlen(in);
    size_t olen = 4 * ((ilen + 2) / 3);
    char* out = (char*) GC_MALLOC_ATOMIC(olen + 1);
    size_t i, j;
    for (i = 0, j = 0; i < ilen;) {
        unsigned a = i < ilen ? (unsigned char)in[i++] : 0;
        unsigned b = i < ilen ? (unsigned char)in[i++] : 0;
        unsigned c = i < ilen ? (unsigned char)in[i++] : 0;
        unsigned tri = (a << 16) | (b << 8) | c;
        out[j++] = tbl[(tri >> 18) & 0x3F];
        out[j++] = tbl[(tri >> 12) & 0x3F];
        out[j++] = tbl[(tri >> 6) & 0x3F];
        out[j++] = tbl[tri & 0x3F];
    }
    size_t mod = ilen % 3;
    if (mod >= 1) out[olen - 1] = '=';
    if (mod == 1) out[olen - 2] = '=';
    out[olen] = 0;
    return out;
}

/* Read a whole file into a GC buffer (binary-safe). Sets *out_len.
 * Returns NULL on error. */
static inline unsigned char* amalgame_smtp_read_file(const char* path, size_t* out_len) {
    FILE* f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    if (sz < 0) { fclose(f); return NULL; }
    fseek(f, 0, SEEK_SET);
    unsigned char* buf = (unsigned char*) GC_MALLOC_ATOMIC((size_t)sz + 1);
    size_t got = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    buf[got] = 0;
    *out_len = got;
    return buf;
}

/* Base64 raw bytes (no line wrapping). Returns a GC string. */
static inline char* amalgame_smtp_b64_bytes(const unsigned char* in, size_t ilen) {
    static const char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t olen = 4 * ((ilen + 2) / 3);
    char* out = (char*) GC_MALLOC_ATOMIC(olen + 1);
    size_t i, j;
    for (i = 0, j = 0; i < ilen;) {
        unsigned a = i < ilen ? in[i++] : 0;
        unsigned b = i < ilen ? in[i++] : 0;
        unsigned c = i < ilen ? in[i++] : 0;
        unsigned tri = (a << 16) | (b << 8) | c;
        out[j++] = tbl[(tri >> 18) & 0x3F];
        out[j++] = tbl[(tri >> 12) & 0x3F];
        out[j++] = tbl[(tri >> 6) & 0x3F];
        out[j++] = tbl[tri & 0x3F];
    }
    size_t mod = ilen % 3;
    if (mod >= 1) out[olen - 1] = '=';
    if (mod == 1) out[olen - 2] = '=';
    out[olen] = 0;
    return out;
}

/*
 * Smtp.FileBase64 — read a file and return its base64-encoded contents
 * (no line wrapping), for building MIME attachments from AM. Empty
 * string on error (missing/unreadable file).
 *
 * AM: public static string FileBase64(string path)
 */
static inline code_string Amalgame_Net_Smtp_FileBase64(code_string path) {
    size_t len = 0;
    unsigned char* data = amalgame_smtp_read_file(path ? path : "", &len);
    if (!data) {
        g_amalgame_smtp_last_error = "SMTP: cannot read attachment file";
        return (code_string) "";
    }
    return (code_string) amalgame_smtp_b64_bytes(data, len);
}

/*
 * Smtp.EncodeHeader — RFC 2047 MIME "encoded-word" for header values
 * that contain non-ASCII bytes (accents in a Subject, a sender name…).
 * Mail headers are 7-bit ASCII; a raw UTF-8 byte gets shown as "?" by
 * the client. We B-encode such values as one or more
 * "=?UTF-8?B?<base64>?=" words, folded with CRLF+SPACE so no encoded
 * line exceeds the RFC 2047 75-char ceiling. Each chunk ends on a UTF-8
 * character boundary (never mid multi-byte sequence). Pure-ASCII input
 * is returned unchanged (no needless encoding).
 *
 * AM: public static string EncodeHeader(string s)
 */
static inline code_string Amalgame_Net_Smtp_EncodeHeader(code_string s) {
    const char* in = s ? s : "";
    size_t n = strlen(in);
    /* Fast path: all printable ASCII → leave as-is. */
    int needs = 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char) in[i];
        if (c >= 0x80 || c < 0x20) { needs = 1; break; }
    }
    if (!needs) return s ? s : (code_string) "";

    /* Encode in chunks of ≤ 45 input bytes (→ ≤ 60 base64 chars; with the
     * "=?UTF-8?B?" + "?=" wrapper that is ≤ 72, under the 75 ceiling),
     * backing each chunk off to the last UTF-8 boundary. */
    const char* prefix = "=?UTF-8?B?";
    const char* suffix = "?=";
    const char* fold   = "\r\n ";
    /* Worst-case output size estimate: each 45-byte block → ~72 chars +
     * 3-char fold; be generous. */
    size_t blocks = n / 45 + 2;
    size_t cap = blocks * 80 + 1;
    char* out = (char*) GC_MALLOC_ATOMIC(cap);
    size_t oj = 0;
    size_t pos = 0;
    int first = 1;
    while (pos < n) {
        size_t take = n - pos;
        if (take > 45) {
            take = 45;
            /* Don't split a UTF-8 multi-byte sequence: walk back while the
             * next byte is a continuation byte (0x80..0xBF). */
            while (take > 0 &&
                   ((unsigned char) in[pos + take] & 0xC0) == 0x80) {
                take--;
            }
            if (take == 0) take = 45;   /* pathological: emit raw rather than loop */
        }
        char* b64 = amalgame_smtp_b64_bytes((const unsigned char*) (in + pos), take);
        if (!first) {
            for (const char* p = fold; *p; p++) out[oj++] = *p;
        }
        for (const char* p = prefix; *p; p++) out[oj++] = *p;
        for (char* p = b64; *p; p++) out[oj++] = *p;
        for (const char* p = suffix; *p; p++) out[oj++] = *p;
        first = 0;
        pos += take;
    }
    out[oj] = 0;
    return (code_string) out;
}

/*
 * Smtp.SendRaw — transport core. Runs the full implicit-TLS SMTP
 * conversation (connect, TLS, EHLO, AUTH LOGIN, MAIL FROM, RCPT TO,
 * DATA) and writes `data` verbatim as the DATA payload. The caller is
 * responsible for `data` being a complete RFC 5322 message (headers +
 * blank line + body), CRLF line endings, and dot-stuffing if needed.
 * SendRaw appends the terminating CRLF "." itself.
 *
 * This is what the Mail builder (mail.am) targets. Smtp.Send below is a
 * convenience wrapper that assembles a plain-text message and calls it.
 *
 * AM: public static bool SendRaw(string host, int port, string user,
 *                                string pass, string from, string to,
 *                                string data)
 */
static inline code_bool Amalgame_Net_Smtp_SendRaw(
        code_string host, i64 port,
        code_string user, code_string pass,
        code_string from, code_string to,
        code_string data) {

    g_amalgame_smtp_last_error = "";
    if (!host || !*host) { g_amalgame_smtp_last_error = "SMTP: empty host"; return 0; }

    int sock = -1;
    SSL_CTX* ctx = NULL;
    SSL* ssl = NULL;
    code_bool ok = 0;
    char* domain = amalgame_smtp_domain_of(from);   /* for EHLO */

    /* Resolve + connect TCP. */
    char portstr[16];
    snprintf(portstr, sizeof(portstr), "%lld", (long long) port);
    struct addrinfo hints, *res = NULL, *rp;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, portstr, &hints, &res) != 0) {
        g_amalgame_smtp_last_error = "SMTP: DNS resolution failed";
        return 0;
    }
    for (rp = res; rp; rp = rp->ai_next) {
        sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock < 0) continue;
        if (connect(sock, rp->ai_addr, rp->ai_addrlen) == 0) break;
        close(sock); sock = -1;
    }
    freeaddrinfo(res);
    if (sock < 0) { g_amalgame_smtp_last_error = "SMTP: TCP connect failed"; return 0; }

    /* TLS handshake (implicit — SMTPS). */
    SSL_library_init();
    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) { g_amalgame_smtp_last_error = "SMTP: SSL_CTX_new failed"; goto cleanup; }
    ssl = SSL_new(ctx);
    if (!ssl) { g_amalgame_smtp_last_error = "SMTP: SSL_new failed"; goto cleanup; }
    SSL_set_fd(ssl, sock);
    SSL_set_tlsext_host_name(ssl, host);
    if (SSL_connect(ssl) != 1) { g_amalgame_smtp_last_error = "SMTP: TLS handshake failed"; goto cleanup; }

    /* SMTP conversation. */
    if (!amalgame_smtp_expect(ssl, '2')) goto cleanup;          /* server greeting */
    {
        char ehlo[300];
        snprintf(ehlo, sizeof(ehlo), "EHLO %s", domain);
        if (!amalgame_smtp_cmd(ssl, ehlo, '2')) goto cleanup;
    }

    if (user && *user) {
        if (!amalgame_smtp_cmd(ssl, "AUTH LOGIN", '3')) goto cleanup;
        if (!amalgame_smtp_cmd(ssl, amalgame_smtp_b64(user), '3')) goto cleanup;
        if (!amalgame_smtp_cmd(ssl, amalgame_smtp_b64(pass ? pass : ""), '2')) goto cleanup;
    }

    {
        char line[1024];
        snprintf(line, sizeof(line), "MAIL FROM:<%s>", from ? from : "");
        if (!amalgame_smtp_cmd(ssl, line, '2')) goto cleanup;
        snprintf(line, sizeof(line), "RCPT TO:<%s>", to ? to : "");
        if (!amalgame_smtp_cmd(ssl, line, '2')) goto cleanup;
        if (!amalgame_smtp_cmd(ssl, "DATA", '3')) goto cleanup;

        /* Caller-assembled message, then the terminating CRLF "." */
        const char* d = data ? data : "";
        SSL_write(ssl, d, (int)strlen(d));
        if (!amalgame_smtp_cmd(ssl, "\r\n.", '2')) goto cleanup;
        amalgame_smtp_cmd(ssl, "QUIT", '2');                    /* best-effort */
    }

    ok = 1;

cleanup:
    if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); }
    if (ctx) SSL_CTX_free(ctx);
    if (sock >= 0) close(sock);
    return ok;
}

/*
 * Smtp.Send — convenience wrapper: assemble a plain-text message
 * (Date + From/To/Subject + Message-ID, text/plain UTF-8) and send it
 * via SendRaw. Unchanged signature from v0.1 (backwards compatible).
 *
 * AM: public static bool Send(string host, int port, string user,
 *                             string pass, string from, string to,
 *                             string subject, string body)
 */
static inline code_bool Amalgame_Net_Smtp_Send(
        code_string host, i64 port,
        code_string user, code_string pass,
        code_string from, code_string to,
        code_string subject, code_string body) {

    char* domain = amalgame_smtp_domain_of(from);
    char* date = amalgame_smtp_date_now();
    char msgid[400];
    snprintf(msgid, sizeof(msgid), "<%lld.%d@%s>",
             (long long) time(NULL), (int) getpid(), domain);
    char* hdr = (char*) GC_MALLOC_ATOMIC(
        (from?strlen(from):0) + (to?strlen(to):0) +
        (subject?strlen(subject):0) + (body?strlen(body):0) +
        strlen(date) + strlen(msgid) + 256);
    sprintf(hdr,
        "Date: %s\r\nFrom: %s\r\nTo: %s\r\nSubject: %s\r\n"
        "Message-ID: %s\r\n"
        "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n"
        "Content-Transfer-Encoding: 8bit\r\n\r\n%s",
        date, from?from:"", to?to:"", subject?subject:"", msgid,
        body?body:"");
    return Amalgame_Net_Smtp_SendRaw(host, port, user, pass, from, to,
                                     (code_string) hdr);
}

#else  /* !AMALGAME_SMTP_HAVE_SSL */

static inline code_bool Amalgame_Net_Smtp_SendRaw(
        code_string host, i64 port, code_string user, code_string pass,
        code_string from, code_string to, code_string data) {
    (void)host;(void)port;(void)user;(void)pass;(void)from;(void)to;(void)data;
    g_amalgame_smtp_last_error =
        "SMTP: built without OpenSSL — install libssl-dev and rebuild";
    return 0;
}
static inline code_bool Amalgame_Net_Smtp_Send(
        code_string host, i64 port, code_string user, code_string pass,
        code_string from, code_string to, code_string subject, code_string body) {
    (void)host;(void)port;(void)user;(void)pass;(void)from;(void)to;(void)subject;(void)body;
    g_amalgame_smtp_last_error =
        "SMTP: built without OpenSSL — install libssl-dev and rebuild";
    return 0;
}
static inline code_string Amalgame_Net_Smtp_FileBase64(code_string path) {
    (void)path;
    g_amalgame_smtp_last_error =
        "SMTP: built without OpenSSL — install libssl-dev and rebuild";
    return (code_string) "";
}

#endif /* AMALGAME_SMTP_HAVE_SSL */

#endif /* AMALGAME_NET_SMTP_H */
