/*
 * Amalgame.Net.Smtp — minimal SMTP client (transactional mail).
 * Copyright (c) 2026 Bastien MOUGET
 * Licensed under the Apache License, Version 2.0.
 * https://github.com/amalgame-lang/amalgame-net-smtp
 *
 * One AM class:
 *   Mail — builder + send, implicit TLS (SMTPS, port 465) or
 *   STARTTLS submission (port 587), selected automatically from the
 *   port passed to Send()/SendRaw().
 *
 * v0.2.6: added STARTTLS (port 587) — cleartext greeting/EHLO/STARTTLS,
 * then a TLS upgrade in place and a second EHLO per RFC 3207. Added
 * process-wide SIGPIPE suppression (a peer closing the connection
 * mid-write — rate-limiting, a reset — used to kill the whole process;
 * it now just fails the send with a clean error). Both fixes came out
 * of a real STARTTLS-only server (mail.nidclair.fr) crashing the caller:
 * calling SSL_connect() immediately on a socket whose peer speaks
 * cleartext first races the server's unprompted "220 ..." greeting
 * against our TLS ClientHello, and OpenSSL's recovery from the
 * resulting garbled handshake was not a clean failure.
 *
 * v0.1 scope was implicit TLS only (the ssl0.ovh.net:465 / Gmail:465
 * case). Inbound (IMAP/POP3) is still out of scope — see the amalgame
 * ecosystem roadmap (beyond-http.md) for the broader
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
#include <signal.h>
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
    /* epoch.pid alone repeats for every message a process sends within the same second (a group
     * invitation to N people went out as N mails with ONE Message-ID — 2026-09-21). Add the
     * nanoseconds and a per-process counter so each call is unique. */
    static unsigned long seq = 0;
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    seq++;
    char* buf = (char*) GC_MALLOC_ATOMIC(400);
    snprintf(buf, 400, "<%lld.%09ld.%d.%lu@%s>",
             (long long) ts.tv_sec, (long) ts.tv_nsec, (int) getpid(), seq,
             (domain && *domain) ? domain : "localhost");
    return (code_string) buf;
}

/*
 * Smtp.QuotedPrintable — RFC 2045 §6.7 encoding of a text/HTML body.
 * The input must already use CRLF line ends (Mail normalises them first):
 * each CRLF stays a hard line break, every other line is cut with soft
 * breaks ("=" CRLF) so no encoded line exceeds 76 characters.
 *
 * Why: sent as 8bit, a one-line HTML body of 2.5 KB broke RFC 5322's
 * 998-byte line limit; OVH's relay folded it by force in the middle of a
 * CSS property and spam filters score such lines (2026-09-21, Gmail spam).
 *
 * AM: public static string QuotedPrintable(string body)
 */
static inline code_string Amalgame_Net_Smtp_QuotedPrintable(code_string body) {
    static const char hex[] = "0123456789ABCDEF";
    const unsigned char* in = (const unsigned char*) (body ? body : "");
    size_t n = strlen((const char*) in);
    /* Worst case: every byte escaped (3x) plus a soft break every 25 escapes. */
    char* out = (char*) GC_MALLOC_ATOMIC(n * 3 + (n / 25 + 1) * 3 + 1);
    size_t j = 0, col = 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = in[i];
        if (c == '\r' && i + 1 < n && in[i + 1] == '\n') {
            out[j++] = '\r'; out[j++] = '\n'; col = 0; i++;
            continue;
        }
        /* Whitespace just before a line end (or at the very end) would be stripped in transit. */
        int endOfLine = (i + 1 == n) || (in[i + 1] == '\r' && i + 2 < n && in[i + 2] == '\n');
        int literal = (c >= 33 && c <= 126 && c != '=') || ((c == ' ' || c == '\t') && !endOfLine);
        size_t w = literal ? 1 : 3;
        if (col + w > 75) { out[j++] = '='; out[j++] = '\r'; out[j++] = '\n'; col = 0; }
        if (literal) { out[j++] = (char) c; }
        else { out[j++] = '='; out[j++] = hex[c >> 4]; out[j++] = hex[c & 15]; }
        col += w;
    }
    out[j] = 0;
    return (code_string) out;
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

/* Plaintext twins of expect/cmd above, for the pre-STARTTLS phase (port
 * 587): the greeting/EHLO/STARTTLS exchange happens in cleartext, BEFORE
 * any SSL object exists. Calling SSL_connect() immediately on a socket
 * whose peer is about to speak plaintext (as the implicit-TLS path did
 * unconditionally) races the server's unprompted "220 ..." greeting
 * against our TLS ClientHello — confirmed in practice against a real
 * STARTTLS-only server: the peer's plaintext bytes land mid-handshake,
 * OpenSSL misparses them as TLS framing, and recovery from that state
 * crashed the process (SIGABRT) instead of failing the handshake
 * cleanly. Identical line-reading logic to amalgame_smtp_expect, just
 * over the raw fd via read()/write() instead of SSL_read/SSL_write. */
static inline int amalgame_smtp_expect_plain(int fd, char expect) {
    char line[1024];
    int li = 0;
    char first = 0;
    int last_line = 0;
    char full[2048];
    int fi = 0;

    while (!last_line) {
        char ch;
        int n = read(fd, &ch, 1);
        if (n <= 0) {
            g_amalgame_smtp_last_error = "SMTP: connection closed while reading reply (STARTTLS phase)";
            return 0;
        }
        if (fi < (int)sizeof(full) - 1) full[fi++] = ch;
        if (ch == '\r') continue;
        if (ch == '\n') {
            line[li] = 0;
            if (li > 0) first = line[0];
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
        snprintf(msg, len + 32, "SMTP rejected (STARTTLS phase): %s", full);
        g_amalgame_smtp_last_error = msg;
        return 0;
    }
    return 1;
}

static inline int amalgame_smtp_cmd_plain(int fd, const char* line, char expect) {
    if (line && *line) {
        if (write(fd, line, strlen(line)) < 0) { /* fallthrough to expect(), which will report closed */ }
        if (write(fd, "\r\n", 2) < 0) { /* ditto */ }
    }
    return amalgame_smtp_expect_plain(fd, expect);
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
 * `to` is the ENVELOPE recipient list, not a header: it never feeds the
 * message headers (those come from `data`, built by the caller). It may
 * contain multiple addresses separated by '\n' — one RCPT TO issued per
 * non-empty entry. This is how Mail.Bcc() reaches an extra recipient
 * without that address ever appearing in the message (true BCC): the
 * caller appends bcc addresses to `to` but keeps the To: header built
 * from the primary recipient only.
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

    /* A write() to a socket the peer has already closed (rate-limiting,
     * greylisting, a mid-conversation reset...) raises SIGPIPE, which
     * kills the process by default in C — observed in practice on the
     * plaintext STARTTLS leg above. Ignore it process-wide so the write
     * just fails with EPIPE/-1 instead, letting the existing expect()/
     * cmd() error paths handle it like any other closed connection. Safe
     * to set unconditionally: a mail sender has no other use for SIGPIPE. */
    signal(SIGPIPE, SIG_IGN);

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

    /* Port 587 = submission, STARTTLS (RFC 3207): the connection starts
     * in cleartext, and TLS is negotiated via an explicit command —
     * different wire protocol from implicit TLS (465/SMTPS), not just a
     * different port number. Any port other than 587 keeps the original
     * v0.1 implicit-TLS behavior verbatim (in particular 465, the
     * ssl0.ovh.net/Gmail case this library already ships in production
     * for) — this branch adds a capability, it does not touch that path.
     */
    if (port == 587) {
        if (!amalgame_smtp_expect_plain(sock, '2')) goto cleanup;      /* server greeting, cleartext */
        {
            char ehlo[300];
            snprintf(ehlo, sizeof(ehlo), "EHLO %s", domain);
            if (!amalgame_smtp_cmd_plain(sock, ehlo, '2')) goto cleanup;
        }
        if (!amalgame_smtp_cmd_plain(sock, "STARTTLS", '2')) goto cleanup;

        SSL_library_init();
        ctx = SSL_CTX_new(TLS_client_method());
        if (!ctx) { g_amalgame_smtp_last_error = "SMTP: SSL_CTX_new failed"; goto cleanup; }
        ssl = SSL_new(ctx);
        if (!ssl) { g_amalgame_smtp_last_error = "SMTP: SSL_new failed"; goto cleanup; }
        SSL_set_fd(ssl, sock);
        SSL_set_tlsext_host_name(ssl, host);
        if (SSL_connect(ssl) != 1) { g_amalgame_smtp_last_error = "SMTP: TLS handshake failed (STARTTLS)"; goto cleanup; }

        /* RFC 3207: re-issue EHLO over the now-encrypted channel — the
         * pre-TLS capability list is untrusted (a MITM could have altered
         * it), and servers commonly only advertise AUTH post-TLS anyway
         * (confirmed in practice: AUTH PLAIN/LOGIN appeared only on the
         * second EHLO against mail.nidclair.fr). */
        {
            char ehlo2[300];
            snprintf(ehlo2, sizeof(ehlo2), "EHLO %s", domain);
            if (!amalgame_smtp_cmd(ssl, ehlo2, '2')) goto cleanup;
        }
    } else {
        /* TLS handshake (implicit — SMTPS). Unchanged from v0.1. */
        SSL_library_init();
        ctx = SSL_CTX_new(TLS_client_method());
        if (!ctx) { g_amalgame_smtp_last_error = "SMTP: SSL_CTX_new failed"; goto cleanup; }
        ssl = SSL_new(ctx);
        if (!ssl) { g_amalgame_smtp_last_error = "SMTP: SSL_new failed"; goto cleanup; }
        SSL_set_fd(ssl, sock);
        SSL_set_tlsext_host_name(ssl, host);
        if (SSL_connect(ssl) != 1) { g_amalgame_smtp_last_error = "SMTP: TLS handshake failed"; goto cleanup; }
    }

    /* SMTP conversation. Greeting + first EHLO already done for port 587
     * (cleartext, then re-issued over TLS right after STARTTLS above) —
     * only the implicit-TLS path still needs them here. */
    if (port != 587) {
        if (!amalgame_smtp_expect(ssl, '2')) goto cleanup;          /* server greeting */
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

        /* One RCPT TO per '\n'-separated envelope recipient (primary To
         * plus any Bcc addresses appended by the caller — see the
         * `to` doc comment above). */
        {
            const char* start = to ? to : "";
            int done = 0;
            while (!done) {
                const char* nl = strchr(start, '\n');
                size_t len = nl ? (size_t)(nl - start) : strlen(start);
                if (len > 0) {
                    char rcpt[600];
                    if (len >= sizeof(rcpt)) len = sizeof(rcpt) - 1;
                    memcpy(rcpt, start, len);
                    rcpt[len] = 0;
                    snprintf(line, sizeof(line), "RCPT TO:<%s>", rcpt);
                    if (!amalgame_smtp_cmd(ssl, line, '2')) goto cleanup;
                }
                if (!nl) { done = 1; } else { start = nl + 1; }
            }
        }

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
