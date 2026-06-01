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

/*
 * Smtp.Send — send one message over implicit TLS (port 465).
 *
 * AM signature:
 *   public static bool Send(string host, int port,
 *                           string user, string pass,
 *                           string from, string to,
 *                           string subject, string body)
 *
 * Returns true on a 250 after the data phase, false otherwise
 * (inspect Smtp.LastError()). AUTH LOGIN is used when user is
 * non-empty.
 */
static inline code_bool Amalgame_Net_Smtp_Send(
        code_string host, i64 port,
        code_string user, code_string pass,
        code_string from, code_string to,
        code_string subject, code_string body) {

    g_amalgame_smtp_last_error = "";
    if (!host || !*host) { g_amalgame_smtp_last_error = "SMTP: empty host"; return 0; }

    int sock = -1;
    SSL_CTX* ctx = NULL;
    SSL* ssl = NULL;
    code_bool ok = 0;

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
    if (!amalgame_smtp_cmd(ssl, "EHLO amalgame", '2')) goto cleanup;

    if (user && *user) {
        if (!amalgame_smtp_cmd(ssl, "AUTH LOGIN", '3')) goto cleanup;
        if (!amalgame_smtp_cmd(ssl, amalgame_smtp_b64(user), '3')) goto cleanup;
        if (!amalgame_smtp_cmd(ssl, amalgame_smtp_b64(pass ? pass : ""), '2')) goto cleanup;
    }

    {
        /* MAIL FROM / RCPT TO use the bare addresses. */
        char line[1024];
        snprintf(line, sizeof(line), "MAIL FROM:<%s>", from ? from : "");
        if (!amalgame_smtp_cmd(ssl, line, '2')) goto cleanup;
        snprintf(line, sizeof(line), "RCPT TO:<%s>", to ? to : "");
        if (!amalgame_smtp_cmd(ssl, line, '2')) goto cleanup;
        if (!amalgame_smtp_cmd(ssl, "DATA", '3')) goto cleanup;

        /* Headers + body, terminated by a lone ".". */
        char* hdr = (char*) GC_MALLOC_ATOMIC(
            (from?strlen(from):0) + (to?strlen(to):0) +
            (subject?strlen(subject):0) + (body?strlen(body):0) + 256);
        sprintf(hdr,
            "From: %s\r\nTo: %s\r\nSubject: %s\r\n"
            "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s",
            from?from:"", to?to:"", subject?subject:"", body?body:"");
        SSL_write(ssl, hdr, (int)strlen(hdr));
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

#else  /* !AMALGAME_SMTP_HAVE_SSL */

static inline code_bool Amalgame_Net_Smtp_Send(
        code_string host, i64 port,
        code_string user, code_string pass,
        code_string from, code_string to,
        code_string subject, code_string body) {
    (void)host;(void)port;(void)user;(void)pass;(void)from;(void)to;(void)subject;(void)body;
    g_amalgame_smtp_last_error =
        "SMTP: built without OpenSSL — install libssl-dev and rebuild";
    return 0;
}

#endif /* AMALGAME_SMTP_HAVE_SSL */

#endif /* AMALGAME_NET_SMTP_H */
