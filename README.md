# amalgame-net-smtp

Minimal **SMTP client** for Amalgame — send transactional mail (contact
forms, notifications) over **implicit TLS** (SMTPS, port 465).

Part of the `Amalgame.Net.*` protocol family (alongside
[`amalgame-net-http`](https://github.com/amalgame-lang/amalgame-net-http)).
Outbound-send only; the broader mail slice (SMTP server/relay, IMAP,
POP3) is roadmap — see the ecosystem's `beyond-http.md`.

Two APIs:
- **`Smtp.Send(...)`** — one call, plain-text body (the simplest case).
- **`Mail.New()....Send(...)`** — a fluent builder for HTML bodies,
  text+HTML alternatives, and file attachments (v0.2).

## Install

```bash
amc package add net-smtp
```

## Prerequisites

OpenSSL 3.x (or LibreSSL — drop-in). Linked automatically via
`libs = ["ssl","crypto"]`.

| OS | Install |
|----|---------|
| Debian / Ubuntu | `sudo apt install libssl-dev` |
| Fedora / RHEL | `sudo dnf install openssl-devel` |
| macOS | `brew install openssl@3` |
| Windows / MSYS2 | `pacman -S mingw-w64-x86_64-openssl` |

## Usage

```amalgame
import Amalgame.Net.Smtp

public class Program {
    public static void Main(string[] args) {
        let ok: bool = Smtp.Send(
            "ssl0.ovh.net", 465,              // SMTP host + port (implicit TLS)
            "contact@example.com",            // SMTP auth user ("" → no AUTH)
            "the-smtp-password",              // SMTP auth password
            "contact@example.com",            // From
            "you@example.com",                // To
            "Hello",                          // Subject
            "Sent from Amalgame.")            // Body (text/plain, UTF-8)

        if (ok) {
            Console.WriteLine("sent")
        } else {
            Console.WriteLine("failed: " + Smtp.LastError())
        }
    }
}
```

### API

| Method | Returns | Notes |
|--------|---------|-------|
| `Smtp.Send(host, port, user, pass, from, to, subject, body)` | `bool` | `true` on a 250 after the data phase. `user=""` skips AUTH. Uses `AUTH LOGIN`. Adds `Date` + `Message-ID` automatically. |
| `Smtp.LastError()` | `string` | Human-readable reason for the last send that returned `false` (per-thread). |

## HTML & attachments — the `Mail` builder (v0.2)

For HTML mail, text+HTML alternatives, or file attachments, use the
fluent `Mail` builder. It assembles the MIME message (and the
`Date`/`Message-ID`/`MIME-Version` headers) for you, then sends via the
same transport core.

```amalgame
import Amalgame.Net.Smtp

public class Program {
    public static void Main(string[] args) {
        let ok: bool = Mail.New()
            .From("contact@example.com")
            .To("client@example.com")
            .Subject("Votre facture")
            .Text("Version texte de secours.")            // optional
            .Html("<h1>Merci</h1><p>Facture en pièce jointe.</p>")
            .Attach("/path/to/invoice.pdf")               // 0..N attachments
            .Send("ssl0.ovh.net", 465, "user", "pass")

        if (!ok) { Console.WriteLine(Mail.LastError()) }
    }
}
```

The MIME shape is chosen automatically:

| Bodies set | Result |
|------------|--------|
| `.Text()` only | `text/plain` |
| `.Html()` only | `text/html` |
| both | `multipart/alternative` |
| any + `.Attach()` | `multipart/mixed` wrapping the above |

| Builder method | Notes |
|----------------|-------|
| `Mail.New()` | start a message |
| `.From(addr)` `.To(addr)` `.Subject(s)` | required envelope/headers |
| `.Text(body)` `.Html(body)` | set either or both |
| `.Attach(path)` | add a file (base64, `application/octet-stream`); call repeatedly |
| `.Send(host, port, user, pass)` | returns `bool`; `Mail.LastError()` on failure |

## Scope & limits

- **Implicit TLS only** (port 465). Plaintext and STARTTLS (port 587)
  are not implemented yet.
- **One recipient** per message (no CC/BCC yet).
- **`AUTH LOGIN`** only (base64 user/pass). No OAUTH2/XOAUTH2.
- Attachments are read fully into memory + base64 (fine for typical
  document sizes; not meant for very large files).
- Outbound only — no server/relay, no IMAP/POP3.

These cover the transactional case (contact form, notification,
invoice). Wider support is roadmap.

### Deliverability

Headers alone don't keep mail out of spam — the sending **domain** needs
**SPF + DKIM + DMARC** DNS records (DKIM especially, for Gmail/Outlook).
That's DNS config on your domain/provider, outside this package.

## Testing

```bash
./tests/run_tests.sh
```

Runs a C smoke against the runtime header: it confirms OpenSSL is
linked, the ABI of `Send`/`LastError` is sound, and a send to an
unreachable host fails cleanly. It does **not** send real mail.

### Real send

To verify an actual delivery, build a small consumer with your real
SMTP credentials and run it locally (don't commit the password):

```bash
amc package add net-smtp
amc build send.am -o send && ./send
```

## License

Apache-2.0 © 2026 Bastien MOUGET
