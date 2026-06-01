# amalgame-net-smtp

Minimal **SMTP client** for Amalgame — send transactional mail (contact
forms, notifications) over **implicit TLS** (SMTPS, port 465).

Part of the `Amalgame.Net.*` protocol family (alongside
[`amalgame-net-http`](https://github.com/amalgame-lang/amalgame-net-http)).
v0.1 is outbound-send only; the broader mail slice (SMTP server/relay,
IMAP, POP3) is roadmap — see the ecosystem's `beyond-http.md`.

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
| `Smtp.Send(host, port, user, pass, from, to, subject, body)` | `bool` | `true` on a 250 after the data phase. `user=""` skips AUTH. Uses `AUTH LOGIN`. |
| `Smtp.LastError()` | `string` | Human-readable reason for the last `Send` that returned `false` (per-thread). |

## Scope & limits (v0.1)

- **Implicit TLS only** (port 465). Plaintext and STARTTLS (port 587)
  are not implemented yet.
- **One recipient** per call, **text/plain** body. No attachments, no
  multipart, no CC/BCC headers yet.
- **`AUTH LOGIN`** only (base64 user/pass). No OAUTH2/XOAUTH2.
- Outbound only — no server/relay, no IMAP/POP3.

These cover the transactional case (contact form → one mailbox). Wider
support is roadmap.

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
