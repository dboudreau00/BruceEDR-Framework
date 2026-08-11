# Indicator feeds

Drop plain-text indicator files here (`*.txt`, `*.ioc`, `*.csv`) and ProcessShield loads
them at startup. A match on a process image hash, a resolved domain or a remote address
scores the process by `intel.hitScore` from `shield.config.json`.

One indicator per line. The type is detected from the shape of the line, so you do not
have to declare it:

```
# a comment; blank lines are ignored
44d88612fea8a8f36de82e1278abb02f                                   ; eicar md5
275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f   ; eicar sha256
evil-c2.example                                                    ; matches sub.evil-c2.example too
203.0.113.44
198.51.100.0/24
2001:db8:dead::/48
url:/gate.php                                                      ; substring of a URL
```

Everything after a `;` is a free-text label carried into the alert.

## Notes

- Domain entries match the domain **and every subdomain of it**. `evil.example` therefore
  matches `a.b.evil.example`. It does *not* match `notevil.example`.
- CIDR entries are matched by byte-wise prefix comparison, for both IPv4 and IPv6.
- Lookups are hash-set based, so a feed with a million entries costs the same per event as
  one with ten.
- These are *your* indicators. ProcessShield ships no third-party feed, because feed
  redistribution terms vary and shipping someone else's list without checking is how open
  source projects acquire licensing problems.
