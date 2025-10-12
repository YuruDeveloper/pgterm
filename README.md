# pgterm

**Lightweight PostgreSQL SSL Termination Proxy**

A simple, high-performance proxy that terminates SSL/TLS connections from PostgreSQL clients and forwards them as plaintext to your backend (HAProxy, PostgreSQL, etc.).

> Forked from [pgt-proxy](https://github.com/ambarltd/pgt-proxy) and simplified by removing backend TLS requirements.

## Why pgterm?

PostgreSQL uses a unique TLS handshake that requires bidirectional transmission of special bytes before initiating the standard TLS handshake. This means:

- ❌ **nginx** can't terminate PostgreSQL SSL
- ❌ **HAProxy** can't terminate PostgreSQL SSL  
- ❌ **Standard TLS proxies** don't work

**pgterm solves this** by understanding PostgreSQL's protocol and handling SSL termination properly.
