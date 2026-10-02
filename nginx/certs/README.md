# TLS certificates

`nginx/conf.d/secureshare.conf` expects `server.crt` and `server.key` here.
They are **not** committed (see `.gitignore`).

Local development / demo (self-signed, 1 year):

```bash
openssl req -x509 -newkey rsa:4096 -sha256 -days 365 -nodes \
  -keyout nginx/certs/server.key -out nginx/certs/server.crt \
  -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
chmod 600 nginx/certs/server.key
```

Production: use a real certificate (Let's Encrypt / your CA). Do not disable
certificate verification in any client to work around a self-signed cert.
