The module is experimental just for tests.
To build it you need openssl, nghttp3 and ngtcp2 installed.
```
./configure --enable-http3
```
To use the QUIC server of OpenSSL 3.5 or later instead of ngtcp2 (no 0-RTT, no connection ID routing):
```
./configure --enable-http3 --with-http3-quic=openssl
```
To test use Firefox, Chrome or curl, Chrome is picky with the certicates.
```
LoadModule ssl_module     modules/mod_ssl.so
LoadModule http3_module   modules/mod_http3.so

EnableMMAP Off
Listen 4433 https
CoreDumpDirectory /tmp
H3MaxConnections 8000
H3HandshakeTimeout 30

<VirtualHost *:4433>
    ServerName localhost

    SSLEngine on
    SSLCertificateFile conf/localhost-fullchain.crt
    SSLCertificateKeyFile conf/localhost.key

    Protocols h3 h2 http/1.1

    DocumentRoot htdocs
    <Directory htdocs>
        Require all granted
    </Directory>
</VirtualHost>
```
All the connections are going to single process with --with-http3-quic=openssl, which is slow for the moment, so DON'T use it in production.                                                                                                                                                                                      
