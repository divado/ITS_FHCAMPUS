= Appendix 1

 #v(0.5cm)

#align(center, block[
  #figure(
    ```bash
    $ ./testssl.sh --full --add-ca tls/nginx_test.crt localhost:443

      #####################################################################
        testssl.sh version 3.3dev from https://testssl.sh/dev/
        (1250d6f8 2025-11-29 22:38:18)

        This program is free software. Distribution and modification under
        GPLv2 permitted. USAGE w/o ANY WARRANTY. USE IT AT YOUR OWN RISK!

        Please file bugs @ https://testssl.sh/bugs/
      #####################################################################

        Using OpenSSL 1.0.2-bad (Mar 28 2025)  [~179 ciphers]
        on framework:./bin/openssl.Linux.x86_64

      Testing all IPv4 addresses (port 443): 127.0.0.1
      -------------------------------------------------------------------------------------------------------------------
      Start 2025-12-15 23:36:20        -->> 127.0.0.1:443 (localhost) <<--

      A record via:           /etc/hosts
      rDNS (127.0.0.1):       localhost.
      Service detected:       HTTP

      Testing protocols via sockets except NPN+ALPN

      SSLv2      not offered (OK)
      SSLv3      not offered (OK)
      TLS 1      not offered
      TLS 1.1    not offered
      TLS 1.2    offered (OK)
      TLS 1.3    offered (OK): final
      QUIC       Local problem: No OpenSSL QUIC support
      NPN/SPDY   not offered
      ALPN/HTTP2 http/1.1 (offered)

      Testing for server implementation bugs

      No bugs found.

      Testing cipher categories

      NULL ciphers (no encryption)                      not offered (OK)
      Anonymous NULL Ciphers (no authentication)        not offered (OK)
      Export ciphers (w/o ADH+NULL)                     not offered (OK)
      LOW: 64 Bit + DES, RC[2,4], MD5 (w/o export)      not offered (OK)
      Triple DES Ciphers / IDEA                         not offered
      Obsoleted CBC ciphers (AES, ARIA etc.)            offered
      Strong encryption (AEAD ciphers) with no FS       not offered
      Forward Secrecy strong encryption (AEAD ciphers)  offered (OK)


      Testing server's cipher preferences

      Hexcode  Cipher Suite Name (OpenSSL)       KeyExch.   Encryption  Bits     Cipher Suite Name (IANA/RFC)
      -----------------------------------------------------------------------------------------------------------------------------
      SSLv2
      -
      SSLv3
      -
      TLSv1
      -
      TLSv1.1
      -
      TLSv1.2 (no server order, thus listed by strength)
      xc030   ECDHE-RSA-AES256-GCM-SHA384       ECDH 521   AESGCM      256      TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
      xc028   ECDHE-RSA-AES256-SHA384           ECDH 521   AES         256      TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
      xcca8   ECDHE-RSA-CHACHA20-POLY1305       ECDH 521   ChaCha20    256      TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
      xc077   ECDHE-RSA-CAMELLIA256-SHA384      ECDH 521   Camellia    256      TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384
      xc061   ECDHE-ARIA256-GCM-SHA384          ECDH 521   ARIAGCM     256      TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384
      xc02f   ECDHE-RSA-AES128-GCM-SHA256       ECDH 521   AESGCM      128      TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
      xc027   ECDHE-RSA-AES128-SHA256           ECDH 521   AES         128      TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
      xc076   ECDHE-RSA-CAMELLIA128-SHA256      ECDH 521   Camellia    128      TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256
      xc060   ECDHE-ARIA128-GCM-SHA256          ECDH 521   ARIAGCM     128      TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256
      TLSv1.3 (no server order, thus listed by strength)
      x1302   TLS_AES_256_GCM_SHA384            ECDH/MLKEM AESGCM      256      TLS_AES_256_GCM_SHA384
      x1303   TLS_CHACHA20_POLY1305_SHA256      ECDH/MLKEM ChaCha20    256      TLS_CHACHA20_POLY1305_SHA256
      x1301   TLS_AES_128_GCM_SHA256            ECDH/MLKEM AESGCM      128      TLS_AES_128_GCM_SHA256

      Has server cipher order?     no (NOT ok)
      (limited sense as client will pick)

      Testing robust forward secrecy (FS) -- omitting Null Authentication/Encryption, 3DES, RC4

      FS is offered (OK)           TLS_AES_256_GCM_SHA384 TLS_CHACHA20_POLY1305_SHA256 ECDHE-RSA-AES256-GCM-SHA384 ECDHE-RSA-AES256-SHA384 ECDHE-RSA-CHACHA20-POLY1305
                                    ECDHE-RSA-CAMELLIA256-SHA384 ECDHE-ARIA256-GCM-SHA384 TLS_AES_128_GCM_SHA256 ECDHE-RSA-AES128-GCM-SHA256 ECDHE-RSA-AES128-SHA256
                                    ECDHE-RSA-CAMELLIA128-SHA256 ECDHE-ARIA128-GCM-SHA256
      KEMs offered                 X25519MLKEM768
      Elliptic curves offered:     prime256v1 secp384r1 secp521r1 X25519 X448
      Finite field group:          ffdhe2048 ffdhe3072
      TLS 1.2 sig_algs offered:    RSA-PSS-RSAE+SHA512 RSA-PSS-RSAE+SHA384 RSA-PSS-RSAE+SHA256 RSA+SHA512 RSA+SHA384 RSA+SHA256 RSA+SHA224
      TLS 1.3 sig_algs offered:    RSA-PSS-RSAE+SHA512 RSA-PSS-RSAE+SHA384 RSA-PSS-RSAE+SHA256

      Testing server defaults (Server Hello)

      TLS extensions (standard)    "server name/#0" "max fragment length/#1" "supported_groups/#10" "EC point formats/#11" "application layer protocol negotiation/#16"
                                    "encrypt-then-mac/#22" "extended master secret/#23" "supported versions/#43" "key share/#51" "renegotiation info/#65281"
      Session Ticket RFC 5077 hint no -- no lifetime advertised
      SSL Session ID support       yes
      Session Resumption           tickets no, ID: no
      TLS 1.3 early data support   no early data offered
      TLS clock skew               Random values, no fingerprinting possible
      Certificate Compression      none
      Client Authentication        none
      Signature Algorithm          SHA256 with RSA
      Server key size              RSA 4096 bits (exponent is 65537)
      Server key usage             --
      Server extended key usage    --
      Serial                       2CAD8D45D7ACEF3F00339C5BB56A42AE404F23B7 (OK: length 20)
      Fingerprints                 SHA1 04CD6B99F36DAC7F4DCCDB1B6C258EB2D53EC793
                                    SHA256 478AF59EAF01A4A237EE8571E8F1889D4991EB29675460E94ED4932F1D3B0978
      Common Name (CN)             localhost
      subjectAltName (SAN)         missing (NOT ok) -- Browsers are complaining
      Trust (hostname)             via CN only -- Browsers are complaining (same w/o SNI)
      Chain of trust               Ok
      EV cert (experimental)       no
      Certificate Validity (UTC)   364 >= 60 days (2025-12-15 22:07 --> 2026-12-15 22:07)
      ETS/"eTLS", visibility info  not present
      Certificate Revocation List  --
      OCSP URI                     --
                                    NOT ok -- neither CRL nor OCSP URI provided
      OCSP stapling                not offered
      OCSP must staple extension   --
      DNS CAA RR (experimental)    not offered
      Certificate Transparency     --
      Certificates provided        1
      Issuer                       localhost (HCW from AU)
      Intermediate Bad OCSP (exp.) Ok


      Testing HTTP header response @ "/"

      HTTP Status Code             200 OK
      HTTP clock skew              0 sec from localtime
      Strict Transport Security    not offered
      Public Key Pinning           --
      Server banner                nginx/1.29.4
      Application banner           --
      Cookie(s)                    (none issued at "/")
      Security headers             --
      Reverse Proxy banner         --


      Testing vulnerabilities

      Heartbleed (CVE-2014-0160)                not vulnerable (OK), no heartbeat extension
      CCS (CVE-2014-0224)                       not vulnerable (OK)
      Ticketbleed (CVE-2016-9244), experiment.  not vulnerable (OK), no session ticket extension
      Opossum (CVE-2025-49812)                  ./testssl.sh: line 1976: read: read error: 0: Connection reset by peer
      not vulnerable (OK)
      ROBOT                                     Server does not support any cipher suites that use RSA key transport
      Secure Renegotiation (RFC 5746)           supported (OK)
      Secure Client-Initiated Renegotiation     not vulnerable (OK)
      CRIME, TLS (CVE-2012-4929)                not vulnerable (OK)
      BREACH (CVE-2013-3587)                    no gzip/deflate/compress/br HTTP compression (OK)  - only supplied "/" tested
      POODLE, SSL (CVE-2014-3566)               not vulnerable (OK), no SSLv3 support
      TLS_FALLBACK_SCSV (RFC 7507)              No fallback possible (OK), no protocol below TLS 1.2 offered
      SWEET32 (CVE-2016-2183, CVE-2016-6329)    not vulnerable (OK)
      FREAK (CVE-2015-0204)                     not vulnerable (OK)
      DROWN (CVE-2016-0800, CVE-2016-0703)      not vulnerable on this host and port (OK)
                                                make sure you don't use this certificate elsewhere with SSLv2 enabled services, see
                                                https://search.censys.io/search?resource=hosts&virtual_hosts=INCLUDE&q=478AF59EAF01A4A237EE8571E8F1889D4991EB29675460E94ED4932F1D3B0978
      LOGJAM (CVE-2015-4000), experimental      not vulnerable (OK): no DH EXPORT ciphers, no DH key detected with <= TLS 1.2
      BEAST (CVE-2011-3389)                     not vulnerable (OK), no SSL3 or TLS1
      LUCKY13 (CVE-2013-0169), experimental     potentially VULNERABLE, uses cipher block chaining (CBC) ciphers with TLS. Check patches
      Winshock (CVE-2014-6321), experimental    not vulnerable (OK)
      RC4 (CVE-2013-2566, CVE-2015-2808)        no RC4 ciphers detected (OK)


      Running client simulations (HTTP) via sockets

      Browser                      Protocol  Cipher Suite Name (OpenSSL)       Forward Secrecy
      ------------------------------------------------------------------------------------------------
      Android 7.0 (native)         TLSv1.2   ECDHE-RSA-AES128-GCM-SHA256       256 bit ECDH (P-256)
      Android 8.1 (native)         TLSv1.2   ECDHE-RSA-AES128-GCM-SHA256       253 bit ECDH (X25519)
      Android 9.0 (native)         TLSv1.3   TLS_AES_128_GCM_SHA256            253 bit ECDH (X25519)
      Android 10.0 (native)        TLSv1.3   TLS_AES_128_GCM_SHA256            253 bit ECDH (X25519)
      Android 11/12 (native)       TLSv1.3   TLS_AES_128_GCM_SHA256            253 bit ECDH (X25519)
      Android 13/14 (native)       TLSv1.3   TLS_AES_128_GCM_SHA256            253 bit ECDH (X25519)
      Android 15 (native)          TLSv1.3   TLS_AES_128_GCM_SHA256            X25519MLKEM768
      Chrome 101 (Win 10)          TLSv1.3   TLS_AES_128_GCM_SHA256            253 bit ECDH (X25519)
      Chromium 137 (Win 11)        TLSv1.3   TLS_AES_128_GCM_SHA256            X25519MLKEM768
      Firefox 100 (Win 10)         TLSv1.3   TLS_AES_128_GCM_SHA256            253 bit ECDH (X25519)
      Firefox 137 (Win 11)         TLSv1.3   TLS_AES_128_GCM_SHA256            X25519MLKEM768
      IE 8 Win 7                   No connection
      IE 11 Win 7                  TLSv1.2   ECDHE-RSA-AES256-SHA384           256 bit ECDH (P-256)
      IE 11 Win 8.1                TLSv1.2   ECDHE-RSA-AES256-SHA384           256 bit ECDH (P-256)
      IE 11 Win Phone 8.1          TLSv1.2   ECDHE-RSA-AES128-SHA256           256 bit ECDH (P-256)
      IE 11 Win 10                 TLSv1.2   ECDHE-RSA-AES256-GCM-SHA384       256 bit ECDH (P-256)
      Edge 15 Win 10               TLSv1.2   ECDHE-RSA-AES256-GCM-SHA384       253 bit ECDH (X25519)
      Edge 101 Win 10 21H2         TLSv1.3   TLS_AES_128_GCM_SHA256            253 bit ECDH (X25519)
      Edge 133 Win 11 23H2         TLSv1.3   TLS_AES_128_GCM_SHA256            X25519MLKEM768
      Safari 18.4 (iOS 18.4)       TLSv1.3   TLS_AES_128_GCM_SHA256            253 bit ECDH (X25519)
      Safari 15.4 (macOS 12.3.1)   TLSv1.3   TLS_AES_128_GCM_SHA256            253 bit ECDH (X25519)
      Safari 18.4 (macOS 15.4)     TLSv1.3   TLS_AES_128_GCM_SHA256            253 bit ECDH (X25519)
      Java 7u25                    No connection
      Java 8u442 (OpenJDK)         TLSv1.3   TLS_AES_256_GCM_SHA384            253 bit ECDH (X25519)
      Java 11.0.2 (OpenJDK)        TLSv1.3   TLS_AES_128_GCM_SHA256            256 bit ECDH (P-256)
      Java 17.0.3 (OpenJDK)        TLSv1.3   TLS_AES_256_GCM_SHA384            253 bit ECDH (X25519)
      Java 21.0.6 (OpenJDK)        TLSv1.3   TLS_AES_256_GCM_SHA384            253 bit ECDH (X25519)
      go 1.17.8                    TLSv1.3   TLS_AES_128_GCM_SHA256            253 bit ECDH (X25519)
      LibreSSL 3.3.6 (macOS)       TLSv1.3   TLS_CHACHA20_POLY1305_SHA256      253 bit ECDH (X25519)
      OpenSSL 1.0.2e               TLSv1.2   ECDHE-RSA-AES256-GCM-SHA384       256 bit ECDH (P-256)
      OpenSSL 1.1.1d (Debian)      TLSv1.3   TLS_AES_256_GCM_SHA384            253 bit ECDH (X25519)
      OpenSSL 3.0.15 (Debian)      TLSv1.3   TLS_AES_256_GCM_SHA384            253 bit ECDH (X25519)
      OpenSSL 3.5.0 (git)          TLSv1.3   TLS_AES_256_GCM_SHA384            X25519MLKEM768
      Apple Mail (16.0)            TLSv1.2   ECDHE-RSA-AES256-GCM-SHA384       256 bit ECDH (P-256)
      Thunderbird (91.9)           TLSv1.3   TLS_AES_128_GCM_SHA256            253 bit ECDH (X25519)


      Rating (experimental)

      Rating specs (not complete)  SSL Labs's 'SSL Server Rating Guide' (version 2009r from 2025-05-16)
      Specification documentation  https://github.com/ssllabs/research/wiki/SSL-Server-Rating-Guide
      Protocol Support (weighted)  100 (30)
      Key Exchange     (weighted)  100 (30)
      Cipher Strength  (weighted)  90 (36)
      Final Score                  96
      Overall Grade                A+

      Done 2025-12-15 23:37:41 [  85s] -->> 127.0.0.1:443 (localhost) <<--

      -------------------------------------------------------------------------------------------------------------------
      Done testing now all IP addresses (on port 443): 127.0.0.1
    ```,
    caption: "Output of testssl.sh against the configured HTTPS server."
  )
])
 
 #pagebreak()