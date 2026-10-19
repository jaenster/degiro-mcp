//! Generated with openssl: a throwaway 2048-bit key, used only by the jwt tests.
pub const issuer = "https://id.example/application/o/degiro-mcp/";
pub const audience = "client-123";
pub const iat: i64 = 1760000000;
pub const jwks =
    \\{"keys": [{"kty": "EC", "kid": "x"}, {"kty": "RSA", "kid": "k1", "use": "sig", "alg": "RS256", "n": "AJ76KTLib4DgwzkK7kDVWwYJYn5SSwQRPgsVGmQbUjnqjoH18uOkHoEkFFqQEeBLC7wKuufWsBrwNwS8jQOBzPIbNtjwCycp9j6s-BFgnsE-1wNMRL0Z7PdPaqZO4BTA1BMBLGGRj0X2V2mL8HXfwU2zbcllforoYWmpRgTL0YgALyvr9GIqsPhoyrAFw-kq6tIZXTk3zLmjVho__N4WGv7ECRuSJbxqDC0yrhN2y71gPq70UFhTSsAG9lXJKOZZjmZ7OWVSD9DmDDUldiylgcbi7tfCYAV-_ZHtr0hrQ4NiaHOwf1bHavH72LFAoRXoAY9D--fbnTJwRbt8Qjt8ULM", "e": "AQAB"}]}
;
pub const token = "eyJhbGciOiAiUlMyNTYiLCAia2lkIjogImsxIiwgInR5cCI6ICJKV1QifQ.eyJpc3MiOiAiaHR0cHM6Ly9pZC5leGFtcGxlL2FwcGxpY2F0aW9uL28vZGVnaXJvLW1jcC8iLCAiYXVkIjogImNsaWVudC0xMjMiLCAic3ViIjogInUxIiwgImVtYWlsIjogInRlc3RAZXhhbXBsZS5jb20iLCAiaWF0IjogMTc2MDAwMDAwMCwgImV4cCI6IDE3NjAwMDM2MDB9.VSY_UAmyeGX5HRGo_eWyRhX_2nAJyvFlcOqsVkWYcZmYeGDl41Hxav034k5sGCnbP_pun0wi-bpZLkNjIQ1hLAmPgFhV-j2Z5Jt3kGx2SbFBeg4Bq2qGrQppdTeeH6q--IVAcn7yr99eqNkTNm3H0gFY_VM0MqIKTakdQ4LJdwXaS6_0E8VRhKLKEn19x_fgcO5TqVJA9l26ZC4WmF8iH8JTXw7QvnmHyqQhCtV7MRVptd5-uwIjDapkCZNOgJt6k6cQ0a16DPh728sWGmcFZDUszT1nXJAsjajHICXM5xipJURxDhm7145GJGJ1mtN3jXnFjo00JQDUNvPcIppnlA";
