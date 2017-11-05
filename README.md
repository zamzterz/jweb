# jweb

Basic CLI application for demonstration and experimentation with JSON Web Encryption (JWE, 
[RFC 7516](https://tools.ietf.org/html/rfc7516)).

## Usage

* To view the help text: `jweb-cli --help`
* To create an encrypted JWT: `jweb-cli encrypt <claims/data to encrypt> <path to public RSA key>`
* To decrypt a JWE: `jweb-cli decrypt <jwe> <path to private RSA key>`
