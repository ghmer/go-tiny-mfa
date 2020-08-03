# go-tiny-mfa
a tinymfa implementation written in go.

**Attention** This is a hobby project to get more used to go-programming. It is **not** intended to be used in a production environment without making further security related steps.

## How it works
 1. tinymfa connects to a postgres database and creates the required table structures. Then, it generates a root encryption key and access token. The encryption key is stored on the filesystem.
 2. when creating an issuer, a new encryption key is generated, encrypted with the root encryption key and then stored to the database. Also, an access token unique to this issuer is generated as well.
 3. when creating a user below an issuer, a new secret key is generated and encrypted with the issuer encryption key.
 4. The api offers an endpoint to generate a QRCode for a user. Use this to let the user register their secret key in an Authenticator App
 5. The api offers an endpoint to validate a token. Send the token using a http get request to the api interface. The resulting json object contains the boolean result of the validation.

## Access tokens
tinymfa can be configured to validate access to its resources. Once activated, tinymfa checks for presence of the http header key 'tiny-mfa-access-token'. This must be either the root token created on installation, or the issuer token presented upon issuer creation.

## Already working
 - v1 api to CRUD issuers and users
 - validate tokens
 - limit validation attempts to defeat brute force attacks
 - generate QRCode png images
 - basic authorization via http header

## Todo
 - authorization model
 - administrative UI
 - ...