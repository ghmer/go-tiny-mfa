# go-tiny-mfa
a tinymfa implementation written in go. See https://tinymfa.parzival.link for more information.

Our repository on github: https://github.com/ghmer/go-tiny-mfa.

Find a docker repository at https://hub.docker.com/r/tinymfa/go-tiny-mfa

Checkout our postman collection: https://tinymfa.parzival.link/tinymfa.postman_collection.json


**Attention** This is a hobby project to get more used to go-programming. It is **not** intended to be used in a production environment without making further security related steps.

## How it works
 1. tinymfa connects to a postgres database and creates the required table structures. Then, it generates a root encryption key and access token. The encryption key is stored on the filesystem.
 2. when creating an issuer, a new encryption key is generated, encrypted with the root encryption key and then stored to the database. Also, an access token unique to this issuer is generated as well.
 3. when creating a user below an issuer, a new secret key is generated and encrypted with the issuer encryption key.
 4. The api offers an endpoint to generate a QRCode for a user. Use this to let the user register their secret key in an Authenticator App
 5. The api offers an endpoint to validate a token. Send the token using a http post request to the api interface. The resulting json object contains the boolean result of the validation.

## Access tokens
tinymfa can be configured to validate access to its resources. Once activated, tinymfa checks for presence of the http header key 'tiny-mfa-access-token'. This must be either the root token created on installation, or the issuer token presented upon issuer creation.

## API Endpoints
### System Configuration and Audit
Endpoint|Method|Description
--- | --- | ---
/api/v1/system/audit|GET|Return audit entries
/api/v1/system/configuration|GET|Return current system configuration
/api/v1/system/configuration|POST|Updates the system configuration

#### payload: Update system configuration
key|type|description
--- | --- | ---
http_port|integer|the port to run on. Requires a restart!
deny_limit|integer|how many times is a user allowed to input a wrong token before we don't allow validation for the given message. This is to defeat brute force attacks
veriy_token|boolean|whether to verify if the *tiny-mfa-access-token* is set and contains a valid token

```
{
    "http_port" : 57687,
    "deny_limit": 3,
    "verify_tokens": true
}
```

### OIDC Configuration
Endpoint|Method|Description
--- | --- | ---
/api/v1/system/oidc|GET|Return current oidc configuration
/api/v1/system/oidc|POST|Updates the oidc configuration

#### payload: Update oidc configuration
key|type|description
--- | --- | ---
enabled|boolean|whether to enable the oidc configuration
client_id|string|the oidc client ID
client_secret|string|the oidc client secret
discovery_url|string|the oidc discovery url, omitting the /.well_known directory
```
{
    "enabled" : true,
    "client_id": "my-client-id",
    "client_secret": "myClientSecret123!",
    "discovery_url": "https://idp.tld/auth/realm"
}
```

### QR Code Look & Feel
Endpoint|Method|Description
--- | --- | ---
/api/v1/system/qrcode|GET|Return current qrcode look & feel
/api/v1/system/qrcode|POST|Update the qrcode look & feel

#### payload: update qrcode look & feel
```
{
    "qrcode-bgcolor": {
        "red": 255,
        "green": 255,
        "blue": 255,
        "alpha": 255
    },
    "qrcode-fgcolor": {
        "red": 0,
        "green": 0,
        "blue": 0,
        "alpha": 255
    }
}
```

### Issuer handling
Endpoint|Method|Description
--- | --- | ---
/api/v1/issuer|GET|Return all registered issuers
/api/v1/issuer|POST|Create a new issuer using a POST request
/api/v1/issuer/{issuer}|GET|Return a distinct issuer by its name
/api/v1/issuer/{issuer}|POST|Updates a distinct issuer using a POST request
/api/v1/issuer/{issuer}|DELETE|Deletes a distinct issuer using a DELETE request

#### payload: create a new issuer
key|type|description
--- | --- | ---
name|string|the name of this issuer
contact|string|a mail adress of the responsible person
token_length|integer|Length of the desired totp tokens
enabled|boolean|whether this issuer is active

```
{
    "name": "issuer.local",
    "contact": "demo@issuer.local",
    "token_length": 6,
    "enabled": true
}
```

#### payload: update a new issuer
key|type|description
--- | --- | ---
contact|string|a mail adress of the responsible person
token_length|integer|Length of the desired totp tokens
enabled|boolean|whether this issuer is active

```
{
    "contact": "demo@issuer.local",
    "token_length": 8,
    "enabled": true
}
```

### Access token handling
Endpoint|Method|Description
--- | --- | ---
/api/v1/issuer/{issuer}/token|GET|Return all registered access tokens for a given issuer
/api/v1/issuer/{issuer}/token|POST|Creates a new access token for the given issuer using a PUT request
/api/v1/issuer/{issuer}/token/{tokenid}|DELETE|Deletes a distinct access token in the scope of a distinct issuer

#### payload: create a new issuer access token
key|type|description
--- | --- | ---
description|string|a description for the new token

```
{
    "description" : "my access token"
}
```

### User handling
Endpoint|Method|Description
--- | --- | ---
/api/v1/issuer/{issuer}/users|GET|Return all users belonging to the scope of a distinct issuer
/api/v1/issuer/{issuer}/users|POST|Create a new user in the scope of a distinct issuer
/api/v1/issuer/{issuer}/users/{user}|GET|Return a distinct user in the scope of a distinct issuer
/api/v1/issuer/{issuer}/users/{user}|POST|Update a distinct user in the scope of a distinct issuer
/api/v1/issuer/{issuer}/users/{user}|DELETE|Deletes a distinct user in the scope of a distinct issuer

#### payload: create a new user
key|type|description
--- | --- | ---
name|string|the name this user
email|string|a mail adress of the user
enabled|boolean|whether this user is active

```
{
    "name" : "demo",
    "email": "demo@issuer.local",
    "enabled": true
}
```

#### payload: update an existing user
key|type|description
--- | --- | ---
email|string|a mail adress of the user
enabled|boolean|whether this user is active

```
{
    "email": "demo.address@issuer.local",
    "enabled": true
}
```

### User token handling
Endpoint|Method|Description
--- | --- | ---
/api/v1/issuer/{issuer}/users/{user}/totp|GET|Generates and returns a PNG image of a QRCode in the scope of a distinct user and issuer
/api/v1/issuer/{issuer}/users/{user}/totp|POST|Validates a given token in the scope of a distinct user and issuer

#### payload: validate a totp token
key|type|description
--- | --- | ---
token|string|the token to validate

```
{
    "token": "123456"
}
```

## docker-compose
This should result in a working tiny-mfa instance:
```
version: "3"
services:
    database:
        image: postgres:12-alpine
        networks: 
            - tiny-mfa-net
        volumes:
            - data:/var/lib/postgresql/data
        environment: 
            - POSTGRES_USER=postgres
            - POSTGRES_PASSWORD=postgres
            - POSTGRES_DB=tinymfa
        restart: unless-stopped
    
    tinymfa:
        image: tinymfa/go-tiny-mfa:latest
        networks:
            - tiny-mfa-net
        ports:
            - "57687:57687"
        volumes:
            - tinysecret:/opt/go-tiny-mfa/secrets
        environment:
            - POSTGRES_HOST=database
            - POSTGRES_USER=postgres
            - POSTGRES_PASSWORD=postgres
            - POSTGRES_DB=tinymfa
        restart: unless-stopped
        depends_on:
            - database

volumes: 
    data:
    tinysecret:

networks: 
    tiny-mfa-net:

```

## quickstart
- create a tiny-mfa instance using the docker-compose script from above
- create an issuer: 

```
curl --location --request POST 'http://localhost:57687/api/v1/issuer' \
--header 'Content-Type: application/json' \
--data-raw '{
    "name": "issuer.local",
    "contact": "contact@issuer.local",
    "token_length:" 6,
    "enabled": true
}'
```

- create a user: 

```
curl --location --request POST 'http://localhost:57687/api/v1/issuer/issuer.local/users' \
--header 'Content-Type: application/json' \
--data-raw '{
    "name" : "demo",
    "email": "demo@issuer.local",
    "enabled": true
}'
```

- get the QRCode for the Authenticator App:

```
curl --location --request GET 'http://localhost:57687/api/v1/issuer/issuer.local/users/demo/totp'
```

- validate a token

```
curl --location --request POST 'http://localhost:57687/api/v1/issuer/issuer.local/users/demo/totp' \
--header 'Content-Type: application/json' \
--data-raw '{
    "token" : "123456"
}'
```

## Already working
 - v1 api to CRUD issuers and users
 - validate tokens
 - limit validation attempts to defeat brute force attacks
 - generate QRCode png images
 - basic authorization via http header

## Todo
 - authorization model
 - administrative UI
 - think about generic middleware concept
 - openid-connect
 - ...