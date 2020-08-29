# Incredibly easy login for your website 

Adding authentication to your website is hard.

Implementing [password storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html), [protection against password bruteforce/login enumeration](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html), [reset lost password feature](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html) or even  [multi-factor authentication](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html) is notoriously hard to implement and get it right.

It is often considered easier and more secure to use a pre-made solution that is proven secure.

An open source solution is [keycloak](https://www.keycloak.org/) developped by [Red Hat](https://www.redhat.com/). 
It acts a a [Single Sign-on](https://en.wikipedia.org/wiki/Single_sign-on) portal that implements all the features listed above.
It is easy to configure using their user interface.

## What are we going to build?

We will assume that you have a Single Page Application (i.e using React or Angular). 
You can adapt the instructions of this tutorial if you are using a more traditional server generated website.

This web application is probably hitting HTTP backend endpoints (for instance REST APIs or GraphQL APIs) in order to fetch or mutate data.  

These APIs should probably be secured and only allow authenticated users.

Using the [OpenID Connect](https://openid.net/connect/) allows you to implement these flows.
After following the *OpenID Connect* authentication flow, the web application will get a **token** that can be used to query backend services.

OpenID Connect flows are hard to implement correctly, we are going to use trusted implementation that will do the heavy lifting for us!

## Part 0: Set-up a keycloak server

*Prerequisite*: Install a keycloak server on your server.
If your server supports docker, you can quickly spin-up a container using [this tutorial](https://www.keycloak.org/getting-started/getting-started-docker).

Make sure your keycloak server is accessible via **HTTPS** on your domain (can be a subdomain), i.e: `auth.mydomain.com`.

## Part 1: Minimal Keycloak configuration

Follow [keycloak documentation](https://www.keycloak.org/docs/latest/getting_started/index.html) and create a **realm** and a user for your website.

You can browse through the option that keycloak provides and activate features. 

Example:
* registration forms with forgot password feature
* brute force protection
* one-time passwords
* allow users to use their Google/Instagram/Github accounts

After you have configured your keycloak server you should be able to log in to your realm using the user you created.

## Part 2: Set up your web application to authenticate your users

Your keycloak server will serve a Javascript library that you can directly import in your code. 
Import it in your application.
```html
<script src="https://auth.mydomain.com/auth/js/keycloak.js"></script>
```

Once you have imported you start using the library:
```js
var keycloak = new Keycloak();
keycloak.init({}, function(authenticated) {}, function() {})
```

Please check the [Keycloak documentation](https://www.keycloak.org/docs/latest/securing_apps/#_javascript_adapter) to learn about how to use this library.

Here is a minimal example of an application that authenticates users.
```html
<html>
  <head>
    <script src="https://auth.mydomain.com/auth/js/keycloak.js"></script>
     <script>
        var keycloak = new Keycloak();
        keycloak.init({
          onLoad: 'login-required', // Will redirect the user to the login page if they are not logged-in yet.
          pkceMethod: 'S256',       // Will enable the OAuth PKCE flow, the most secure flow for Single Page Applications.
        }).then(function(authenticated) {
            document.getElementById('token').innerText = keycloak.token;
        }).catch(function() {
            alert('failed to initialize');
        });
    </script>
  </head>
  <body>
    <p>Token: <span id="token"></span></p>
  </body>
</html>
```

Try pasting that in a file, and opening it with your browser. 
It should redirect you to the login page and back to your HTML page with a token.

You can use this token to access protected APIs.

## Part 3: Protecting your backend API with tokens

This tutorial is agnostic to the language you are using for your backend system.

We are going to set-up a proxy in front of your API that will make sure that all the requests are authenticated and that will forward the user information to your API.
It will be transparent for the backend service, you will not have to use any library (that might be vulnerable/outdated).

```
+---------------+ API request  +-----------------+   Authenticated request   +------------------+
|               |   + token    |                 |   + user information      |                  |
|Web application|              | Authentication  |                           | Your backend API |
|     (SPA)     +-------------->     proxy       +--------------------------->                  |
|               |              |                 |                           |                  |
+---------------+              +-----------------+                           +------------------+
```

The authentication proxy that we are going to use is [NGINX](https://www.nginx.com/) with an [OpenResty](https://github.com/openresty/) plugin called [lua-resty-oidc](https://github.com/zmartzone/lua-resty-openidc).

You can spin-up a docker container like using a Dockerfile like so:
```
FROM openresty/openresty:buster-fat
RUN opm install zmartzone/lua-resty-openidc
EXPOSE 80
```

Expose the port 80 and bind mount a file in `/usr/local/openresty/nginx/conf/nginx.conf`. (I will let you find the proper docker command / docker-compose config for that).

You can also install openresty locally following the instructions on the github repository.


You will need to have a client created on Keycloak:
* Go to your admin panel.
* Go the the `Clients` category.
* Create a client.
* Change the `Access type` to `Confidential`.
* Go `Credential` tab and save your `Secret`.

Here is a sample `nginx.conf` that you can use. 
Don't forget to replace the value of `introspection_endpoint`,  `client_id`, `client_secret` and `proxy_pass`.

```
events {
  worker_connections 128;
}

http {

  lua_package_path '~/lua/?.lua;;';

  resolver 8.8.8.8;

  lua_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;
  lua_ssl_verify_depth 5;

  # cache for validation results
  lua_shared_dict introspection 10m;

  server {
    listen 80;

    location / {

      access_by_lua '

          local opts = {
             introspection_endpoint="https://auth.mydomain.com/auth/realms/<INSERT YOUR REALM NAME HERE>/protocol/openid-connect/token/introspect",
             client_id="<INSERT YOUR CLIENT HERE>",
             client_secret="<INSERT YOUR CLIENT SECRET HERE>",
          }

          -- call introspect for OAuth 2.0 Bearer Access Token validation
          local res, err = require("resty.openidc").introspect(opts)

          if err then
            ngx.status = 403
            ngx.say(err)
            ngx.exit(ngx.HTTP_FORBIDDEN)
          end

          -- All these headers will be attached to the calls made to your backend.
          ngx.req.set_header("X-AUTH-SUB", res.sub) -- The most important header, will be the unique ID of the user that is authenticated.
          ngx.req.set_header("X-AUTH-EMAIL", res.email) -- Email of the user.
          ngx.req.set_header("X-AUTH-USERNAME", res.username) -- Username of the user.
          ngx.req.set_header("X-AUTH-ROLES", res.realm_access.roles) -- Roles of the user.

          ngx.req.set_header("X-AUTH-AZP", res.azp)
          ngx.req.set_header("X-AUTH-IAT", res.iat)
          ngx.req.set_header("X-AUTH-ISS", res.iss)
          ngx.req.set_header("X-AUTH-NONCE", res.nonce)
          ngx.req.set_header("X-AUTH-FAMILY_NAME", res.family_name)
          ngx.req.set_header("X-AUTH-AUTH_TIME", res.auth_time)
          ngx.req.set_header("X-AUTH-ACTIVE", res.active)
          ngx.req.set_header("X-AUTH-EMAIL_VERIFIED", res.email_verified)
          ngx.req.set_header("X-AUTH-SCOPE", res.scope)
          ngx.req.set_header("X-AUTH-AUD", res.aud)
          ngx.req.set_header("X-AUTH-SESSION_STATE", res.session_state)
          ngx.req.set_header("X-AUTH-ACR", res.acr)
          ngx.req.set_header("X-AUTH-CLIENT_ID", res.client_id)
          ngx.req.set_header("X-AUTH-GIVEN_NAME", res.given_name)
          ngx.req.set_header("X-AUTH-EXP", res.exp)
          ngx.req.set_header("X-AUTH-PREFERRED_USERNAME", res.preferred_username)
          ngx.req.set_header("X-AUTH-JTI", res.jti)
          ngx.req.set_header("X-AUTH-NAME", res.name)
          ngx.req.set_header("X-AUTH-TYP", res.typ)
      ';
      proxy_pass 'http://sample-app:8080/'; -- CHANGEME: Put the address of your backend API there.
    }
  }
}
```

Launch the proxy, and any call made to the API using a token will be forwarded to your backend API. 
Any call using an invalid token / no token will be rejected with a HTTP 403 error.

The proxy will also attach headers to the request so your backend can identify the user. 
You can use `X-AUTH-SUB` which is the [Universally unique identifier (UUID)](https://en.wikipedia.org/wiki/Universally_unique_identifier) of the user.
The email and username will also be attached as headers.

You will also get all the roles of the user for that realm using the `X-AUTH-ROLES` header (admin, moderator, user...).

The good thing about this proxy is that if you get a call to your backend, you already know that it is authenticated and you do not have to add any code to verify that. 
You can focus on writing your business logic.

## Part 4: Glueing things together and wrapping up.

Now that you have a HTML page that supports authentication and an API that is protected, you can link the two.

Call your API from your web application, [see keycloak documentation](https://www.keycloak.org/docs/latest/securing_apps/#_javascript_adapter):

```js
var req = new XMLHttpRequest(); // (or use fetch API)
req.open('GET', 'https://my-auth-proxy.mydomain.com/my_api', true);
req.setRequestHeader('Accept', 'application/json');
req.setRequestHeader('Authorization', 'Bearer ' + keycloak.token); // <-- This is the important part, pass your token there.
```

And you have a working secure authentication for your website and your API! 
No need to re-implement any security function, you get a secure API out-of-the box!
