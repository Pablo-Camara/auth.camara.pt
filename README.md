# AuthServer
## API Specifications


### Authenticating the User

First thing you should do is authenticating the user.
You MUST send a POST request to /api/authenticate,

if the user is not yet authenticated , that request will create
a new Guest User, and a Guest Token returned in the response.

if the user is already authenticated, there will be an encrypted cookie
set with an array containing the 'at' (auth token), the user_id and 
and a 'guest' flag to tell if the user is logged in or not.

/api/authenticate will return a json with the 'at' (auth token),
this auth token must be stored on the client side for any subsequent
requests to this or other services.

example response:

```
{"at":"25|uHHmnjkwrBvIMhOCJmnxxWAdK9tqh9kteP6KlJeu"}
```

this auth token expires in 24 hours, after it expires the user will have to
get another guest user token, or login to get a logged in token (with potentially more abilities).

this token should be sent in the Authorization header:

example:

Authorization: Bearer 25|uHHmnjkwrBvIMhOCJmnxxWAdK9tqh9kteP6KlJeu



### Login User

To login an user, you must send a POST request to

/api/login

with the following params:
 - email 
 - password

and you MUST send the 'at' (auth token) that you received from /api/authenticate
in the Authorization header, example:

Authorization: Bearer 25|uHHmnjkwrBvIMhOCJmnxxWAdK9tqh9kteP6KlJeu

if that token is not sent, the /api/login endpoint will return a 401 Unauthorized response
with a json body like:
```
{"message": "Unauthenticated"}
```

if that token belongs to a guest user, and if the email/password are valid credentials,
the user will be logged in, this guest user id will be associated to the logged in account,
and the authentication (encrypted)cookie will be replaced with the new data (logged_in token, user_id, guest = 0)


if that token belongs to a non guest user, it means the user has already logged in
and a 406 Not Acceptable response will be returned, with a json body like:
```
{"message": "already logged in"}
```
