# UAA-Server 

Here is a sample README file explaining how to use the provided `curl` command to obtain an OAuth2 token from a Spring Boot application:

---

# OAuth2 Token Request

This document provides instructions for obtaining an OAuth2 token using the `curl` command in a Spring Boot application.

## Prerequisites

- Ensure that your Spring Boot application is running on `http://localhost:8085`.
- You have valid client credentials (`client_id` and `client_secret`).
- You have a user account with a username and password.


## Command Breakdown

- `--location 'http://localhost:8085/oauth2/token'`: Specifies the URL for the OAuth2 token endpoint.
- `--header 'Content-Type: application/x-www-form-urlencoded'`: Sets the content type of the request to `application/x-www-form-urlencoded`.
- `--header 'Authorization: Basic bXljbGllbnRpZDpteWNsaWVudHNlY3JldA=='`: Provides the basic authorization header with the Base64-encoded client credentials (`client_id:client_secret`).
  - In this example, `bXljbGllbnRpZDpteWNsaWVudHNlY3JldA==` is the Base64-encoded string of `myclientid:myclientsecret`.
- `--header 'Cookie: JSESSIONID=4DC4896AC338D1D15EC0FE8D2B500156'`: (Optional) Includes a session cookie if needed for the request.
- `--data-urlencode 'username=alex@gmail.com'`: Provides the username for the resource owner.
- `--data-urlencode 'password=123456'`: Provides the password for the resource owner.
- `--data-urlencode 'grant_type=password'`: Specifies the grant type as `password`.

## Example

To run the command, open a terminal and paste the following command:

```sh
curl --location 'http://localhost:8085/oauth2/token' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--header 'Authorization: Basic bXljbGllbnRpZDpteWNsaWVudHNlY3JldA==' \
--header 'Cookie: JSESSIONID=4DC4896AC338D1D15EC0FE8D2B500156' \
--data-urlencode 'username=alex@gmail.com' \
--data-urlencode 'password=123456' \
--data-urlencode 'grant_type=password'
```

Upon successful execution, the command will return a JSON response containing the OAuth2 token.

## Notes

- Replace `myclientid` and `myclientsecret` with your actual client ID and client secret.
- Replace `alex@gmail.com` and `123456` with the actual username and password of the resource owner.
- If the server requires a session cookie, ensure that the `JSESSIONID` is correctly set.

---

This README file should help you understand and execute the `curl` command for obtaining an OAuth2 token in a Spring Boot application.