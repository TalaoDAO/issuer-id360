# KYC API for verifiable credential issuance

This api is used to extract identity datas from user to issue verifiables credentials in differents formats.

The process needs :
- a `client_id` that you can get contacting us on contact@talao.io.
- an `api-key` that you can get contacting us on contact@talao.io.
- a `callback_url` that the server will call, when the datas are ready to be sent, with the datas collected. An api key can be added.
- a `browser_callback_url` where the server will redirect your user after the data collection process. 
- a `format`, an optional argument to choose the format of datas. By default is `raw`.

*Optional needs :*
- an api-key that you can give us trough telegram to secure your callback reception.
- a logo to display on the KYC UI.

## Get a session code

First you need to get a code to identify the session of the user:

```
GET /id360/get_code_customer?client_id=<client_id>&callback_url=<your_endpoint>&browser_callback_url=<website_user_will_be_redirected_on>&format=<format> HTTP/1.1

Host: talao.co

API-KEY : <your_api_key> 
```

The code returned is useful for one session for one user to get one data structure.

```
HTTP/1.1 200 OK
Content-Type: application/json

{
   "code": <code>
}
```


```
HTTP/1.1 400 Bad Request
Content-Type: application/json

{
   "error": <error_description>
}
```


```
HTTP/1.1 401 Unauthorized
Content-Type: application/json

{
   "error": <error_description>
}
```


## Redirect your user

Redirect your user browser to this route with the code to let him complete the KYC process :

`https://talao.co/id360/authenticate_customer/<code>`

This endpoint will redirect your user to the KYC provider UI to collect his datas. The server will then redirect him to `<browser_callback_url>?code=code` and it will POST datas on your callback_url.

> [!IMPORTANT]
> The user will redirected on your <browser_callback_url> before the server send the callback to <callback_url> with the datas.

## Receive the datas

When the datas are collected, the server will send this request :

```
curl --header "Content-Type: application/json" \
  --header "api-key: <your_optional_api_key>" \
  --request POST \
  --data '{
        "code":<code>
        "name": <name>,
        "first_name": <first_name>,
        "first_names": [
            <first_name1>,
            <first_name2>,
            <first_name3>
        ],
        "address": <address>, //can be wrong
        "nationality": <code_country>,
        "birth_date": <birth_date>,
        "gender": <gender>,
        "birth_place": <birth_place>,
        "birth_country": <birth_country>,
        "country_emission": <code_country>,
        "verificationMethod":<verification_method>,
        "levelOfAssurance":<level_of_assurance>
        "success":true
    }' \
    <callback_url>
```

If the datas could not be collected for any reason, the server will send this request :

```
curl --header "Content-Type: application/json" \
  --header "api-key: <your_optional_api_key>" \
  --request POST \
  --data '{
        "code":<code>
        "success":false,
        "description":<error_description>
    }' \
    <callback_url>
``` 