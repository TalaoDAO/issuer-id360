# KYC API



The process need:
- a callback_url, that we will call, when the datas are ready to be sent, with the datas collected. An api key can be added.
- a browser_callback_url, where we will redirect your user after the data collection process. 

## Ask for a session code


First you need to ask a code to identify the session of the user:

GET /id360/get_code_customer?client_id=<client_id>&callback_url=<your_endpoint>&browser_callback_url=<website_user_will_be_redirected_on> HTTP/1.1
Host: talao.co
Content-Type: application/x-www-form-urlencoded
API-KEY : <your_api_key> 


The code returned is useful for one session for one user to get one data structure

HTTP/1.1 200 OK
Content-Type: application/json

{
   "code": \<code>
}

HTTP/1.1 400 Bad Request
Content-Type: application/json

{
   "error": <error_description>
}

HTTP/1.1 401 Unauthorized
Content-Type: application/json

{
   "error": <error_description>
}

## Redirect your user

Redirect your user browser on this route with the code to let him complete the data collection process :

https://talao.co/id360/authenticate_customer/\<\code> 
this endpoint will redirect your user on the KYC provider UI to collect his datas. We will then redirect him on <browser_callback_url>?code=code and we will POST datas on your callback_url


## Receive the datas


When the datas are collected, the server will send this request :

```
curl --header "Content-Type: application/json" \
  --request POST \
  --data '{
        "code":\<code>
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
        "country_emission": <code_country>
    }' \
    <callback_url>
```
