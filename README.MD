What we need :
- a callback_url, that we will call, when the datas are ready to be sent, with the datas collected. An api key can be added.
- a browser_callback, where we will redirect your user after the data collection process. 

First you need to ask a code to identify the session of the user:

curl https://talao.co/id360/get_code?client_id=<client_id> -H "api-key":<your_api_key> -H "callback_url":<your_endpoint> -H "browser_callback":<website_user_will_be_redirected_on>

the code returned is useful for one session for one user to get one data structure

returns {"code": <code>} 200
returns {"error": <error_description>} with status code if an error occured

redirect your user browser on this route to let him complete the data collection process :

https://talao.co/id360/authenticate/<code> 
this endpoint will redirect your user on the KYC provider UI to collect his datas. We will then redirect him on the browser_callback and we will POST datas on your callback_url



