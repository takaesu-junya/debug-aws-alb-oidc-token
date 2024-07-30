# READ
# https://docs.aws.amazon.com/elasticloadbalancing/latest/application/listener-authenticate-users.html
# This is the poc to debug the JWT token received from ALB after OIDC authentication.
# - Can be used to validate the signer(which is the ARN of the ALB). This ensures that the JWT token is issued by the ALB.
# - Can be used to get the public key from the regional endpoint.
# - Can be used to decode the payload of the JWT token if it is confirmed that the JWT is signed by the public key.

import jwt
import requests
import base64
import json

# Replace this sample headers with the actual headers from ALB after OIDC authentication.
# OIDC is processed by ALB and the IdP provider which is Google for example.
# Even if the IdP is Google, the JWT token is signed by the ALB. And its payload contains the user information provided by Google.
headers = {
        "x-forwarded-for": "",
        "x-forwarded-proto": "",
        "x-forwarded-port": "",
        "host": "",
        "x-amzn-trace-id": "",
        "x-amzn-oidc-data": "",
        "x-amzn-oidc-identity": "",
        "x-amzn-oidc-accesstoken": "",
        "cache-control": "",
        "sec-ch-ua": "",
        "sec-ch-ua-mobile": "",
        "sec-ch-ua-platform": "",
        "upgrade-insecure-requests": "",
        "user-agent": "",
        "accept": "",
        "sec-fetch-site": "",
        "sec-fetch-mode": "",
        "sec-fetch-user": "",
        "sec-fetch-dest": "",
        "referer": "",
        "accept-encoding": "",
        "accept-language": "",
        "if-none-match": "",
        "priority": "",
        "cookie": ""
    }
# Tips: You can use this docker container to just show the headers from the ALB.
# https://hub.docker.com/r/mendhak/http-https-echo


# Step 1: Validate the signer
expected_alb_arn = 'arn:aws:elasticloadbalancing:ap-northeast-1:123456789012:listener/app/my-load-balancer/1234567890123456/1234567890123456'

encoded_jwt = headers['x-amzn-oidc-data']
jwt_headers = encoded_jwt.split('.')[0]
decoded_jwt_headers = base64.b64decode(jwt_headers)
decoded_jwt_headers = decoded_jwt_headers.decode("utf-8")
decoded_json = json.loads(decoded_jwt_headers)
received_alb_arn = decoded_json['signer']

print("""
_____________________________________
Value of decoded jwt headers: {}
_____________________________________
""".format(json.dumps(decoded_json, indent=2)))

assert expected_alb_arn == received_alb_arn, "Invalid Signer"

# Step 2: Get the key id from JWT headers (the kid field)
kid = decoded_json['kid']

print("""
_____________________________________
Value of kid: {}
We need to get the public key for this kid.
_____________________________________
""".format(kid))

# Step 3: Get the public key from regional endpoint
region = 'ap-northeast-1'
url = 'https://public-keys.auth.elb.' + region + '.amazonaws.com/' + kid
req = requests.get(url)
pub_key = req.text

print("""
_____________________________________
The URL to get the public key: {}
The public key: {}
_____________________________________
""".format(url, pub_key))

# Step 4: Get the payload
payload = jwt.decode(encoded_jwt, pub_key, algorithms=['ES256'])

raw_string = json.dumps(payload)
utf8_decoded = raw_string.encode().decode('unicode_escape')

print("""
_____________________________________
The payload: {}
_____________________________________
""".format(utf8_decoded))
