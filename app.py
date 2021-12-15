from flask import Flask, Response, render_template, request
import boto3
import time
import os
import requests
# import jwt
import json
# from flask_cognito import CognitoAuth, 

app = Flask(__name__)
client_id = "1c5m1dkc43amhvr10bjf1jrqsr"
client_secret = "n8vk8hqna7aqn7fve6m7lq6i9mal3gbh3n0c834gqhglvuq68aj"
callback_uri = 'http://localhost:5000/'
cognito_app_url = "https://cu-fantasy.auth.us-east-1.amazoncognito.com"
token_expire_time = {}

@app.route('/login')
def login():
    return render_template("login.html")

@app.route('/logout')
def logout():
    return render_template("logout.html")

@app.route('/validate_token')
def validate_token():
    if 'token' in request.headers:
        return {
            'error message': 'You do not have the access to get the token information.'
    }
    access_token = request.headers['token']
    if access_token in token_expire_time:
        if time.time()-token_expire_time[access_token] < 3600:
            return jwt.decode(access_token, options={"verify_signature": False}, algorithms=["RS256"])
        else:
            return {'error message': 'Token has expired. Please login again!'}
    return {
        'error message': 'The token did not exist. Please login first!'
    }

@app.route('/')
def main():
    code = request.args.get('code')
    print(code)
    token_url = "{}/oauth2/token".format(cognito_app_url)
    auth = requests.auth.HTTPBasicAuth(client_id, client_secret)
    params = {
        "grant_type": "authorization_code",
        "client_id": client_id,
        "code": code,
        "redirect_uri": callback_uri
    }
    
    response = requests.post(token_url, auth=auth, data=params).json()
    print(response)
    if not 'id_token' in response:
        return render_template("error.html")
    
    
    # client = boto3.client('cognito-idp', 
    #                        region_name='us-east-1',
    #                        aws_access_key_id=os.environ['ACCESS_KEY'],
    #                        aws_secret_access_key=os.environ['SECRET_KEY']
    # )
    # response['access_token'] = 'eyJraWQiOiI1dlR1Yk9UcE9aZmk2YkNyUEhYd1JMTlRUcnZVbzJ3dHRIcVJxTWhiblg4PSIsImFsZyI6IlJTMjU2In0.eyJvcmlnaW5fanRpIjoiOTA3YzEwMjktZmM2OC00ZWEzLThhNmEtNWU1MTNiNWU1MjVlIiwic3ViIjoiZGJiMWI5ZmYtNmE1Yi00NjEzLThjZDYtYTNhMjFjZjdkOTRkIiwidG9rZW5fdXNlIjoiYWNjZXNzIiwic2NvcGUiOiJhd3MuY29nbml0by5zaWduaW4udXNlci5hZG1pbiBvcGVuaWQgZW1haWwiLCJhdXRoX3RpbWUiOjE2Mzk1MjM5NDEsImlzcyI6Imh0dHBzOlwvXC9jb2duaXRvLWlkcC51cy1lYXN0LTEuYW1hem9uYXdzLmNvbVwvdXMtZWFzdC0xX0ZYdHBjemY5UiIsImV4cCI6MTYzOTUyNzU0MSwiaWF0IjoxNjM5NTIzOTQxLCJ2ZXJzaW9uIjoyLCJqdGkiOiI0ZjFlNDk5Yi04MjM2LTQwYTctYjE2Ny0yZmI0MWZmOGFmMjciLCJjbGllbnRfaWQiOiIxYzVtMWRrYzQzYW1odnIxMGJqZjFqcnFzciIsInVzZXJuYW1lIjoiam9zaGNoYW5nIn0.MxT7olkgRm_0Dz3Pg-ujsFGqxQ77YMkvXuTdzrixcplW0BmyPEPwH9_wSnh5yY3gS8NpH69UGZOetIqIedS2B-_FI1zvzaagbMnp8U3mE-hp9-TUqF5YAG6TSmu0uSulWQqtZJgjMf4epx0vonpD-Dgr0ftXEZkE1fhRCU4xLlPwgu6YvSI7r3LBfWiwJP3EDWKdNwyj0lkL1UlKy6W13IrEz_vf6GS8TAd99aKFy3ljg1U0xCCL3u0p9blkxSYS_iP7wVg6laDNmO0QRSszbQ7-SJFMTWZowNlbZj-KASdMmOSv0wbsNHZewQ4GxM3kRMziiOagpXgkxqw7gds3WQ'
    user_info = jwt.decode(response['access_token'], options={"verify_signature": False}, algorithms=["RS256"])
    token_expire_time[response['access_token']] = user_info['exp']
    # user_info = client.get_user(AccessToken=response['access_token'])
    # print(user_info)
    return render_template("main.html")




if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000)
