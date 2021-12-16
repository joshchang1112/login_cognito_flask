from flask import Flask, Response, render_template, request, session
import boto3
import time
import os
import requests
import jwt
import json
import pymysql
# from flask_cognito import CognitoAuth, 

# conn = pymysql.connect(
#     host='cu-fantasy-baseball-user.chnpzu4a9le6.us-east-1.rds.amazonaws.com',
#     port=3306,
#     user='admin',
#     password='abcd1234ABCD1234===',
#     db='user',
# 	cursorclass=pymysql.cursors.DictCursor
# )


# client_id = "1c5m1dkc43amhvr10bjf1jrqsr"
# client_secret = "n8vk8hqna7aqn7fve6m7lq6i9mal3gbh3n0c834gqhglvuq68aj"
# callback_uri = 'https://baseball.cu-fantasy.com/'
# cognito_app_url = "https://cu-fantasy.auth.us-east-1.amazoncognito.com"
# client_identify = boto3.client('cognito-identity', region_name='us-east-1')

# IDENTITY_POOL_ID = 'us-east-1:26e70958-ceba-4f4b-94e2-1d7bfc1029db'
# IDENTITY_ID = client_identify.get_id(
#          IdentityPoolId=IDENTITY_POOL_ID
# )['IdentityId']
# temperate_id = client_identify.get_credentials_for_identity(
#        IdentityId=IDENTITY_ID
# )


def update_user_profile(user_info, token):
    cur = conn.cursor()
    cur.execute("select * from user_info where username = %(username)s", {'username': user_info['username']})
    info = cur.fetchone()
    if not info:
        client = boto3.client('cognito-idp', 
                           region_name='us-east-1',
                           aws_access_key_id=temperate_id['Credentials']['AccessKeyId'],
                           aws_secret_access_key=temperate_id['Credentials']['SecretKey']
        )
        user_details = client.get_user(AccessToken=token)
        for att in user_details['UserAttributes']:
            if att['Name'] == 'email':
                email = att['Value']
        columns = "(username, email, access_token, token_start, token_exp)"
       
        values = [user_info['username'], email, token, str(user_info['auth_time']), str(user_info['exp'])]
        for i in range(3):
            values[i] = '"' + values[i] + '"'
        values_str = ','.join(values)
        cur.execute('Insert into user_info {} Values ({})'.format(columns, values_str))
        conn.commit()
        return {
            'statusCode': 200,
            'text': json.dumps('Succeessfully insert new user!')
        } 
    else:
        cur.execute("Update user_info SET access_token = %(token)s WHERE username = %(username)s"\
            , {'token': token, 'username': user_info['username']})
        cur.execute("Update user_info SET token_start = %(auth_time)s WHERE username = %(username)s"\
            , {'auth_time': user_info['auth_time'], 'username': user_info['username']})
        cur.execute("Update user_info SET token_exp = %(exp)s WHERE username = %(username)s"\
            , {'exp': user_info['exp'], 'username': user_info['username']})
        conn.commit()
        return {
            'statusCode': 200,
            'text': json.dumps('Succeessfully update user token info!')
        } 


application = Flask(__name__)


@application.route('/login')
def login():
    return render_template("login.html")

@application.route('/logout')
def logout():
    return render_template("logout.html")

@application.route('/get_username')
def get_username():
    if 'token' not in request.headers:
        return {
            'statusCode': 401,
            'text': json.dumps('You do not have token information in the headers.')
        }
    access_token = request.headers['token']
    cur = conn.cursor()
    cur.execute("select username from user_info where access_token = %(token)s", {'token': access_token})
    info = cur.fetchall()
    if not info:
        return {
            'statusCode': 500,
            'text': json.dumps('The token is invalid. Please login first and try again.')
        }
    return {
            'statusCode': 200,
            'text': json.dumps('Succeessfully get username'),
            'data': info[0]['username']
        }

@application.route('/get_email')
def get_email():
    if 'token' not in request.headers:
        return {
            'statusCode': 401,
            'text': json.dumps('You do not have token information in the headers.')
        }
    access_token = request.headers['token']
    cur = conn.cursor()
    cur.execute("select email from user_info where access_token = %(token)s", {'token': access_token})
    info = cur.fetchall()
    if not info:
        return {
            'statusCode': 500,
            'text': json.dumps('The token is invalid. Please login first and try again.')
        }
    return {
            'statusCode': 200,
            'text': json.dumps('Succeessfully get email'),
            'data': info[0]['email']
        }

@application.route('/get_exp')
def get_exp():
    if 'token' not in request.headers:
        return {
            'statusCode': 401,
            'text': json.dumps('You do not have token information in the headers.')
        }
    access_token = request.headers['token']
    cur = conn.cursor()
    cur.execute("select token_exp from user_info where access_token = %(token)s", {'token': access_token})
    info = cur.fetchall()
    if not info:
        return {
            'statusCode': 401,
            'text': json.dumps('The token is invalid. Please login first and try again.')
        }
    return {
            'statusCode': 200,
            'text': json.dumps('Succeessfully get exp time'),
            'data': info[0]['token_exp']
        }

@application.route('/validate_token')
def validate_token():
    if 'token' not in request.headers:
        return {
            'statusCode': 401,
            'text': json.dumps('You do not have token information in the headers.')
        }
    access_token = request.headers['token']
    response = requests.get('https://baseball.cu-fantasy.com/get_exp', headers=request.headers).json()
    if 'data' in response:
        if time.time() > response['data']:
            return {
                'statusCode': 401,
                'text': json.dumps('Your token has expired. Please login again.')
            }
        else:
            return {
                'statusCode': 200,
                'text': json.dumps('The token has been verified successfully!')
            } 
    return {
        'statusCode': 401,
        'text': json.dumps('The token is invalid. Please login first.')
    } 

@application.route('/')
def main():
    code = request.args.get('code')
    token_url = "{}/oauth2/token".format(cognito_app_url)
    auth = requests.auth.HTTPBasicAuth(client_id, client_secret)
    params = {
        "grant_type": "authorization_code",
        "client_id": client_id,
        "code": code,
        "redirect_uri": callback_uri
    }
    
    response = requests.post(token_url, auth=auth, data=params).json()
    # return json.dumps(response)
    if 'access_token' in response:
        access_token = response['access_token']
        decode_user_info = jwt.decode(access_token, options={"verify_signature": False}, algorithms=["RS256"])
        response = update_user_profile(decode_user_info, access_token)
        print(response)
    elif 'token' in request.headers:
        access_token = request.headers['token']
    else:
        return render_template("error.html")
    
    return render_template("main.html")
    # return {
    #       'statusCode': 200,
    #       'token': access_token,
    #       'text': json.dumps("Get access token successfully.")
    # }



if __name__ == '__main__':
    application.run()

