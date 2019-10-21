#!/usr/bin/python

# *******************************************************************************
# Name: cpgw_sns_to_identity_awareness.py
# Description: An AWS Lambda function that consumes an SNS message containing
#  a target IP, role and session-timeout to be injected into the CheckPoint 
#  Gateway Idenity Awareness API
#
# PIP Requirements: requests
#
# Copywrite 2019, Check Point Software
# www.checkpoint.com
# *******************************************************************************

import os
import json
import requests 
from requests.exceptions import HTTPError
from requests.exceptions import Timeout

# Load parameters

# gw_list parameter info
#  string(CSV)
#  format: "<ip>:<shared-secret>,... "
#  Example 172.31.89.87:12345D8Bgt,192.168.7.7:abc123
gw_list = os.environ['cgGatewayList']
gw_list = gw_list.split(',') 

def send_to_gw(url, payload):

    print(f'URL: {url}')
    print(f'Payload: {payload}')
    headers = {'Content-Type': 'application/json'} 

    try:
        resp = requests.post(url, json=payload, headers=headers, timeout=5, verify=False)
        resp.raise_for_status()
        if resp.status_code == 200:
            respcontent = json.loads(resp.content)
            return f'SUCCESS<{resp.status_code}>,{respcontent}'
        else:
            return f'ERROR<{resp.status_code}>'
    except Timeout as timeout_err:
        print(f'Timeout error occurred: {timeout_err}')
        return 'ERROR<TIMEOUT>'
    except HTTPError as http_err:
        print(f'HTTP error occurred: {http_err}')
        return f'ERROR<{resp.status_code}>'
    except Exception as err:
        print(f'Other error occurred: {err}') 
        return 'UNEXPECTED ERROR'
        
def process_rule(message):

    report = []
    for gw in gw_list:
        # parse host and shared secret from string      
        ia_api_hostip = gw.split(':')[0]
        ia_api_secret = gw.split(':')[1]
        
        if 'session-timeout' in message: #if session-timeout does not exist or less than 300 then default to 300 seconds
            if message['session-timeout'] >= 300:
                session_timeout = message['session-timeout']
            else:
                session_timeout = 300
        else:
            session_timeout = 300 

        payload = {
          "shared-secret": ia_api_secret,
          "ip-address": message['hostIp'],
          "machine": "allowed host",
          "roles": [message['roleName']],
          "session-timeout": session_timeout,
          "fetch-machine-groups": 0,
          "calculate-roles": 0,
          "identity-source": "AWS SNS"
        } 
         
        url = f'https://{ia_api_hostip}/_IA_API/v1.0/add-identity'
        
        post_result = send_to_gw(url, payload)
        report.append({"gateway": ia_api_hostip, "result": post_result, "session-timeout": session_timeout})
    
    return report

def lambda_handler(event, context):

    #  Message JSON: 
    #  Syntax: {"hostIp": "<ip-address>","roleName": "<role-name-here>","session-timeout": <integer-300-or-greater>}
    #  Example: {"hostIp": "1.1.1.40","roleName": "role1","session-timeout": 60}
    message = event['Records'][0]['Sns']['Message']
    print("From SNS: " + str(message))
    message = json.loads(message)
    report = process_rule(message)

    return {"message": message, "report": report}