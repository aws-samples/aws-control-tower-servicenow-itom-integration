"""
Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to
deal in the Software without restriction, including without limitation the
rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
sell copies of the Software, and to permit persons to whom the Software is
furnished to do so.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
"""

import boto3
import base64
import json
from botocore.vendored import requests
from botocore.vendored.requests.auth import HTTPBasicAuth
import logging
import os
from time import sleep
from utils import *

logger = logging.getLogger()
logger.setLevel(logging.INFO)

CLOUD_SERVICE_ACCOUNT_TABLE_API = 'api/now/table/cmdb_ci_cloud_service_account'
DISCOVERY_SCHEDULE_TABLE_API = 'api/now/table/discovery_schedule'
REFRESH_DATACENTER_API = 'api/now/cloud_account_discovery/refreshDatacenters'
LOGICAL_DATACENTER_CONFIG_TABLE_API = 'api/now/table/cmp_discovery_ldc_config'
LOGICAL_DATACENTER_TABLE_API = 'api/now/table/cmdb_ci_logical_datacenter'
GET_DISCOVERY_RESULT_API = 'api/now/cloud_account_discovery/getDiscoveryResult'
CLOUD_SERVICE_ACCOUNT_RELATIONSHIP_API = 'api/now/cmdb/instance/cmdb_ci_cloud_service_account'
DISCOVERY_CREDENTIALS_TABLE_API = 'api/now/table/aws_credentials'
CLOUD_SERVICE_ACCOUNT_ASSUME_ROLE_TABLE_API = 'api/now/table/cloud_service_account_aws_org_assume_role_params'

assume_role_external_id = os.environ['ASSUME_ROLE_EXTERNAL_ID']
member_account_discovery_role = os.environ['MEMBER_ACCOUNT_ASSUME_ROLE']
discovery_region = os.environ['DISCOVERY_REGION']
servicenow_creds = os.environ['SERVICENOW_CREDS']

response_data = {}
creds=None
try:
    logger.debug("Retrieving ServiceNow API credentials from Secret Manager")
    creds = json.loads(get_secret(servicenow_creds))
except Exception as e:
    logger.error("Error retrieving servicenow credentials from secret manager")
    logger.error(str(e))
    response_data['ERROR'] = 'Missing secrets in Secrets manager'
    # cfnresponse.send(event, context, cfnresponse.FAILED, response_data, "ServiceNowInitialSetup")
    # return

logger.debug("Successfully retrieved credentials from Secret Manager")
global servicenow_auth
servicenow_auth = HTTPBasicAuth(creds['username'], creds['password'])

def servicenow_request(url, request_type, params=None, request_data=None):
    """
    Helper function to make REST API request to ServiceNow and return response in json format
    """
    logger.debug(f"Request Type: {request_type}")
    logger.debug(f"Request URL: {url}")
    # Set proper headers
    headers = {"Content-Type":"application/json","Accept":"application/json"}
    # Do the HTTP request
    if request_type == "POST":
        response = requests.post(url, params=params, auth=servicenow_auth,
            headers=headers, data=json.dumps(request_data))
    elif request_type == "DELETE":
        response = requests.delete(url, params=params, auth=servicenow_auth, headers=headers)
    else:
        response = requests.get(url, auth=servicenow_auth, params=params, headers=headers )
        # Check for HTTP codes other than 200

    if (response.status_code != 200 and response.status_code != 201 and
        response.status_code != 202 and response.status_code != 204):
        logger.error("Request Failed")
        logger.error(f"Status: {response.status_code}, Error Response: {response.json()}")
        error_msg = "ServiceNow Request Failed"
        if response.status_code == 401:
            error_msg = "ServiceNow Request Failed - Invalid Credentails"
        raise Exception(error_msg)

    response_data = None
    logger.debug("Request executed successfully")
    if response.status_code != 204:
        response_data = response.json()
        logger.debug(f"Response data: {json.dumps(response_data)}")
    return response_data

def get_account_sys_id(servicenow_url, account_id):
    """
    Retrieves system identifier for the specified account from Service Now

    :param servicenow_url: ServiceNow endpoint URL
    :param account_id: Identifier for cloud service account in ServiceNow
    :return: Returns system id
    """
    url = servicenow_url + "/" + CLOUD_SERVICE_ACCOUNT_TABLE_API
    params = {"account_id": account_id}
    resp = servicenow_request(url=url, request_type="GET", params=params)
    sys_id = None
    if resp['result']:
        data = resp['result'][0]
        sys_id = data['sys_id']
    return sys_id

def get_discovery_schedule_sys_id(servicenow_url, schedule_name):
    """
    Retrieves system identifier for the specified discovery schedule from Service Now

    :param servicenow_url: ServiceNow endpoint URL
    :param schedule_name: Discovery schedule in ServiceNow
    :return: Returns system id
    """
    url = servicenow_url + "/" + DISCOVERY_SCHEDULE_TABLE_API
    params = {"name": schedule_name}
    resp = servicenow_request(url=url, request_type="GET", params=params)
    data = resp['result'][0]
    return data['sys_id']

def check_account_in_service_now(servicenow_url, account_id):
    """
    Check if given account exists in ServiceNow service account

    :param servicenow_url: ServiceNow endpoint URL
    :param schedule_name: Discovery schedule in ServiceNow
    :return: Returns system id
    """
    url = servicenow_url + "/" + CLOUD_SERVICE_ACCOUNT_TABLE_API
    params = {"account_id": account_id}
    resp = servicenow_request(url=url, request_type="GET", params=params)
    data = resp['result']
    if not data:
        return False
    else:
        return True

def create_account_in_service_now(servicenow_url, account_id, account_name, parent_account_id=None, discovery_credentials=None):
    """
    Creates new account in ServiceNow's cloud service account table

    :param servicenow_url: ServiceNow endpoint URL
    :param account_id: Id of Service Account to create in ServiceNow
    :param account_name: Name of Service Account to create in ServiceNow
    :param parent_account: Id of Parent account
    :param discovery_credentials: Discovery credentials to use for the service account
    :return: Returns system id of new service account created in ServiceNow
    """
    #Retrieve sys_id(s) for parent_account and deployment schedule
    create_account_req = {}
    create_account_req['account_id'] = account_id
    create_account_req['name'] = account_name
    
    if parent_account_id:
        parent_account_sys_id = get_account_sys_id(servicenow_url, parent_account_id)
        create_account_req['parent_account'] = parent_account_sys_id
    else:
        create_account_req['is_master_account'] = True
    
    if discovery_credentials:
        create_account_req['discovery_credentials'] = discovery_credentials
    create_account_req['datacenter_type'] = "cmdb_ci_aws_datacenter"
    url = servicenow_url + "/" + CLOUD_SERVICE_ACCOUNT_TABLE_API

    resp = servicenow_request(url=url, request_type="POST", request_data=create_account_req)
    data = resp['result']
    new_account_sys_id = data['sys_id']
    logger.info(f"Account created in cloud service account table, sys_id: {new_account_sys_id}")
    return new_account_sys_id

def start_data_center_discovery(servicenow_url, account_sys_id):
    """
    Discovers data centers for ServiceNow's cloud service account

    :param servicenow_url: ServiceNow endpoint URL
    :param account_sys_id: Id of Service Account n ServiceNow
    :return: Returns system id of data center discovery status
    """
    url = servicenow_url + "/" + REFRESH_DATACENTER_API
    params = {"accountSysId": account_sys_id}
    resp = servicenow_request(url=url, request_type="GET", params=params)
    data = resp['result']
    status_id = data['statusSysId']
    logger.info(f"Data Center discovery started successfully, status id: {status_id}")
    return status_id

def get_data_center_discovery_result(servicenow_url, discovery_status_id, timeout_secs = 120):
    """
    Retrieves result of the data center discovery for cloud service account

    :param servicenow_url: ServiceNow endpoint URL
    :param discovery_status_id: Id of discovery status
    :param timeout_secs: Number of secs to wait for discovery to timeout
    :return: Returns list of discovered data center (regions)
    """
    wait = 0
    sleep_in_secs = 10
    ci_list = []
    url = servicenow_url + "/" + GET_DISCOVERY_RESULT_API
    params = {'statusSysId': discovery_status_id}
    status = None
    while (wait < timeout_secs):
        resp = servicenow_request(url=url, request_type="GET", params=params)
        status = resp['result']['state']
        logger.info(f"Data center discovery status: {status}")
        if status == 'success' or status == 'error':
            ci_list = resp['result']['ci_list']
            break
        sleep(sleep_in_secs)
        wait = wait + sleep_in_secs
        if wait >= timeout_secs:
            logger.error("Data center discovery timed out")
            raise Exception('Data center discovery failed')
    return ci_list

def configure_account_ldc_for_discovery(servicenow_url, ldc_sys_id, new_account_sys_id, discovery_schedule_id):
    """
    Associates service accounts data center with specified discovery schedule to configure for discovery

    :param servicenow_url: ServiceNow endpoint URL
    :param ldc_sys_id: Id of discovery status
    :param new_account_sys_id: New account sys id
    :param discovery_schedule_id: Discovery schedule id
    :return: Returns result of associating data center with discovery schedule
    """
    logger.info("Adding account logical data center to existing discovery schedule")

    ldc_request = {}
    ldc_request['ldc'] = ldc_sys_id
    ldc_request['service_account'] = new_account_sys_id
    ldc_request['discovery_schedule'] = discovery_schedule_id

    url = servicenow_url + "/" + LOGICAL_DATACENTER_CONFIG_TABLE_API

    resp = servicenow_request(url=url, request_type="POST", request_data=ldc_request)
    data = resp['result']
    return data

def remove_account_from_ldc_discovery_config(servicenow_url, account_sys_id):
    """
    Removes service accounts data center from discovery schedule

    :param servicenow_url: ServiceNow endpoint URL
    :param account_sys_id: Service Account sys id
    """
    url = servicenow_url + "/" + LOGICAL_DATACENTER_CONFIG_TABLE_API
    params = {'service_account': account_sys_id}
    resp = servicenow_request(url=url, request_type="GET", params=params)
    data = resp['result']
    if data:
        ldc_config = data[0]
        ldc_config_sys_id = ldc_config['sys_id']
        url = url + "/" + ldc_config_sys_id
        resp = servicenow_request(url=url, request_type="DELETE")
    else:
        logger.error("Unable to find any logical data center configured for discovery")

def delete_account_logical_datacenters(servicenow_url, account_sys_id):
    """
    Removes all service account logical data center 

    :param servicenow_url: ServiceNow endpoint URL
    :param account_sys_id: Service Account sys id
    """
    ## Retrieve list of LDCs for the given account
    url = servicenow_url + "/" + CLOUD_SERVICE_ACCOUNT_RELATIONSHIP_API + "/" + account_sys_id
    resp = servicenow_request(url=url, request_type="GET")
    ldc_relationships = resp['result']['inbound_relations']

    # Iterate over the list of LDCs and delete them
    if ldc_relationships:
        for entry in ldc_relationships:
            ldc_sys_id = entry['target']['value']
            region = entry['target']['display_value']
            req_url = servicenow_url + "/" + LOGICAL_DATACENTER_TABLE_API + "/" + ldc_sys_id
            resp = servicenow_request(url=req_url, request_type="DELETE")
            logger.info(f"Removed logical data center for {region}")
    else:
        logger.info("Unable to find any discovered data centers for the account")

def remove_account_from_servicenow(servicenow_url, account_sys_id):
    """
    Removes service account from ServiceNow cloud service account

    :param servicenow_url: ServiceNow endpoint URL
    :param account_sys_id: Service Account sys id
    """
    url = servicenow_url + "/" + CLOUD_SERVICE_ACCOUNT_TABLE_API
    url = url + "/" + account_sys_id
    servicenow_request(url=url, request_type="DELETE")

def configure_account_for_snow_discovery(servicenow_env, account_id, account_name,
                                         discovery_schedule, parent_account_id=None, 
                                         discovery_credentials=None):
    """
    Configures account in ServiceNow's for cloud discovery

    :param servicenow_url: ServiceNow endpoint URL
    :param account_id: Id of Service Account to create in ServiceNow
    :param account_name: Name of Service Account to create in ServiceNow
    :param discovery_schedule: Name of discovery schedule
    :param parent_account: Id of Parent account
    :param discovery_credentials: Discovery credentials to use for the service account
    :return: Returns system id of new service account created in ServiceNow
    """
    account_exists = False
    # check if account is already provisioned
    account_exists = check_account_in_service_now(servicenow_env, account_id)
    if account_exists:
        logger.info(f"Account {account_name}:{account_id} exists in ServiceNow... skipping")
        return
    #Create account in service now
    logger.info(f"Creating new account {account_name} in cloud service account table")
    new_account_sys_id = create_account_in_service_now(servicenow_env, account_id, account_name,
                             parent_account_id=parent_account_id, discovery_credentials=discovery_credentials)

    # Start Data center discovery
    logger.info("Refreshing data center for new account")
    discovery_status_id = start_data_center_discovery(servicenow_env, new_account_sys_id)
    retry_attempts = 0

    logger.info("Getting data center discovery status")
    data_center_ci_list = get_data_center_discovery_result(servicenow_env, discovery_status_id)
    if not data_center_ci_list:
        while len(data_center_ci_list) == 0 and retry_attempts < 2 :
            # retry data center discovery
            retry_attempts = retry_attempts + 1
            discovery_status_id = start_data_center_discovery(servicenow_env, new_account_sys_id)
            data_center_ci_list = get_data_center_discovery_result(servicenow_env, discovery_status_id)

    if retry_attempts >= 2:
        logger.error(f"Data center discovery failed after {retry_attempts}")
        raise Exception('Data center discovery failed')

    ldc_sys_id = None
    for ci in data_center_ci_list:
        if ci['name'] == discovery_region:
            ldc_sys_id = ci['sys_id']
            logger.info("\tData center for us-east-1 is discovered")

    logger.info(f"Retrieving id for discovery schedule {discovery_schedule}")
    discovery_schedule_id = get_discovery_schedule_sys_id(servicenow_env, discovery_schedule)

    logger.info(f"Configuring account for discovery in Data Center: {ldc_sys_id}")
    configure_account_ldc_for_discovery(servicenow_env, ldc_sys_id, new_account_sys_id, discovery_schedule_id)

    logger.info(f"Done provisioning Account {account_name}:{account_id} in Service Now for discovery")

    return new_account_sys_id

def deprovision_account_for_snow_discovery(servicenow_env, account_id, account_name):
    """
    Removes account from ServiceNow discovery

    :param servicenow_url: ServiceNow endpoint URL
    :param account_id: Id of Service Account to create in ServiceNow
    :param account_name: Name of Service Account to create in ServiceNow
    """
    logger.info(f"Removing account {account_id} from ServiceNow")
    ## Retrieve sys_id from discovery config ldc for given account
    account_sys_id = get_account_sys_id(servicenow_env, account_id)
    if account_sys_id is None:
        logger.info(f"Account {account_name}:{account_id} does not exists in ServiceNow... skipping")
        return
    ## Delete entry from discovery config LDC
    logger.info("Removing account from discovery configuration")
    remove_account_from_ldc_discovery_config(servicenow_env, account_sys_id)

    ## Delete LDCs for the account
    logger.info("Removing Logical data centers for this account")
    delete_account_logical_datacenters(servicenow_env, account_sys_id)
    ## delete the account from cloud service account table

    logger.info("Removing account from ServiceNow cloud service table")
    remove_account_from_servicenow(servicenow_env, account_sys_id)
    logger.info(f"Successfully removed account {account_name} from ServiceNow")

def create_aws_credentails(servicenow_url, name, access_key, secret_key):
    """
    Creates AWS discovery crendentials in ServiceNow

    :param servicenow_url: ServiceNow endpoint URL
    :param name: Name of discovery credential to create in ServiceNow
    :param access_key: Access key Id for the discovery credential
    :param secret_key: Secret key for discovery credential
    :return: System identifier for newly created discovery credential
    """
    aws_credentials_request = {}
    aws_credentials_request['name'] = name
    aws_credentials_request['access_key'] = access_key
    aws_credentials_request['secret_key'] = secret_key

    url = servicenow_url + "/" + DISCOVERY_CREDENTIALS_TABLE_API

    resp = servicenow_request(url=url, request_type="POST", request_data=aws_credentials_request)
    data = resp['result']
    cred_sys_id = data['sys_id']
    return cred_sys_id

def delete_aws_discovery_credentials(servicenow_url, account_name):
    """
    Deletes AWS discovery crendentials in ServiceNow

    :param servicenow_url: ServiceNow endpoint URL
    :param account_name: Name of discovery credential to create in ServiceNow
    """
    ## Retrieve sys id for the discovery credentails
    url = servicenow_url + "/" + DISCOVERY_CREDENTIALS_TABLE_API
    params = {"name": account_name }
    resp = servicenow_request(url=url, request_type="GET", params=params)

    credentials = resp['result']
    if not credentials:
        logger.info(f"Discovery credentials for account: {account_name} does not exits")
    else:
        credential_id = credentials[0]['sys_id']
        url = servicenow_url + "/" + DISCOVERY_CREDENTIALS_TABLE_API
        url = url + "/" + credential_id
        servicenow_request(url=url, request_type="DELETE")

def check_discovery_schedule_in_service_now(servicenow_url, discovery_schedule):
    """
    Checks if discovery schedule with specified name existing in ServiceNow

    :param servicenow_url: ServiceNow endpoint URL
    :param discovery_schedule: Name of discovery schedule to check in ServiceNow
    :return: System identifier for discovery schedule if exist, otherwise returns None
    """
    url = servicenow_url + "/" + DISCOVERY_SCHEDULE_TABLE_API
    params = {"name": discovery_schedule}
    resp = servicenow_request(url=url, request_type="GET", params=params)
    data = resp['result']
    if not data:
        return None
    else:
        return data['sys_id']

def create_discovery_schedule(servicenow_url, discovery_schedule):
    """
    Creates AWS discovery schedule in ServiceNow

    :param servicenow_url: ServiceNow endpoint URL
    :param name: Name of discovery schedule to create in ServiceNow
    :return: System identifier for newly created discovery schedule
    """
    # check if schedule already exits
    schedule_sys_id = check_discovery_schedule_in_service_now(servicenow_url, discovery_schedule)
    if schedule_sys_id:
        logger.info(f"Schedule {discovery_schedule} exists in ServiceNow... skipping")
        return schedule_sys_id
    url = servicenow_url + "/" + DISCOVERY_SCHEDULE_TABLE_API
    discovery_schedule_request = {}
    discovery_schedule_request["name"] = discovery_schedule
    discovery_schedule_request["discover"] = "Cloud Resources"
    discovery_schedule_request["active"] = True
    discovery_schedule_request['disco_run_type'] = "Daily"
    resp = servicenow_request(url=url, request_type="POST", request_data=discovery_schedule_request)
    data = resp['result']
    schedule_sys_id = data['sys_id']
    return schedule_sys_id

def delete_aws_discovery_schedule(servicenow_url, discovery_schedule):
    """
    Deletes AWS discovery schedule in ServiceNow

    :param servicenow_url: ServiceNow endpoint URL
    :param account_name: Name of discovery schedule to create in ServiceNow
    """
    ## Retrieve sys id for the discovery credentails
    url = servicenow_url + "/" + DISCOVERY_SCHEDULE_TABLE_API
    params = {"name": discovery_schedule }
    resp = servicenow_request(url=url, request_type="GET", params=params)
    discovery_schedules = resp['result']
    if not discovery_schedules:
        logger.info(f"Could not find discovery schedule with name: {discovery_schedule}")
    else:
        schedule_id = discovery_schedules[0]['sys_id']
        url = servicenow_url + "/" + DISCOVERY_SCHEDULE_TABLE_API
        url = url + "/" + schedule_id
        servicenow_request(url=url, request_type="DELETE")

def create_member_account_discovery_role(servicenow_url, parent_account, 
                                         member_account_discovery_role, 
                                         assume_role_external_id):
    """
    Creates entry in the cloud service account assume role table for master account to
    setup role based discovery

    :param servicenow_url: ServiceNow endpoint URL
    :param parent_account: Master account id
    :param member_account_discovery_role: Name of IAM role created in member accounts
    :param assume_role_external_id: External Id for the IAM role created in member accounts
    :return: System identifier for newly created discovery role
    """
    url = servicenow_url + "/" + CLOUD_SERVICE_ACCOUNT_ASSUME_ROLE_TABLE_API
    assume_role_request = {}
    assume_role_request["access_role_name"] = member_account_discovery_role
    assume_role_request["cloud_service_account"] = parent_account
    assume_role_request["external_id"] = assume_role_external_id
    resp = servicenow_request(url=url, request_type="POST", request_data=assume_role_request)
    data = resp['result']
    role_sys_id = data['sys_id']
    return role_sys_id

def delete_member_account_discovery_role(servicenow_url, parent_account):
    """
    Creates entry in the cloud service account assume role table for master account to
    setup role based discovery

    :param servicenow_url: ServiceNow endpoint URL
    :param parent_account: Master account id
    """
    ## Retrieve sys id for the assume role
    url = servicenow_url + "/" + CLOUD_SERVICE_ACCOUNT_ASSUME_ROLE_TABLE_API
    params = {"name": parent_account }
    resp = servicenow_request(url=url, request_type="GET", params=params)
    roles = resp['result']
    if not roles:
        logger.info(f"Could not find role for master account: {parent_account} in assume role table")
    else:
        role_id = resp['result']['sys_id']
        url = servicenow_url + "/" + CLOUD_SERVICE_ACCOUNT_ASSUME_ROLE_TABLE_API
        url = url + "/" + role_id
        servicenow_request(url=url, request_type="DELETE")

def perform_master_acct_cleanup(servicenow_env, parent_account_id,
                                discovery_schedule, master_acct_user_creds):
    """
    Deletes master account and its assosicated discovery schedule and credentials from ServiceNow

    :param servicenow_url: ServiceNow endpoint URL
    :param parent_account: Master account id
    :param discovery_schedule: Name of discovery schedule
    :param master_acct_user_creds: Name of AWS discovery credentials for master account
    """                           
    # remove master account from service now
    try:
        logger.info("Retrieving Master Account name from Organizations")
        client = boto3.client('organizations')
        account_info = client.describe_account(
            AccountId=parent_account_id
        )
        account_name = account_info['Account']['Name']
    except Exception:
        logger.error("Error retrieving account info for master account from Organization")
        account_name = 'default'

    logger.info("Removing Master Account from ServiceNow")
    deprovision_account_for_snow_discovery(servicenow_env, parent_account_id, account_name)
    
    # remove discovery credentials
    logger.info("Removing Master Account credentials from ServiceNow")
    delete_aws_discovery_credentials(servicenow_env, account_name)

    # remove discovery schedule
    logger.info("Removing Discovery Schedule from ServiceNow")
    delete_aws_discovery_schedule(servicenow_env, discovery_schedule)

    # remove assume role
    logger.info("Removing Assume Role from ServiceNow")
    delete_member_account_discovery_role(servicenow_env, account_name)

def perform_master_acct_setup(servicenow_env, account_id, discovery_schedule, master_acct_user_creds):
    """
    Creates master account and its assosicated discovery schedule and credentials in ServiceNow

    :param servicenow_url: ServiceNow endpoint URL
    :param parent_account: Master account id
    :param discovery_schedule: Name of discovery schedule
    :param master_acct_user_creds: Name of AWS discovery credentials for master account
    """  
    logger.info("Starting Master Account Discovery setup in ServiceNow ...")
    # Create discovery credentials in SNOW using credentials stored in SM
    try:
        logger.info("Retrieving Master Account User credentials from Secret Manager")
        creds = json.loads(get_secret(master_acct_user_creds))
    except Exception as e:
        logger.error("Error retrieving servicenow credentials from secret manager")
        raise e

    try:
        logger.info("Retrieving Master Account name from Organizations")
        client = boto3.client('organizations')
        account_info = client.describe_account(
            AccountId=account_id
        )
        account_name = account_info['Account']['Name']
    except Exception as e:
        logger.error("Error retrieving account info for master account from Organization")
        raise e
    
    logger.info(f"Creating credentials for master account: {account_name} in ServiceNow")
    cred_sys_id = create_aws_credentails(servicenow_env, account_name, 
                      creds['ACCESS_KEY_ID'], creds['SECRET_ACCESS_KEY'])
    
    # Create discovery schedule
    logger.info("Creating schedule for aws discovery")
    create_discovery_schedule(servicenow_env, discovery_schedule)
    
    #Create account in service now
    sleep(10)
    # Start Data center discovery
    parent_account_sys_id = configure_account_for_snow_discovery(servicenow_env, account_id, 
                                account_name, discovery_schedule, parent_account_id=None, 
                                discovery_credentials=cred_sys_id)

    # Create role in assume role table
    logger.info(f"Updating assume role table with role {member_account_discovery_role} for master account {account_id}")
    create_member_account_discovery_role(servicenow_env, parent_account_sys_id,
         member_account_discovery_role, assume_role_external_id)
    
    logger.info("Done setting up master account for discovery in ServiceNow")

