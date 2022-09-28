# -*- coding: utf-8 -*-

import os
import sys
import io
import json
import pyotp
import uuid

import pyqrcode

import access_ssm_aws as vault
import slack_vault_settings
import images_management_aws as image_storage
import slack_tooling

SLACK_SIGNING_SECRET = slack_vault_settings.slack_signing_secret
# SLACK_SIGNING_SECRET = os.environ.get('slack_signing_secret')

ISLAMBDA = True if "LAMBDA_RUNTIME_DIR" in os.environ else False
DEBUG = os.environ.get('debug', 'false').lower() == 'true'
DEFAULT_AWS_REGION = slack_vault_settings.DEFAULT_AWS_REGION
# DEFAULT_AWS_REGION = os.environ.get('AWS_DEFAULT_REGION', image_storage.get_region())

S3_BUCKET = slack_vault_settings.S3_BUCKET
# S3_BUCKET = os.environ.get('S3_BUCKET','')

MARKDOWN = '*_ ->#'
# ..................................................................................................
def main(event=None, context=None):
    # we have a lambda triggered by an event
    ISLAMBDA = bool(context)
    if DEBUG: print(event)
    if event.get("version", "1.0") != "2.0":
        raw_response = "Error: APIGateway Version must be 2.0"
        response = formatResponse(raw_response, statusCode=400)
        return response
    try:
        event_method = event["requestContext"]["http"]["method"]
    except:
        print(json.dumps(event))
        raw_response = "Error: Bad Request"
        response = formatResponse(raw_response, statusCode=400)
        return response
    # POST method is processed differently from GET
    if event_method in ['POST']:
        return Process_POST(event, context)
    else:
        raw_response = f"{event_method} not supported"
        response = formatResponse(raw_response, statusCode=400)
        return response

def available_commands():
    otp_command_list = {
        "list":
            {
                "func" : command_list,
                "text" : "* *list* or nothing to get the list"
             },
        "help":
            {
                "func" : command_help,
                "text": "* *help*: see this text"
            },
        "update": {
                "func" : command_update,
                "text": "* *update*: admins create or update a private ; /otp update <secretname> <seed>"
            },
        "debug" : {
                "func" : command_debug,
                "text": "* *debug*: throws back the data from slack ; /otp debug"
            },
        "kitten" : {
                "func" : command_kitten,
                "text": "* *kitten*: see a kitten ; /otp kitten"
            },
        "qr" : {
                "func" : command_qr,
                "text": "* *qr*: superadmins retrieve a QR for Google Authenticator ; /otp qr <secretname>"
            },
        "retrieve" : {
                "func" : command_retrieve,
                "text": "* *retrieve*: superadmins retrieve a private otp seed ; /otp retrieve <secretname>"
            },
        "admins": {
            "func": command_admins,
            "text": "* *admins*: show the list of admins ; /otp admins"
        }

    }
    return otp_command_list
# ----------------------------------------------------------------------

def cleanup(name, prefix=''):
    clean_name = name.replace(prefix, '')
    pass
    return clean_name

def get_totp_list():
    secret_list = vault.get_secrets_list(
        prefix=slack_vault_settings.otp_list_secrets_prefix ,
        region=DEFAULT_AWS_REGION)
    return  secret_list
# ..............................................................................................
def Process_POST(event, context=None):
    # we have a lambda triggered by an event
    slack_data = slack_tooling.retrieve_body(event)
    slack_user = slack_data.get('user_id', [''])[0]
    slack_user_name = slack_data.get('user_name', ['unknown'])[0]
    slack_slash_command = slack_data.get('command', [''])[0]
    slack_parameters = slack_data.get('text', [''])[0].split()
    slack_otp_command = slack_parameters[0] if len(slack_parameters) > 0 else "list"
    if slack_otp_command.lower() == 'diag':
        raw_response = command_diagnostics(event)
        response = formatResponse(raw_response, statusCode=200, response_type='json')
        return response
    # if not is_validated(event):
    if not slack_tooling.is_valid(event, SLACK_SIGNING_SECRET, DEBUG=DEBUG):
        raw_response = "Authentication Error"
        response = formatResponse(raw_response, statusCode=403)
        return response

    if not is_authorized(event):
        raw_response = f"*Error, user_id {slack_user} ({slack_user_name}) not authorized to action*"
        response = formatResponse(raw_response, statusCode=200)
        return response

    otp_command_list = available_commands()
    ISLAMBDA = bool(context)

    command_response_creator = otp_command_list.get(slack_otp_command, {}).get("func", command_unknown)
    raw_response = command_response_creator(slack_parameters, slack_data=slack_data)

    response = formatResponse(raw_response, statusCode=200, response_type='json')
    return response

# ------------------------------------------------------------------------------
def is_authorized(event):
    vault_viewers = []
    slack_data = slack_tooling.retrieve_body(event)
    slack_user = slack_data.get('user_id', [''])[0]
    slack_command = slack_data.get('command', ['/'])[0].strip('/')
    slack_parameters = slack_data.get('text', [''])[0].split()
    if slack_parameters == []:
        return True
    action = slack_parameters[0]
    if action.lower() in ['debug', 'diag']:
        return True
    elif action.lower() in ['update']:
        return slack_user in slack_vault_settings.vault_editors
    elif action.lower() in ['retrieve', 'qr'] :
        return slack_user in slack_vault_settings.vault_super_editors
    else:
        return True


# -------------------------------------------------------------------------------------------

def formatResponse(payload, statusCode=200, response_type='json'):
    if response_type == 'json':
        response = {
            "isBase64Encoded": False,
            "statusCode": statusCode,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps(payload)
        }
    else:
        response = {
            "isBase64Encoded": False,
            "statusCode": statusCode,
            "headers": {"Content-Type": "text/plain"},
            "body": payload
        }
    return response

def command_diagnostics(event):
    response = dict(
        environment=dict(os.environ),
        event=event
    )
    response_text = json.dumps(response, indent=4)
    return {
            "text": response_text,
            "response_type": "ephemeral",
            "markdwn": True
        }



def command_help(slack_parameters, slack_data=None):
    text_list = [ "OTP available commands:" ] + \
        [command["text"] for command in available_commands().values()]
    text = "\n".join(text_list)
    return {
            "text": text,
            "response_type": "ephemeral",
            "markdwn": True
        }

def command_admins(slack_parameters, slack_data=None):
    lookup_users = {user.get("id") : user for user in slack_vault_settings.slack_full_members}
    text_list = ["*Vault Editors:*"] + \
        [lookup_users[admin]["real_name"] for admin in slack_vault_settings.vault_editors]
    text_list = text_list + ["*Superadmins:*"] + \
        [lookup_users[admin]["real_name"]  for admin in slack_vault_settings.vault_super_editors]
    raw_response = {
        "text": "\n".join(text_list),
        "response_type": "ephemeral",
        "markdwn": True
    }
    return raw_response

def command_debug(slack_parameters, slack_data=None):
    text = json.dumps(slack_data)
    return {
            "text": text,
            "response_type": "ephemeral",
            "markdwn": True
        }
def command_unknown(slack_parameters, slack_data=None):
    return {
            "text": f"*unrecognized command*",
            "response_type": "ephemeral",
            "markdwn": True
        }

def command_list(slack_parameters, slack_data=None):
    totp_list = get_totp_list()
    raw_response = {
        "text": "\n".join([f"*{cleanup(key, prefix='/otp/')}* : {otp(value)}" for key, value in totp_list.items()]),
        "response_type": "ephemeral",
        "markdwn": True
    }
    return raw_response

def command_retrieve(slack_parameters, slack_data=None):
    if len(slack_parameters) >= 2:
        secret_name = '/otp/' + slack_parameters[1].strip(MARKDOWN)
        seed = vault.get_secret(secret_name, region=DEFAULT_AWS_REGION)
        text = seed
    else:
        text = "Missing arguments, need name"
    raw_response = {
        "text": text,
        "response_type": "ephemeral",
        "markdwn": False
    }
    return raw_response

def command_qr(slack_parameters, slack_data=None):
    if len(slack_parameters) >= 2:
        secret_name = '/otp/' + slack_parameters[1].strip(MARKDOWN)
        seed = vault.get_secret(secret_name, region=DEFAULT_AWS_REGION)
        if seed:
            image_url = handle_qr(slack_parameters[1].strip(MARKDOWN), seed, issuer='Globaldots Slack')
            raw_response = format_qr_reponse(image_url)
        else:  # missing seed
            raw_response = {
                "text": "not found",
                "response_type": "ephemeral",
                "markdwn": False
            }
    else:
        text = "Missing arguments, need name"
        raw_response = {
            "text": text,
            "response_type": "ephemeral",
            "markdwn": False
        }
    return raw_response

def command_update(slack_parameters, slack_data=None):
    if len(slack_parameters) >= 3:
        secret_name = '/otp/' + slack_parameters[1].strip(MARKDOWN)
        secret_value = slack_parameters[2]
        otp_response = str(otp(secret_value))
        if otp_response.lower().find("error") == -1:
            vault.write_secret(secret_name, secret_value, region=DEFAULT_AWS_REGION)
            text = "Secret added"
        else:  # in error
            text = "Bad Secret *NOT* stored"
    else:
        text = "Missing arguments, need name and private"
    raw_response = {
        "text": text,
        "response_type": "ephemeral",
        "markdwn": False
    }
    return raw_response

def command_kitten(slack_parameters, slack_data=None):
    response = {
        "blocks": [
            {
                "type": "image",
                "title": {
                    "type": "plain_text",
                    "text": "Please enjoy this photo of a kitten"
                },
                "block_id": "image4",
                "image_url": "http://placekitten.com/500/500",
                "alt_text": "An incredibly cute kitten."
            }
        ]
    }
    return response

def format_qr_reponse(url):
    response = {
        "blocks": [
            {
                "type": "image",
                "title": {
                    "type": "plain_text",
                    "text": "Import into Google Authenticator"
                },
                "block_id": "image4",
                "image_url": url,
                "alt_text": "QR"
            }
        ]
    }
    return response

# --------------------------------------------------------------------------------
def otp(totp_seed):
    try:
        totp = pyotp.TOTP(totp_seed)
        otp_result = totp.now()
    except:
        print("Unexpected error:", sys.exc_info()[0])
        otp_result = '"*ERROR* - look in the logs"'
    return otp_result

# --------------------------------------------------------------------------------


def mfa_code(name, seed, issuer=None):
    if not bool(name):
        raise ValueError('Missing 2FA name')
    if not bool(seed):
        raise ValueError('Missing 2FA seed')
    if issuer is None:
        data_to_encode = "otpauth://totp/{name}?private={secret}".format(name=name,secret=seed)
    else:
        data_to_encode = "otpauth://totp/{name}?private={secret}&issuer={issuer}".format( name=name, secret=seed, issuer=issuer)
    return data_to_encode
#----------------------------------------------------------------------
def mfa_qrcode(name, seed, issuer=None, **kwargs):
    return pyqrcode.create(mfa_code(name, seed, issuer ), **kwargs)
    # return qrcode.make(mfa_code(name, seed, issuer ), **kwargs).get_image()
#----------------------------------------------------------------------

def handle_qr(name, seed, issuer=None, **kwargs):
    mfa_issuer = issuer
    mfa_name= name
    otp_seed = seed
    filename=f"{uuid.uuid1()}.png"
    buffer = io.BytesIO()

    img = mfa_qrcode(mfa_name, otp_seed, mfa_issuer)
    # img.save(buffer, "png")
    img.png(buffer, scale=8)
    buffer.seek(0)  # rewind pointer back to start
    url = image_storage.put_image(filename, buffer, S3_BUCKET, region=DEFAULT_AWS_REGION)
    return url
