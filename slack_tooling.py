from urllib.parse import parse_qs
import base64
import time
import hmac
import hashlib

from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

def retrieve_body(event, format='dict'):
    if event.get("isBase64Encoded", True):
        base64_bytes = event.get("body", "")
        message_bytes = base64.b64decode(base64_bytes)
        raw_slack_data = message_bytes.decode('ascii')
    else:
        raw_slack_data = event.get("body", "")
    if format=='dict':
        try:
            slack_data = parse_qs(raw_slack_data)
            return slack_data
        except:
            pass # do nothing
    else:
        return raw_slack_data
#---------------------------------------------------------------------------
def is_valid(event, slack_signing_secret, DEBUG=False):
    request_body = retrieve_body(event, format='text')

    timestamp = event["headers"]['x-slack-request-timestamp']
    timestamp_value = int(timestamp)

    if abs((time.time() - timestamp_value)) > 60 * 5 and not DEBUG:
        # The request timestamp is more than five minutes from local time.
        # It could be a replay attack, so let's ignore it.
        return False
    sig_basestring = 'v0:' + timestamp + ':' + request_body

    my_signature = 'v0=' + hmac.new(
        slack_signing_secret.encode('utf-8'),
        sig_basestring.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    message_signature = event["headers"]['x-slack-signature']
    return message_signature==my_signature

def get_slack_users(slack_token):
    client = WebClient(token=slack_token)
    try:
        # Call the users.list method using the WebClient
        # users.list requires the users:read scope
        result = client.users_list()
        users_store = result["members"]
    except SlackApiError as e:
        print("Error creating conversation: {}".format(e))
        users_store = []
    return users_store
