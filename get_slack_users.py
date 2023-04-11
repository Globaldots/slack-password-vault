import json
import logging
import os

from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
import access_ssm_aws as vault

if __name__ == "__main__":
    # decide how you pass constants into your code
    # token = os.environ.get("SLACK_BOT_TOKEN")
    configuration=json.loads( vault.get_secret('otp-config'))
    token=configuration.get("slack-token")
    vault_editors = configuration.get("vault_editors",[])
    vault_super_editors = configuration.get("vault_super_editors",[])

    # WebClient instantiates a client that can call API methods
    # When using Bolt, you can use either `app.client` or the `client` passed to listeners.
    client = WebClient(token=token)
    logger = logging.getLogger(__name__)
    # You probably want to use a database to store any user information ;)

    try:
        # Call the users.list method using the WebClient
        # users.list requires the users:read scope
        result = client.users_list()
        users_store = {user["id"] : user for user in result["members"] }
    except SlackApiError as e:
        logger.error("Error creating conversation: {}".format(e))

# print(users_store)

for userid in vault_editors:
    print("Editor:",
          userid,
          users_store.get(userid,{}).get('real_name','N/A'),
          'Inactive' if users_store.get(userid, {}).get('deleted', True) else 'Active'
          )

for userid in vault_super_editors:
    print("Super Editor:",
          userid,
          users_store.get(userid,{}).get('real_name','N/A'),
          'Inactive' if users_store.get(userid, {}).get('deleted', True) else 'Active'
          )

print()