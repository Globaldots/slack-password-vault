# The slack /otp command
The /otp command can be used to store and retrieve shared one-time-passwords via slack.   

The command executes a AWS python Lambda, and uses either AWS SSM or AWS SecretsManager to store the OTP seeds. SSM costs less, but it is up to you to decide. 

## Installation
If you use venv, now is the time to activate it. Install dependencies for your entire python environment or to your venv by running

`pip install -r requirements.txt`

## Setup on Slack 
Create a new slash command app. It needs the following settings: 
* Display Name (Bot Name): otp
* It uses the /otp slash command
* It needs the `commands` and `users:read` OAUTH scopes
aws secretsmanager get-secret-value --secret-id "otp-config"  --region eu-central-1
