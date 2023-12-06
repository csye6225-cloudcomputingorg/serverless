import os
import json
import boto3
import logging
from google.cloud import storage
from google.oauth2 import service_account
import requests
import base64
from datetime import datetime
import time
from uuid import uuid4
   
# Configure the logging module
logging.basicConfig(level=logging.INFO)

# DynamoDB configuration
dynamodb = boto3.resource("dynamodb", region_name=os.environ.get('AWS_REGION'))
ddb_table = dynamodb.Table(os.environ.get('DYNAMODB_TABLE_NAME'))


def check_email_status(user_email):
   
    secrets_manager_client = boto3.client('secretsmanager')
    
    api_secret_response = secrets_manager_client.get_secret_value(
        SecretId=os.environ.get('API_SECRET_ARN')
    )
    
    mailgun_api_key = api_secret_response['SecretString']
    
    # Get the latest message for the user_email
    messages_url = os.environ.get('MAILGUN_STATUS_URL')
    params = {'recipient': user_email}
    headers = {'Authorization': f'Basic {base64.b64encode(f"api:{mailgun_api_key}".encode()).decode()}'}

    max_attempts = 3
    for attempt in range(max_attempts):
        try:
            response = requests.get(messages_url, params=params, headers=headers)
            response.raise_for_status()
            response_json = response.json()
            print(f"mailgun status response {attempt}")
            print(response_json)

            # Check if there are any events
            if response_json['items']:
                latest_event = response_json['items'][0]
                event_type = latest_event.get('event', '')

                if event_type == 'accepted':
                    return "Email accepted for delivery"
                elif event_type == 'delivered':
                    return "Email delivered successfully"
                elif event_type == 'failed':
                    return "Email delivery failed"
                else:
                    print(f"Attempt {attempt + 1}/{max_attempts}: Email event type is {event_type}. Waiting for 10 seconds...")
        except requests.exceptions.RequestException as e:
            return f"Failed to check email status: {str(e)}"
        except Exception as e:
            return f"Failed to check email status: {str(e)}"

        time.sleep(10)

    return "Max attempts reached. Email status not confirmed."


def download_release_and_store_in_gcs(release_url, release_tag, user_email):
    
    print("download_release_and_store_in_gcs called")
    
    secrets_manager_client = boto3.client('secretsmanager')

    # Retrieve the secret value
    gcp_secret_response = secrets_manager_client.get_secret_value(
        SecretId=os.environ.get('GOOGLE_ACCESS_SECRET_ARN')
    )
    
    # Parse the secret string as JSON
    service_account_key = gcp_secret_response['SecretString']
    secret_key = json.loads(base64.b64decode(service_account_key).decode('utf-8'))
    

    # Extract repo name
    github_repo_name = release_url.rsplit('/', 1)[-1].split('/archive')[0]
    unique_object_name = f"{user_email}_{str(uuid4())}"
    
    response = requests.get(release_url)
    
    file_content_type = response.headers.get('content-type')
    
    if response.status_code != 200:
        email_text = "Invalid URL. Doesn't Point to Valid Submission File"
        send_email(user_email, email_text)
        email_status = check_email_status(user_email)
        track_email_sent_in_dynamodb(user_email, email_status)
    elif file_content_type != 'application/zip' and not release_url.endswith('.zip'):
        email_text="Download Error", "The downloaded file is not a zip file."
        send_email(user_email, email_text)
        email_status = check_email_status(user_email)
        track_email_sent_in_dynamodb(user_email, email_status)
    elif response.status_code == 200:
        with open("/tmp/github_release.zip", "wb") as f:
            f.write(response.content)
        
        gcs_creds = service_account.Credentials.from_service_account_info(secret_key)
        gcs_client = storage.Client(credentials=gcs_creds)
        gcs_bucket = gcs_client.bucket(os.environ.get('BUCKET_NAME'))
        blob = gcs_bucket.blob(
           f"{github_repo_name}_{unique_object_name}_{release_tag}.zip")
        blob.upload_from_filename("/tmp/github_release.zip")

        email_text = "Assignment Submitted Successfully."
        send_email(user_email, email_text)
        email_status = check_email_status(user_email)
        track_email_sent_in_dynamodb(user_email, email_status)
    else:
        email_text = f"Unexpected Error {response}"
        send_email(user_email, email_text)
        email_status = check_email_status(user_email)
        track_email_sent_in_dynamodb(user_email, email_status)
        return False


def send_email(to_email, text):
    
    mailgun_url = os.environ.get('MAILGUN_MESSAGE_URL')
    email_subject = "Assignment Submission Status"
    
    auth = ("api", os.environ.get('MAILGUN_API_KEY'))
    data = {
        "from": os.environ.get('FROM_EMAIL'),
        "to": to_email,
        "subject": email_subject,
        "text": text
    }
    
    response = requests.post(mailgun_url, auth=auth, data=data)
    response_data = response.json()
    
    if 'event' in response_data:
        event = response_data['event']
        if event == 'delivered':
            return "Email delivered successfully!"
        elif event == 'accepted':
            return "Email accepted for delivery."
        else:
            return f"Failed to send email. Event: {event}"
    else:
        print(f"Failed to send email. Status code: {response.status_code}")
        print(response.text)


def track_email_sent_in_dynamodb(user_email, status):
    
    current_timestamp = datetime.now().isoformat()
    
    email_data_success = {
        'email': user_email,
        'status': status + "_" + current_timestamp if status is not None else "Queued"
    }
     
    ddb_table.put_item(
        Item=email_data_success
    )


def lambda_handler(event, context):
    
    if 'Records' in event and len(event['Records']) > 0:
        
        sns_message_str = event['Records'][0]['Sns']['Message']
        sns_message_str = sns_message_str.replace("'", "\"")

        try:
            sns_message = json.loads(sns_message_str)
            print("Successfully parsed JSON:", sns_message)
        except json.JSONDecodeError as e:
            print("JSON decoding failed. Error:", e)

        # Access the 'repo_url' from the message
        release_url = sns_message.get('repo_url', '')
        print(release_url)
        
        to_email_sns = sns_message.get('user_email', '')
        print(to_email_sns)
        
        status = sns_message.get('status')
        print(sns_message.get('status'))
        
    
    if(status == 'success'):
        # Download the release from GitHub and store it in Google Cloud Storage
        download_release_and_store_in_gcs(release_url, sns_message.get('release_tag'), to_email_sns )
    elif (status == 'not_found'):
        email_text = "Assignment Not Found"
        send_email(to_email_sns, email_text)
        email_status = check_email_status(to_email_sns)
        track_email_sent_in_dynamodb(to_email_sns, email_status)
    elif (status == 'deadline_passed'):
        email_text = "The submission deadline has passed. No further submissions are allowed."
        send_email(to_email_sns, email_text)
        email_status = check_email_status(to_email_sns)
        track_email_sent_in_dynamodb(to_email_sns, email_status)
    elif (status == 'invalid_url'):
        email_text = "Invalid Submission URL. Please Check the URL and try again."
        send_email(to_email_sns, email_text)
        email_status = check_email_status(to_email_sns)
        track_email_sent_in_dynamodb(to_email_sns, email_status)
    elif (status == 'bad_request'):
        email_text = "Bad Request. Please Check the Request."
        send_email(to_email_sns, email_text)
        email_status = check_email_status(to_email_sns)
        track_email_sent_in_dynamodb(to_email_sns, email_status)
    elif (status == 'attempts_exceeded'):
        email_text = "Number of Attempts Exceeded. No further submissions are allowed."
        send_email(to_email_sns, email_text)
        email_status = check_email_status(to_email_sns)
        track_email_sent_in_dynamodb(to_email_sns, email_status)
    elif (status == 'unauthorised'):
        email_text = "Unauthorised, Please check your credentials."
        send_email(to_email_sns, email_text)
        email_status = check_email_status(to_email_sns)
        track_email_sent_in_dynamodb(to_email_sns, email_status)
        