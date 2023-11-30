import os
import json
import boto3
import logging
from google.cloud import storage
import requests
import base64
import sys
from uuid import uuid4
      
search_path = sys.path
print(search_path)

# local_download_path = "/home/admin/webapp/"
# blob_name = "v1.0.0.zip"
project_id = "gcp-demo-csye6225"
print(os.environ.get('GOOOGLE_PROJECT_ID'))

for key, value in os.environ.items():
        print(f"{key}: {value}")

# Configure the logging module
logging.basicConfig(level=logging.INFO)

# AWS configuration
aws_region = "us-east-1"
sns_topic_arn = os.environ.get('SNS_TOPIC_ARN')
dynamodb_table_name = "emailTrackerTable"
print(os.environ.get('DYNAMODB_TABLE_NAME'))
print(os.environ.get('AWS_REGION'))

print(aws_region + " : " + sns_topic_arn + " : " + dynamodb_table_name + " : ")

# Google Cloud Storage configuration
gcs_bucket_name = "submission-bucket"
print(os.environ.get('BUCKET_NAME'))

print(gcs_bucket_name)

# DynamoDB configuration
dynamodb = boto3.resource("dynamodb", region_name=aws_region)
ddb_table = dynamodb.Table(dynamodb_table_name)

print(dynamodb)
print(ddb_table)

# AWS SNS configuration
sns = boto3.client("sns", region_name=aws_region)

print(sns)

# def send_sns_notification(message):
#     print("send notification called")
#     sns.publish(
#         TopicArn=sns_topic_arn,
#         Message=message,
#         Subject="GitHub Release Download Status"
#     )


def download_release_and_store_in_gcs(release_url, release_tag, secret_key, user_email):
    
    print("download_release_and_store_in_gcs called")
    
    # Download release from GitHub

    # Remove unnecessary parts of the URL
    # repo_name_with_extension = release_url.rsplit('/', 1)[-1].split('/archive')[0]
    # release_tag_with_extension = release_url.split("/")[-1]

    # Extract repo name and release tag without extension
    github_repo_name = release_url.rsplit('/', 1)[-1].split('/archive')[0]
    # github_release_tag, _ = os.path.splitext(release_tag_with_extension)[0]
    unique_object_name = f"{user_email}_{str(uuid4())}"

    response = requests.get(release_url)
    
    print(response)
    
    # Check if the request was successful (status code 200)
    if response.status_code == 200:
        # Upload release to Google Cloud Storage
        with open("/tmp/github_release.zip", "wb") as f:
            f.write(response.content)
       
        print("response OK")
        # gcs_client = storage.Client()
        print(secret_key)
        gcs_client = storage.Client.from_service_account_info(secret_key)
        
        gcs_bucket = gcs_client.bucket(gcs_bucket_name)
        blob = gcs_bucket.blob(
           f"{github_repo_name}_{unique_object_name}_{release_tag}.zip")
        blob.upload_from_filename("/tmp/github_release.zip")

        return True
    else:
        return False


def send_email(api_key, domain, from_email, to_email, subject, text):
    mailgun_url = f"https://api.mailgun.net/v3/{domain}/messages"
    auth = ("api", api_key)
    data = {
        "from": from_email,
        "to": to_email,
        "subject": subject,
        "text": text
    }

    response = requests.post(mailgun_url, auth=auth, data=data)
    print(response)

    if response.status_code == 200:
        print("Email sent successfully!")
    else:
        print(f"Failed to send email. Status code: {response.status_code}")
        print(response.text)


def track_email_sent_in_dynamodb(sns_message):
    
    email_data_success = {
        'Id': sns_message.get('user_email', ''),
        'Email': sns_message.get('user_email', ''),
        'Status': 'Sent',
    }
    
    email_data_fail = {
        'Id': sns_message.get('user_email', ''),
        'Email': sns_message.get('user_email', ''),
        'Status': 'Failed',
    }
    
    response = ddb_table.put_item(
        Item=email_data_success
    )
    
    print(response)


def lambda_handler(event, context):

    # Create an AWS Secrets Manager client
    secrets_manager_client = boto3.client('secretsmanager')

    # Retrieve the secret value
    secret_response = secrets_manager_client.get_secret_value(
        SecretId=os.environ.get('GOOGLE_ACCESS_SECRET_ARN')
    )

    print(secret_response)

    # Parse the secret string as JSON
    service_account_key = secret_response['SecretString']

    print(service_account_key)
    
    # Access individual secret values
    # access_key = secret_data[0]
    # secret_key = secret_data[1]
    
    service_account_key_json = json.loads(base64.b64decode(service_account_key).decode('utf-8'))
    print(base64.b64decode(service_account_key).decode('utf-8'))
    print(service_account_key_json)

    if 'Records' in event and len(event['Records']) > 0:
        # Assuming event is the dictionary containing your SNS message
        sns_message_str = event['Records'][0]['Sns']['Message']

        # Print or log the original string
        print(f"Original SNS Message String: {sns_message_str}")

        # Replace single quotes with double quotes
        sns_message_str = sns_message_str.replace("'", "\"")

        # Print or log the modified string
        print(f"Modified SNS Message String: {sns_message_str}")

        # Now parse the modified string as JSON
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


    # Task 1: Download the release from GitHub and store it in Google Cloud Storage
    download_status = download_release_and_store_in_gcs(release_url, sns_message.get('release_tag'),  service_account_key_json, to_email_sns)
    print(download_status)

    domain = "adityasrprakash.me"

    # Replace these with your Mailgun API key, domain, and email addresses
    mailgun_api_key = "4dc82ba6f91f8bbf597a3aeced3ef791-30b58138-ae50c84a"
    mailgun_domain = domain
    from_email = "prakash.adi@northeastern.edu"
    to_email = "adityaprakash41@gmail.com"
    email_subject = "Download Status"
    email_text = "The download is complete. Please check your attachment."

    # Task 2: Email the user the status of the download
    if download_status:
        send_email(mailgun_api_key, mailgun_domain, from_email,
           to_email, email_subject, email_text)
    
    # Task 3: Track the emails sent in DynamoDB
    track_email_sent_in_dynamodb(sns_message)

    # Task 4: Send SNS notification
    # send_sns_notification(
        # f"GitHub release download status: {'Success' if download_status else 'Failure'}")
