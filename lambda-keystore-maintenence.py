import json
import boto3
import os.path

def lambda_handler(event, context):
    # Create a S3 client
    s3_clent = boto3.client('s3')
    # Create a Secrets Manager client & get Secret
    # Source: https://stackoverflow.com/questions/58000751/using-aws-secrets-manager-with-python-lambda-console
    secrets_client = boto3.client('secretsmanager')
    secret_arn = 'arn:aws:secretsmanager:eu-west-1:<AcoountId>:secret:lambda-secret-1G6gvh'
    secret = secrets_client.get_secret_value(SecretId=secret_arn).get('SecretString')
    credentials = json.loads(secret)
    paswrd = credentials['password']
    #print(paswrd)

    # Event Info
    src_bucket = event['Records'][0]['s3']['bucket']['name']
    src_file = event['Records'][0]['s3']['object']['key']
    message = 'Hey, file ' + src_file + ' uploaded to ' + src_bucket
    print(message)

    # Download latest cert
    s3_clent.download_file(src_bucket, src_file, '/tmp/cert.crt')
    cert_exists = os.path.exists('/tmp/cert.crt')
    print(cert_exists)

    # Download truststore
    # Source : https://stackoverflow.com/questions/16480846/x-509-private-public-key
    s3_clent.download_file('bucket-change2', 'service1/truststore.pfx', '/tmp/truststore.pfx')
    keystore_exists = os.path.exists('/tmp/truststore.pfx')
    print(keystore_exists)

    # Import cert to truststore
    # Source: https://www.misterpki.com/aws-lambda-pyopenssl/



