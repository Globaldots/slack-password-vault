import boto3
import base64
from botocore.exceptions import ClientError

ERROR_IMAGE = 'https://miro.medium.com/max/978/1*pUEZd8z__1p-7ICIO1NZFA.png'

def get_region(region=None):
    # Create a S3 client
    session = boto3.session.Session()
    client = session.client(
        service_name='s3',
        region_name=region
    )
    return client.meta.region_name

def put_image(filename, imagedata, bucket, content_type='image/png', region=get_region()):
    # Create a S3 client
    session = boto3.session.Session()
    client = session.client(
        service_name='s3',
        region_name=region
    )
    try:
        response = client.put_object(
            Bucket=bucket,
            Key=filename,
            Body=imagedata,
            ContentType=content_type
        )
        return signed_url(filename, bucket, expiry=3600, region=region)
    except ClientError as e:
        print(e)
        return ERROR_IMAGE
    return response

def signed_url(filename, bucket, expiry=3600, region=get_region()):
    # Create a S3 client
    session = boto3.session.Session()
    client = session.client(
        service_name='s3',
        region_name=region
    )
    try:
        response = client.generate_presigned_url('get_object',
                                                        Params={'Bucket': bucket,
                                                                'Key': filename},
                                                        ExpiresIn=expiry)
    except ClientError as e:
        print(e)
        return ERROR_IMAGE
    return response


def lower_keys(d):
    tempdir = {key.lower():value for key,value in d.items()}
    return tempdir




if __name__=='__main__':
    print(get_region())