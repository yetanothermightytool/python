
import sys
from boto3 import client, Session
from botocore.exceptions import ProfileNotFound, ClientError
import datetime
import argparse


def print_line():
    print("___________________________________________________")
    """
    Original script from Wasabi Knowledge Base.
    https://knowledgebase.wasabi.com/hc/en-us/articles/5495621320603-How-do-I-find-the-longest-Retention-Period-I-have-in-my-Object-Lock-Bucket-
    Added the number of objects, size and the possibility to list only objects which have threshold_days > than given value.
    """


def get_credentials():
    """
    This function gets the access key and secret key by 2 methods.
    1. Select profile from aws credentials file.
       Make sure that you have run AWS config and set up your keys in the ~/.aws/credentials file.
    2. Insert the keys directly as a string.
    :return: access key and secret key
    """
    credentials_verified = False
    aws_access_key_id = None
    aws_secret_access_key = None
    while not credentials_verified:
        ch = input("$ Press 1 and enter to select existing profile\n"
                   "$ Press 2 and enter to enter Access Key and Secret Key\n"
                   "$ Press 3 to exit: ")
        if ch.strip() == "1":
            aws_access_key_id, aws_secret_access_key = select_profile() 
            if aws_access_key_id is not None and aws_secret_access_key is not None:
                credentials_verified = True
        elif ch.strip() == "2":
            aws_access_key_id = input("$ AWS access key").strip()
            aws_secret_access_key = input("$ AWS secret access key").strip()
            credentials_verified = True
        elif ch.strip() == "3":
            sys.exit(0)
        else:
            print("Invalid choice please try again")
    return aws_access_key_id, aws_secret_access_key


def select_profile():
    """
    sub-function under get credentials that selects the profile form ~/.aws/credentials file.
    :return: access key and secret key
    """
    profile_selected = False
    while not profile_selected:
        try:
            profiles = Session().available_profiles
            if len(profiles) == 0:
                return None, None
            print("$ Available Profiles: ", profiles)
        except Exception as e:
            print(e)
            return None, None
        profile_name = input("$ Profile name: ").strip().lower()
        try:
            session = Session(profile_name=profile_name)
            credentials = session.get_credentials()
            aws_access_key_id = credentials.access_key
            aws_secret_access_key = credentials.secret_key
            profile_selected = True
            return aws_access_key_id, aws_secret_access_key
        except ProfileNotFound:
            print("$ Invalid profile. Please Try again.")
        except Exception as e:
            raise e


def get_bucket_name():
    print_line()
    bucket_verified = False
    bucket_name = ""
    while not bucket_verified:
        bucket_name = input("$ Enter your bucket name: ").strip()
        if bucket_name.strip() is not None and bucket_name.strip() != "":
            bucket_verified = True
    return bucket_name

def get_location(bucket_name, aws_access_key_id, aws_secret_access_key, endpoint):
    _s3_client = client('s3',
                        endpoint_url=endpoint,
                        aws_access_key_id=aws_access_key_id,
                        aws_secret_access_key=aws_secret_access_key)
    try:
        result = _s3_client.get_bucket_location(Bucket=bucket_name)
    except ClientError as e:
        raise Exception("boto3 client error in get_bucket_location_of_s3: " + e.__str__())
    except Exception as e:
        raise Exception("Unexpected error in get_bucket_location_of_s3 function: " + e.__str__())

    location = result['LocationConstraint'] or ('us-east-1')
    return location, endpoint


def create_connection_and_test(aws_access_key_id: str, aws_secret_access_key: str, _region, _bucket):
    """
    Creates a connection to wasabi endpoint based on selected region and checks if the access keys are valid.
    NOTE: creating the connection is not enough to test. We need to make a method call to check for its working status.
    :param aws_access_key_id: access key string
    :param aws_secret_access_key: secret key string
    :param _region: region string
    :param _bucket: bucket name string
    :return: reference to the connection client
    """
    try:
        _s3_client = client('s3',
                            endpoint_url=_region,
                            aws_access_key_id=aws_access_key_id,
                            aws_secret_access_key=aws_secret_access_key)

        try:
            _s3_client.head_bucket(Bucket=_bucket)
        except ClientError:
            # The bucket does not exist or you have no access.
            raise Exception("$ bucket does not exist in the account please re-check the name and try again: ")

        return _s3_client

    except ClientError:
        print("Invalid Access and Secret keys")
    except Exception as e:
        raise e
    # cannot reach here
    return None


def get_verbose_display():
    verbose_set = False
    result = False
    while not verbose_set:
        user_input = input("$ Do you want to display the full list of the objects in your bucket [Y/N]?: ")
        if user_input.strip().lower() == "y" or user_input.strip().lower() == "yes":
            result = True
            verbose_set = True
        elif user_input.strip().lower() == "n" or user_input.strip().lower() == "no":
            verbose_set = True
    return result


def main():

    parser = argparse.ArgumentParser(description="S3 get object information")
    parser.add_argument("-endpoint", required=True, help="S3 endpoint")
    parser.add_argument("-threshold",required=True, type=int, help="Display only object immutable > threshold")
    args = parser.parse_args()

    # generate access keys
    access_key_id, secret_access_key = get_credentials()

    bucket_name = get_bucket_name()

    # prefix
    prefix = input("$ Enter a prefix (do not start with '/'): ").strip()

    # get region
    print("$ Loading the region information for your bucket!")
    region, endpoint_url = get_location(bucket_name, access_key_id, secret_access_key, args.endpoint)
    print(f'$ Region loaded successfully: {region}')

    # test the connection and access keys. Also checks if the bucket is valid.
    print('$ Testing connection to Wasabi...')
    s3_client = create_connection_and_test(access_key_id, secret_access_key, endpoint_url, bucket_name)
    print('$ Connected successfully.')
    print_line()

    # Check object lock configuration
    print(f'$ Checking if object lock is enabled on bucket {bucket_name}')
    bucket_has_object_lock = False;
    try:
        response = s3_client.get_object_lock_configuration(Bucket=bucket_name)
        enabled = response['ObjectLockConfiguration']['ObjectLockEnabled'] == 'Enabled'
        if not enabled:
            print(f'$ The object lock is not enabled for bucket {bucket_name}')
            print('$ Exiting the script!')
            print_line()
            sys.exit(-1)
    except ClientError:
        print(f'$ The bucket "{bucket_name}" doesn\'t have object lock')
        print('$ Exiting the script!')
        print_line()
        sys.exit(-1)

    verbose = get_verbose_display()

    print(f'$ Analyzing bucket content: {bucket_name}/{prefix}')
    print(f'$ Note: for large buckets, this could take a while!!')

    if verbose:
        print_line()
    # create a paginator with default settings.
    object_response_paginator = s3_client.get_paginator('list_object_versions')

    if len(prefix) > 0:
        operation_parameters = {'Bucket': bucket_name,
                                'Prefix': prefix}
    else:
        operation_parameters = {'Bucket': bucket_name}

    # Initialize variables
    mode                 = None
    number_of_days       = None
    longest_retention    = 0
    longest_object       = ""
    longest_version_id   = ""
    object_count         = 0
    total_size_bytes     = 0
    long_retention_count = 0

    # Set this values for displaying objects with retention > threshold_days
    threshold_days       = args.threshold

    # Paginating over bucket's objects
    for object_response_itr in object_response_paginator.paginate(**operation_parameters):
        deleted_objects = {}
        if 'DeleteMarkers' in object_response_itr:
            for delete_marker in object_response_itr["DeleteMarkers"]:
                dm_version_id = delete_marker['VersionId']
                dm_key = delete_marker['Key']
                if delete_marker['IsLatest']:
                    deleted_objects[dm_key] = dm_version_id

        # checking all the versions of the object!
        if 'Versions' not in object_response_itr:
            continue
        old_key = ''
        for version in object_response_itr['Versions']:
            # Checking if response contains Key & VersionId fields
            if 'Key' not in version or 'VersionId' not in version:
                continue

            key        = version["Key"]
            version_id = version["VersionId"]
            current    = "YES" if version["IsLatest"] else "NO "

            # Increment object count
            if key.startswith(prefix):
                object_count += 1

            # Display object size 
            size_bytes = version.get('Size', 0)
            size_kb    = size_bytes / 1024  
            size_mb    = size_kb / 1024     

            
            object_retention = s3_client.get_object_retention(
                Bucket=bucket_name,
                Key=key,
                VersionId=version_id
            )
            if 'Retention' in object_retention \
                    and 'Mode' in object_retention['Retention']:
                mode = object_retention['Retention']['Mode']

            # Get number_of_days 
            if 'Retention' in object_retention \
                    and 'RetainUntilDate' in object_retention['Retention']:
                retain_until_date = object_retention['Retention']['RetainUntilDate']
                timezone = retain_until_date.tzinfo
                current_date = datetime.datetime.now(timezone)
                if current_date < retain_until_date:
                    number_of_days = (retain_until_date - current_date).days

                    # Update longest retention information
                    if number_of_days > longest_retention:
                        longest_retention = number_of_days
                        longest_object = key
                        longest_version_id = version_id

                    # Check if retention is longer than the threshold
                    if number_of_days > threshold_days:
                        long_retention_count += 1

            if verbose:
                print(f'$     Version Id: {version_id} | Current version: {current} | '
                      f'Mode: {mode} | Remaining days: {number_of_days} | Size: {size_mb:.2f} MB')

            # Total size
            total_size_bytes += size_bytes

  
    print_line()
    print(f'$ Number of objects within the prefix "{prefix}": {object_count}')

    # Display all
    total_size_kb = total_size_bytes / 1024  
    total_size_mb = total_size_kb / 1024     
    print(f'$ Longest retention detected in ({longest_retention}) day(s) for object "{longest_object}" with it\'s version ({longest_version_id})')
    print(f'$ Total size of all objects within the prefix "{prefix}": {total_size_mb:.2f} MB')
    print(f'$ Number of objects with immutability longer than {threshold_days} days: {long_retention_count}')


if __name__ == '__main__':
    print("Welcome. This script will list objects that are still under retention.")
    print_line()
    main()
    print("Ended execution!")
