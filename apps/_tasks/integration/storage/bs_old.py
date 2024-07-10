import json
import subprocess
from apps._tasks.exceptions import NodeBackupSheepUploadFailedError


def storage_bs_old(stored_backup):
    try:
        local_zip = f"_storage/{stored_backup.backup.uuid}.zip"
        storage = stored_backup.storage
        backup = stored_backup.backup

        key = f"{storage.storage_bs.prefix}{stored_backup.backup.uuid}.zip"
        bucket = storage.storage_bs.bucket_name
        endpoint = storage.storage_bs.endpoint
        profile = storage.storage_bs.profile

        # boto3.setup_default_session(profile_name='filebase')
        # s3_client = boto3.client("s3", endpoint_url=f"https://{storage.storage_bs.endpoint}")

        # s3_client = boto3.session.Session(
        #     profile_name='filebase',
        #     region_name=storage.storage_bs.region,
        #     aws_access_key_id=settings.FILEBASE_ACCESS_KEY_ID,
        #     aws_secret_access_key=settings.FILEBASE_SECRET_ACCESS_KEY
        # ).client(
        #     's3',
        #     endpoint_url=f"https://{storage.storage_bs.endpoint}"
        # )

        # Working
        # session = boto3.Session(
        #     aws_access_key_id=settings.FILEBASE_ACCESS_KEY_ID,
        #     aws_secret_access_key=settings.FILEBASE_SECRET_ACCESS_KEY,
        # )
        # s3 = session.resource(
        #     "s3", endpoint_url="https://s3.filebase.com"
        # )

        metadata = {
            "account": storage.account.id,
            "backup": backup.id,
            "backup-type": backup.get_type_display().lower(),
            "schedule": backup.schedule.id if backup.schedule else '',
        }

        if hasattr(backup, "database"):
            metadata.update({
                "node": backup.database.node.id,
                "type": backup.database.node.get_type_display(),
                "database": backup.database.id,
                "connection": backup.database.node.connection.id,
            })
        elif hasattr(backup, "website"):
            metadata.update({
                "node": backup.website.node.id,
                "type": backup.website.node.get_type_display(),
                "website": backup.website.id,
                "connection": backup.website.node.connection.id,
            })
        elif hasattr(backup, "wordpress"):
            metadata.update({
                "node": backup.wordpress.node.id,
                "type": backup.wordpress.node.get_type_display(),
                "wordpress": backup.wordpress.id,
                "connection": backup.wordpress.node.connection.id,
            })

        metadata_new = json.loads(json.dumps(metadata), parse_int=str)

        # with open(local_zip, "rb") as data:
        #     s3.meta.client.upload_fileobj(
        #         data,
        #         bucket,
        #         key,
        #         ExtraArgs={"Metadata": metadata_new},
        #     )
        '''
        Upload File To Storage
        '''
        app_path = "/home/ubuntu/backupsheep"
        metadata_json = json.dumps(metadata_new)
        execstr = f"/usr/local/bin/aws --profile {profile} --endpoint https://{endpoint} s3 cp {app_path}/{local_zip} s3://{bucket}/{key} --metadata '{metadata_json}'"
        # capture_message(execstr)
        process = subprocess.Popen(execstr, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        output, error = process.communicate()
        if error and error != "":
            raise ValueError(error)
        # output_json = json.loads(output)
        # s3.meta.client.upload_file(
        #     local_zip, storage.storage_bs.bucket_name, key
        # )
        storage_file_id = f"{stored_backup.backup.uuid}.zip"
        stored_backup.storage_file_id = storage_file_id
        stored_backup.save()
    except FileNotFoundError as e:
        stored_backup.status = stored_backup.Status.UPLOAD_FAILED_FILE_NOT_FOUND
        stored_backup.save()
    except Exception as e:
        raise NodeBackupSheepUploadFailedError(stored_backup.backup.uuid_str, stored_backup.backup.attempt_no, stored_backup.backup.type, e.__str__())