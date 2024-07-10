from celery.exceptions import InvalidTaskError
from django.core.cache import cache
from rest_framework.exceptions import APIException


class TaskParamsNotProvided(InvalidTaskError):
    def __init__(
        self,
        message="Unable to initiate backup because of invalid parameters.",
    ):
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f"{self.message}"


class NodeNotReadyForBackupError(APIException):
    """Exception raised for errors in the input node.

    Attributes:
        node -- input node which caused the error
        message -- explanation of the error
    """

    email_template_id = "unable_to_start_backup"

    def __init__(
        self,
        node,
        attempt_no,
        backup_type,
        message="The node must be in an active or retrying status to initiate the backup.",
    ):
        self.node = node
        self.attempt_no = attempt_no
        self.backup_type = backup_type
        self.message = message
        super().__init__(self.message)

        # Add to logs
        if self.node:
            data = {
                "error": self.__class__.__name__,
                "message": self.message,
                "node_id": self.node.id,
                "node_name": self.node.name,
                "connection_id": self.node.connection.id,
                "connection_name": self.node.connection.name,
                "attempt_no": self.attempt_no,
                "backup_type": self.backup_type,
            }
            node.connection.account.create_log(data)

    def __str__(self):
        return f"{self.message}"


class ConnectionNotReadyForBackupError(APIException):
    """Exception raised for errors in the input node.

    Attributes:
        node -- input node which caused the error
        message -- explanation of the error
    """

    email_template_id = "unable_to_start_backup"

    def __init__(
        self,
        node,
        attempt_no,
        backup_type,
        message="The connection must be in an active or retrying status to initiate the backup.",
    ):
        self.node = node
        self.attempt_no = attempt_no
        self.backup_type = backup_type
        self.message = message
        super().__init__(self.message)

        # Add to logs
        if self.node:
            data = {
                "error": self.__class__.__name__,
                "message": self.message,
                "node_id": self.node.id,
                "node_name": self.node.name,
                "connection_id": self.node.connection.id,
                "connection_name": self.node.connection.name,
                "attempt_no": self.attempt_no,
                "backup_type": self.backup_type,
            }
            node.connection.account.create_log(data)

    def __str__(self):
        return f"{self.message}"


class ConnectionValidationFailedError(APIException):
    """Exception raised for errors in the input node.

    Attributes:
        node -- input node which caused the error
        message -- explanation of the error
    """

    email_template_id = "unable_to_start_backup"

    def __init__(
        self,
        node,
        attempt_no,
        backup_type,
        message="Unable to validate the connection for this node.",
    ):
        self.node = node
        self.attempt_no = attempt_no
        self.backup_type = backup_type
        self.message = message
        super().__init__(self.message)
        # Add to logs
        if self.node:
            data = {
                "error": self.__class__.__name__,
                "message": self.message,
                "node_id": self.node.id,
                "node_name": self.node.name,
                "connection_id": self.node.connection.id,
                "connection_name": self.node.connection.name,
                "attempt_no": self.attempt_no,
                "backup_type": self.backup_type,
            }
            node.connection.account.create_log(data)

    def __str__(self):
        return f"{self.message}"


class NodeValidationFailedError(APIException):
    """Exception raised for errors in the input node.

    Attributes:
        node -- input node which caused the error
        message -- explanation of the error
    """

    email_template_id = "unable_to_start_backup"

    def __init__(
        self,
        node,
        attempt_no,
        backup_type,
        message="Unable to validate the node at your cloud provider account. Please check your server status and make sure it's in active state.",
    ):
        self.node = node
        self.attempt_no = attempt_no
        self.backup_type = backup_type
        self.message = message
        super().__init__(self.message)
        # Add to logs
        if self.node:
            data = {
                "error": self.__class__.__name__,
                "message": self.message,
                "node_id": self.node.id,
                "node_name": self.node.name,
                "connection_id": self.node.connection.id,
                "connection_name": self.node.connection.name,
                "attempt_no": self.attempt_no,
                "backup_type": self.backup_type,
            }
            node.connection.account.create_log(data)

    def __str__(self):
        return f"{self.message}"


class NodeBackupStatusCheckTimeOutError(APIException):
    """Exception raised for errors in the input node.

    Attributes:
        node -- input node which caused the error
        message -- explanation of the error
    """

    def __init__(
        self,
        node,
        backup_name,
        attempt_no=None,
        backup_type=None,
        message="Encountered timeout while checking status on backup/snapshot. "
        "It may be created in your cloud provider account but we are unable to confirm.",
    ):
        data = cache.get(backup_name)
        if data:
            attempt_no = data.get("attempt_no")
            backup_type = data.get("backup_type")

        self.node = node
        self.attempt_no = attempt_no
        self.backup_type = backup_type
        self.message = message
        super().__init__(self.message)
        # Add to logs
        if self.node:
            data = {
                "error": self.__class__.__name__,
                "message": self.message,
                "node_id": self.node.id,
                "node_name": self.node.name,
                "connection_id": self.node.connection.id,
                "connection_name": self.node.connection.name,
                "attempt_no": self.attempt_no,
                "backup_type": self.backup_type,
            }
            node.connection.account.create_log(data)

    def __str__(self):
        return f"{self.message}" f"This was attempt no:{self.attempt_no} and backup type was:{self.backup_type}."


class NodeBackupStatusCheckCallError(APIException):
    """Exception raised for errors in the input node.

    Attributes:
        node -- input node which caused the error
        message -- explanation of the error
    """

    def __init__(
        self,
        node,
        backup_name,
        attempt_no=None,
        backup_type=None,
        message="Unable to get status on backup/snapshot. "
        "This cloud be temporary because of failed API call. We keep trying until timeout.",
    ):
        data = cache.get(backup_name)
        if data:
            attempt_no = data.get("attempt_no")
            backup_type = data.get("backup_type")

        self.node = node
        self.attempt_no = attempt_no
        self.backup_type = backup_type
        self.message = message
        super().__init__(self.message)
        # Add to logs
        if self.node:
            data = {
                "error": self.__class__.__name__,
                "message": self.message,
                "node_id": self.node.id,
                "node_name": self.node.name,
                "connection_id": self.node.connection.id,
                "connection_name": self.node.connection.name,
                "attempt_no": self.attempt_no,
                "backup_type": self.backup_type,
            }
            node.connection.account.create_log(data)

    def __str__(self):
        return f"{self.message}" f"This was attempt no:{self.attempt_no} and backup type was:{self.backup_type}."


class NodeBackupFailedError(APIException):
    """Exception raised for errors in the input node.

    Attributes:
        node -- input node which caused the error
        message -- explanation of the error
    """

    email_template_id = "error_during_backup"

    def __init__(
        self,
        node,
        backup_uuid=None,
        attempt_no=None,
        backup_type=None,
        message="Unable to create backup/snapshot. "
        "This cloud be temporary because of failed API call. We will keep trying.",
    ):
        self.node = node
        self.backup_uuid = backup_uuid
        self.attempt_no = attempt_no
        self.backup_type = backup_type
        self.message = message
        super().__init__(self.message)
        # Add to logs
        if self.node:
            data = {
                "error": self.__class__.__name__,
                "message": self.message,
                "node_id": self.node.id,
                "node_name": self.node.name,
                "connection_id": self.node.connection.id,
                "connection_name": self.node.connection.name,
                "attempt_no": self.attempt_no,
                "backup_type": self.backup_type,
                "backup__uuid": self.backup_uuid,
            }
            node.connection.account.create_log(data)

    def __str__(self):
        return (
            f"{self.message}  Backup UUID:{self.backup_uuid}. "
            f"This was attempt no:{self.attempt_no} and backup type was:{self.backup_type}."
        )


class NodeBackupTimeoutError(APIException):
    email_template_id = "error_during_backup"

    def __init__(
        self,
        node,
        backup_uuid=None,
        attempt_no=None,
        backup_type=None,
        message="Backup execution timeout. Backup must complete within 24 hours or else it will be terminated."
        " Try to reduce number of files you are trying to backup '"
        "or increase the Parallel Downloads on node modify page",
    ):
        self.node = node
        self.backup_uuid = backup_uuid
        self.attempt_no = attempt_no
        self.backup_type = backup_type
        self.message = message
        super().__init__(self.message)
        # Add to logs
        if self.node:
            data = {
                "error": self.__class__.__name__,
                "message": self.message,
                "node_id": self.node.id,
                "node_name": self.node.name,
                "connection_id": self.node.connection.id,
                "connection_name": self.node.connection.name,
                "attempt_no": self.attempt_no,
                "backup_type": self.backup_type,
                "backup__uuid": self.backup_uuid,
            }
            node.connection.account.create_log(data)

    def __str__(self):
        return (
            f"{self.message}  Backup UUID:{self.backup_uuid}. "
            f"This was attempt no:{self.attempt_no} and backup type was:{self.backup_type}."
        )


class NodeConnectionError(APIException):
    """Exception raised for errors in the input node.

    Attributes:
        node -- input node which caused the error
        message -- explanation of the error
    """

    def __init__(
        self,
        node=None,
        backup_name=None,
        attempt_no=None,
        backup_type=None,
        message="Unable to make connection.",
    ):
        data = cache.get(backup_name)
        if data:
            attempt_no = data.get("attempt_no")
            backup_type = data.get("backup_type")

        self.node = node
        self.attempt_no = attempt_no
        self.backup_type = backup_type
        self.message = message
        super().__init__(self.message)

        # Add to logs
        if self.node:
            data = {
                "error": self.__class__.__name__,
                "message": self.message,
                "node_id": self.node.id,
                "node_name": self.node.name,
                "connection_id": self.node.connection.id,
                "connection_name": self.node.connection.name,
                "attempt_no": self.attempt_no,
                "backup_type": self.backup_type,
            }
            node.connection.account.create_log(data)

    def __str__(self):
        return (
            f"{self.message}  Backup UUID:. "
            f"This was attempt no:{self.attempt_no} and backup type was:{self.backup_type}."
        )


class NodeConnectionErrorSSH(APIException):
    status_code = 503
    default_detail = "Unable to validate SSH connection."
    default_code = "node_connection_error"

    def __init__(
        self,
        message="",
    ):
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f"{self.message}"


class NodeConnectionErrorSFTP(APIException):
    """Exception raised for errors in the input node.

    Attributes:
        node -- input node which caused the error
        message -- explanation of the error
    """

    def __init__(
        self,
        message="Unable to validate SFTP integration.",
    ):
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f"{self.message}"


class NodeConnectionErrorMYSQL(APIException):
    status_code = 503
    default_detail = "Unable to validate MySQL integration."
    default_code = "node_connection_error_mysql"

    def __init__(
        self,
        message="",
    ):
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f"{self.message}"


class NodeConnectionErrorMARIADB(APIException):
    status_code = 503
    default_detail = "Unable to validate MariaDB integration."
    default_code = "node_connection_error_mariadb"

    def __init__(
        self,
        message="",
    ):
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f"{self.message}"


class NodeConnectionErrorPOSTGRESQL(APIException):
    status_code = 503
    default_detail = "Unable to validate PostgreSQL integration."
    default_code = "node_connection_error_postgresql"

    def __init__(
        self,
        message="",
    ):
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f"{self.message}"


class NodeConnectionErrorWebsite(APIException):
    status_code = 503
    default_detail = "Unable to validate Website connection."
    default_code = "node_connection_error_website"

    def __init__(
        self,
        message="",
    ):
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f"{self.message}"


class NodeSnapshotDeleteFailed(APIException):
    """Exception raised for errors in the input node.

    Attributes:
        node -- input node which caused the error
        message -- explanation of the error
    """

    def __init__(
        self,
        node=None,
        backup_name=None,
        message="Unable to delete snapshot.",
    ):
        self.node = node
        self.backup_name = backup_name
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f"{self.message}"


class NodeBackupDeleteFailed(APIException):
    """Exception raised for errors in the input node.

    Attributes:
        node -- input node which caused the error
        message -- explanation of the error
    """

    def __init__(
        self,
        node=None,
        backup_name=None,
        message="Unable to delete snapshot.",
    ):
        self.node = node
        self.backup_name = backup_name
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f"{self.message}"


class NodeConnectionErrorEligibleObjects(APIException):
    status_code = 503
    default_detail = (
        "Unable to get list of objects from connection. Please check your permissions or try reconnecting connection."
    )
    default_code = "backup_unable_to_initiate"

    def __init__(
        self,
        message="",
    ):
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f"{self.message}"


class IntegrationValidationFailed(APIException):
    status_code = 503
    default_detail = "Integration validation failed"
    default_code = "integration_validation_failed"

    def __init__(
        self,
        attempt_no=1,
        message="",
    ):
        self.message = message
        self.attempt_no = attempt_no
        super().__init__(self.message)

    def __str__(self):
        return f"{self.message}"


class IntegrationValidationError(APIException):
    status_code = 503
    default_detail = "Integration validation error"
    default_code = "integration_validation_error"

    def __init__(
        self,
        message="",
    ):
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f"{self.message or self.default_detail}"


class StorageValidationFailed(APIException):
    status_code = 503
    default_detail = "Storage validation failed"
    default_code = "storage_validation_failed"

    def __init__(
        self,
        message="",
    ):
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f"{self.message}"


class NodeValidationFailed(APIException):
    status_code = 503
    default_detail = "Node validation failed"
    default_code = "node_validation_failed"

    def __init__(
        self,
        message="",
    ):
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f"{self.message}"


class NodeDropboxUploadFailedError(APIException):
    """Exception raised for errors in the input node.

    Attributes:
        node -- input node which caused the error
        message -- explanation of the error
    """

    def __init__(
        self,
        backup_uuid=None,
        attempt_no=None,
        backup_type=None,
        message="Unable to upload backup file.",
    ):
        self.backup_uuid = backup_uuid
        self.attempt_no = attempt_no
        self.backup_type = backup_type
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f"{self.message}"


class NodeOneDriveUploadFailedError(APIException):
    """Exception raised for errors in the input node.

    Attributes:
        node -- input node which caused the error
        message -- explanation of the error
    """

    def __init__(
        self,
        backup_uuid=None,
        attempt_no=None,
        backup_type=None,
        message="Unable to upload backup file.",
    ):
        self.backup_uuid = backup_uuid
        self.attempt_no = attempt_no
        self.backup_type = backup_type
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f"{self.message}"


class NodeGoogleDriveUploadFailedError(APIException):
    """Exception raised for errors in the input node.

    Attributes:
        node -- input node which caused the error
        message -- explanation of the error
    """

    default_detail = "Unable to upload backup file to Google Drive"

    def __init__(
        self,
        backup_uuid=None,
        attempt_no=None,
        backup_type=None,
        message="Unable to upload backup file.",
    ):
        self.backup_uuid = backup_uuid
        self.attempt_no = attempt_no
        self.backup_type = backup_type
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f"{self.message or self.default_detail}"


class NodeGoogleDriveNotEnoughStorageError(APIException):
    """Exception raised for errors in the input node.

    Attributes:
        node -- input node which caused the error
        message -- explanation of the error
    """

    email_template_id = "unable_to_upload_backup"
    default_detail = "The user's Google Drive storage quota has been exceeded."

    def __init__(
        self,
        backup_uuid=None,
        attempt_no=None,
        backup_type=None,
        message="Unable to upload backup file.",
    ):
        self.backup_uuid = backup_uuid
        self.attempt_no = attempt_no
        self.backup_type = backup_type
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f"{self.message or self.default_detail}"


class NodeGoogleDriveTooManyRequestsError(APIException):
    email_template_id = "unable_to_upload_backup"
    default_detail = "The Google Drive API returned with too many requests error."

    def __init__(
        self,
        backup_uuid=None,
        attempt_no=None,
        backup_type=None,
        message="Unable to upload backup file.",
    ):
        self.backup_uuid = backup_uuid
        self.attempt_no = attempt_no
        self.backup_type = backup_type
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f"{self.message or self.default_detail}"


class NodeDigitalOceanSpacesBucketDeletedError(APIException):
    email_template_id = "unable_to_upload_backup"
    default_detail = "The user's DigitalOcean Spaces storage bucket is not available or deleted."

    def __init__(
        self,
        backup_uuid=None,
        attempt_no=None,
        backup_type=None,
        message="Unable to upload backup file.",
    ):
        self.backup_uuid = backup_uuid
        self.attempt_no = attempt_no
        self.backup_type = backup_type
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f"{self.message or self.default_detail}"


class NodeDigitalOceanSpacesNoSuchBucketError(APIException):
    email_template_id = "unable_to_upload_backup"
    default_detail = "The user's DigitalOcean Spaces storage bucket is not available or deleted."

    def __init__(
        self,
        backup_uuid=None,
        attempt_no=None,
        backup_type=None,
        message="Unable to upload backup file.",
    ):
        self.backup_uuid = backup_uuid
        self.attempt_no = attempt_no
        self.backup_type = backup_type
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f"{self.message or self.default_detail}"


class NodeDropboxNotEnoughStorageError(APIException):
    """Exception raised for errors in the input node.

    Attributes:
        node -- input node which caused the error
        message -- explanation of the error
    """

    email_template_id = "unable_to_upload_backup"
    default_detail = "The user's Dropbox storage quota has been exceeded."

    def __init__(
        self,
        backup_uuid=None,
        attempt_no=None,
        backup_type=None,
        message="Unable to upload backup file.",
    ):
        self.backup_uuid = backup_uuid
        self.attempt_no = attempt_no
        self.backup_type = backup_type
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return (
            f"{self.default_detail}\n  Backup UUID:{self.backup_uuid}. \n"
            f"This was attempt no:{self.attempt_no}.\n Error: {self.message}"
        )


class NodeDropboxTokenExpiredError(APIException):
    """Exception raised for errors in the input node.

    Attributes:
        node -- input node which caused the error
        message -- explanation of the error
    """

    email_template_id = "unable_to_upload_backup"
    default_detail = "The user's Dropbox token is unable to refresh or expired. Please reconnect your Dropbox account."

    def __init__(
        self,
        backup_uuid=None,
        attempt_no=None,
        backup_type=None,
        message="Unable to upload backup file.",
    ):
        self.backup_uuid = backup_uuid
        self.attempt_no = attempt_no
        self.backup_type = backup_type
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return (
            f"{self.default_detail} \n Backup UUID:{self.backup_uuid}.\n "
            f"This was attempt no:{self.attempt_no}.\n Error: {self.message}"
        )


class NodeDropboxFileIDMissingError(APIException):
    """Exception raised for errors in the input node.

    Attributes:
        node -- input node which caused the error
        message -- explanation of the error
    """

    email_template_id = "unable_to_upload_backup"
    default_detail = (
        "Dropbox did not send path or file id. "
        "Your file size may be too large or your Dropbox account may be reaching monthly usage limits."
    )

    def __init__(
        self,
        backup_uuid=None,
        attempt_no=None,
        backup_type=None,
        message="Unable to upload backup file.",
    ):
        self.backup_uuid = backup_uuid
        self.attempt_no = attempt_no
        self.backup_type = backup_type
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return (
            f"{self.default_detail} \n Backup UUID:{self.backup_uuid}. \n"
            f"This was attempt no:{self.attempt_no}. \n Error: {self.message}"
        )


class StorageFilebaseQuotaExceededError(APIException):
    email_template_id = "unable_to_upload_backup"
    default_detail = "The user's Filebase storage quota has been exceeded."

    def __init__(
        self,
        backup_uuid=None,
        attempt_no=None,
        backup_type=None,
        message="Unable to upload backup file.",
    ):
        self.backup_uuid = backup_uuid
        self.attempt_no = attempt_no
        self.backup_type = backup_type
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return (
            f"{self.default_detail} \n Backup UUID:{self.backup_uuid}. \n"
            f"This was attempt no:{self.attempt_no}.\n Error: {self.message}"
        )


class NodeAWSS3UploadFailedError(APIException):
    """Exception raised for errors in the input node.

    Attributes:
        node -- input node which caused the error
        message -- explanation of the error
    """

    email_template_id = "unable_to_upload_backup"

    def __init__(
        self,
        backup_uuid=None,
        attempt_no=None,
        backup_type=None,
        message="Unable to upload backup file.",
    ):
        self.backup_uuid = backup_uuid
        self.attempt_no = attempt_no
        self.backup_type = backup_type
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f"{self.message}  Backup UUID:{self.backup_uuid}. " f"This was attempt no:{self.attempt_no}."


class NodeWasabiUploadFailedError(APIException):
    """Exception raised for errors in the input node.

    Attributes:
        node -- input node which caused the error
        message -- explanation of the error
    """

    def __init__(
        self,
        backup_uuid=None,
        attempt_no=None,
        backup_type=None,
        message="Unable to upload backup file.",
    ):
        self.backup_uuid = backup_uuid
        self.attempt_no = attempt_no
        self.backup_type = backup_type
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f"{self.message}  Backup UUID:{self.backup_uuid}. " f"This was attempt no:{self.attempt_no}."


class NodeDoSpacesUploadFailedError(APIException):
    """Exception raised for errors in the input node.

    Attributes:
        node -- input node which caused the error
        message -- explanation of the error
    """

    def __init__(
        self,
        backup_uuid=None,
        attempt_no=None,
        backup_type=None,
        message="Unable to upload backup file.",
    ):
        self.backup_uuid = backup_uuid
        self.attempt_no = attempt_no
        self.backup_type = backup_type
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f"{self.message}  Backup UUID:{self.backup_uuid}. " f"This was attempt no:{self.attempt_no}."


class StorageBackBlazeB2UploadFailedError(APIException):
    def __init__(
        self,
        backup_uuid=None,
        attempt_no=None,
        backup_type=None,
        message="Unable to upload backup file.",
    ):
        self.backup_uuid = backup_uuid
        self.attempt_no = attempt_no
        self.backup_type = backup_type
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f"{self.message}  Backup UUID:{self.backup_uuid}. " f"This was attempt no:{self.attempt_no}."


class StorageDOSpacesUploadFailedError(APIException):
    def __init__(
        self,
        backup_uuid=None,
        attempt_no=None,
        backup_type=None,
        message="Unable to upload backup file.",
    ):
        self.backup_uuid = backup_uuid
        self.attempt_no = attempt_no
        self.backup_type = backup_type
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f"{self.message}  Backup UUID:{self.backup_uuid}. " f"This was attempt no:{self.attempt_no}."


class StorageExoScaleUploadFailedError(APIException):
    def __init__(
        self,
        backup_uuid=None,
        attempt_no=None,
        backup_type=None,
        message="Unable to upload backup file.",
    ):
        self.backup_uuid = backup_uuid
        self.attempt_no = attempt_no
        self.backup_type = backup_type
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f"{self.message}  Backup UUID:{self.backup_uuid}. " f"This was attempt no:{self.attempt_no}."


class StorageOracleUploadFailedError(APIException):
    def __init__(
        self,
        backup_uuid=None,
        attempt_no=None,
        backup_type=None,
        message="Unable to upload backup file.",
    ):
        self.backup_uuid = backup_uuid
        self.attempt_no = attempt_no
        self.backup_type = backup_type
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f"{self.message}  Backup UUID:{self.backup_uuid}. " f"This was attempt no:{self.attempt_no}."


class StorageScalewayUploadFailedError(APIException):
    def __init__(
        self,
        backup_uuid=None,
        attempt_no=None,
        backup_type=None,
        message="Unable to upload backup file.",
    ):
        self.backup_uuid = backup_uuid
        self.attempt_no = attempt_no
        self.backup_type = backup_type
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f"{self.message}  Backup UUID:{self.backup_uuid}. " f"This was attempt no:{self.attempt_no}."


class StorageIonosUploadFailedError(APIException):
    def __init__(
        self,
        backup_uuid=None,
        attempt_no=None,
        backup_type=None,
        message="Unable to upload backup file.",
    ):
        self.backup_uuid = backup_uuid
        self.attempt_no = attempt_no
        self.backup_type = backup_type
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f"{self.message}  Backup UUID:{self.backup_uuid}. " f"This was attempt no:{self.attempt_no}."


class StorageRackCorpUploadFailedError(APIException):
    def __init__(
        self,
        backup_uuid=None,
        attempt_no=None,
        backup_type=None,
        message="Unable to upload backup file.",
    ):
        self.backup_uuid = backup_uuid
        self.attempt_no = attempt_no
        self.backup_type = backup_type
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f"{self.message}  Backup UUID:{self.backup_uuid}. " f"This was attempt no:{self.attempt_no}."


class StorageIBMUploadFailedError(APIException):
    def __init__(
        self,
        backup_uuid=None,
        attempt_no=None,
        backup_type=None,
        message="Unable to upload backup file.",
    ):
        self.backup_uuid = backup_uuid
        self.attempt_no = attempt_no
        self.backup_type = backup_type
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f"{self.message}  Backup UUID:{self.backup_uuid}. " f"This was attempt no:{self.attempt_no}."


class StorageAliBabaUploadFailedError(APIException):
    def __init__(
        self,
        backup_uuid=None,
        attempt_no=None,
        backup_type=None,
        message="Unable to upload backup file.",
    ):
        self.backup_uuid = backup_uuid
        self.attempt_no = attempt_no
        self.backup_type = backup_type
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f"{self.message}  Backup UUID:{self.backup_uuid}. " f"This was attempt no:{self.attempt_no}."


class StorageTencentUploadFailedError(APIException):
    def __init__(
        self,
        backup_uuid=None,
        attempt_no=None,
        backup_type=None,
        message="Unable to upload backup file.",
    ):
        self.backup_uuid = backup_uuid
        self.attempt_no = attempt_no
        self.backup_type = backup_type
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f"{self.message}  Backup UUID:{self.backup_uuid}. " f"This was attempt no:{self.attempt_no}."


class StorageFilebaseUploadFailedError(APIException):
    def __init__(
        self,
        backup_uuid=None,
        attempt_no=None,
        backup_type=None,
        message="Unable to upload backup file.",
    ):
        self.backup_uuid = backup_uuid
        self.attempt_no = attempt_no
        self.backup_type = backup_type
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f"{self.message}  Backup UUID:{self.backup_uuid}. " f"This was attempt no:{self.attempt_no}."


class StorageLinodeUploadFailedError(APIException):
    def __init__(
        self,
        backup_uuid=None,
        attempt_no=None,
        backup_type=None,
        message="Unable to upload backup file.",
    ):
        self.backup_uuid = backup_uuid
        self.attempt_no = attempt_no
        self.backup_type = backup_type
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f"{self.message}  Backup UUID:{self.backup_uuid}. " f"This was attempt no:{self.attempt_no}."


class StorageUpCloudUploadFailedError(APIException):
    def __init__(
        self,
        backup_uuid=None,
        attempt_no=None,
        backup_type=None,
        message="Unable to upload backup file.",
    ):
        self.backup_uuid = backup_uuid
        self.attempt_no = attempt_no
        self.backup_type = backup_type
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f"{self.message}  Backup UUID:{self.backup_uuid}. " f"This was attempt no:{self.attempt_no}."


class StorageIDriveUploadFailedError(APIException):
    def __init__(
        self,
        backup_uuid=None,
        attempt_no=None,
        backup_type=None,
        message="Unable to upload backup file.",
    ):
        self.backup_uuid = backup_uuid
        self.attempt_no = attempt_no
        self.backup_type = backup_type
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f"{self.message}  Backup UUID:{self.backup_uuid}. " f"This was attempt no:{self.attempt_no}."


class StorageCloudflareUploadFailedError(APIException):
    def __init__(
        self,
        backup_uuid=None,
        attempt_no=None,
        backup_type=None,
        message="Unable to upload backup file.",
    ):
        self.backup_uuid = backup_uuid
        self.attempt_no = attempt_no
        self.backup_type = backup_type
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f"{self.message}  Backup UUID:{self.backup_uuid}. " f"This was attempt no:{self.attempt_no}."


class StorageLeviiaUploadFailedError(APIException):
    def __init__(
        self,
        backup_uuid=None,
        attempt_no=None,
        backup_type=None,
        message="Unable to upload backup file.",
    ):
        self.backup_uuid = backup_uuid
        self.attempt_no = attempt_no
        self.backup_type = backup_type
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f"{self.message}  Backup UUID:{self.backup_uuid}. " f"This was attempt no:{self.attempt_no}."


class StorageGoogleCloudUploadFailedError(APIException):
    def __init__(
        self,
        backup_uuid=None,
        attempt_no=None,
        backup_type=None,
        message="Unable to upload backup file.",
    ):
        self.backup_uuid = backup_uuid
        self.attempt_no = attempt_no
        self.backup_type = backup_type
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f"{self.message}  Backup UUID:{self.backup_uuid}. " f"This was attempt no:{self.attempt_no}."


class StorageAzureUploadFailedError(APIException):
    def __init__(
        self,
        backup_uuid=None,
        attempt_no=None,
        backup_type=None,
        message="Unable to upload backup file.",
    ):
        self.backup_uuid = backup_uuid
        self.attempt_no = attempt_no
        self.backup_type = backup_type
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f"{self.message}  Backup UUID:{self.backup_uuid}. " f"This was attempt no:{self.attempt_no}."


class StoragePCloudUploadFailedError(APIException):
    def __init__(
        self,
        backup_uuid=None,
        attempt_no=None,
        backup_type=None,
        message="Unable to upload backup file.",
    ):
        self.backup_uuid = backup_uuid
        self.attempt_no = attempt_no
        self.backup_type = backup_type
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f"{self.message}  Backup UUID:{self.backup_uuid}. " f"This was attempt no:{self.attempt_no}."


class StorageVultrUploadFailedError(APIException):
    def __init__(
        self,
        backup_uuid=None,
        attempt_no=None,
        backup_type=None,
        message="Unable to upload backup file.",
    ):
        self.backup_uuid = backup_uuid
        self.attempt_no = attempt_no
        self.backup_type = backup_type
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f"{self.message}  Backup UUID:{self.backup_uuid}. " f"This was attempt no:{self.attempt_no}."


class StorageAWSS3UploadFailedError(APIException):
    def __init__(
        self,
        backup_uuid=None,
        attempt_no=None,
        backup_type=None,
        message="Unable to upload backup file.",
    ):
        self.backup_uuid = backup_uuid
        self.attempt_no = attempt_no
        self.backup_type = backup_type
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f"{self.message}  Backup UUID:{self.backup_uuid}. " f"This was attempt no:{self.attempt_no}."


class StorageWasabiUploadFailedError(APIException):
    def __init__(
        self,
        backup_uuid=None,
        attempt_no=None,
        backup_type=None,
        message="Unable to upload backup file.",
    ):
        self.backup_uuid = backup_uuid
        self.attempt_no = attempt_no
        self.backup_type = backup_type
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f"{self.message}  Backup UUID:{self.backup_uuid}. " f"This was attempt no:{self.attempt_no}."


class NodeBackupSheepUploadFailedError(APIException):
    """Exception raised for errors in the input node.

    Attributes:
        node -- input node which caused the error
        message -- explanation of the error
    """

    def __init__(
        self,
        backup_uuid=None,
        attempt_no=None,
        backup_type=None,
        message="Unable to upload backup file.",
    ):
        self.backup_uuid = backup_uuid
        self.attempt_no = attempt_no
        self.backup_type = backup_type
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f"{self.message}  Backup UUID:{self.backup_uuid}. " f"This was attempt no:{self.attempt_no}."


class SnapshotCreateMissingParams(APIException):
    status_code = 503
    default_detail = "Looks like storage_point_ids is missing from your request. Please try again."
    default_code = "snapshot_create_missing_params"

    def __init__(
        self,
        message=None,
    ):
        if message is None:
            message = {"storage_point_ids": "You must select at-least one of the Storage Locations. Please try again."}
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f"{self.message}"


class SnapshotCreateNodeNotActive(APIException):
    status_code = 503
    default_detail = ""
    default_code = "snapshot_create_node_not_active"

    def __init__(
        self,
        message="Looks like storage_point_ids is missing from your request. Please try again.",
    ):
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f"{self.message}"


class SnapshotCreateNodeValidationFailed(APIException):
    status_code = 503
    default_detail = "Unable to validate node with the cloud provider. Please check if the node is active and in a running state before creating a snapshot."
    default_code = "snapshot_create_node_validation_failed"

    def __init__(
        self,
        message="Unable to validate node with the cloud provider. Please check if the node is active and in a running state before creating a snapshot.",
    ):
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f"{self.message}"


class DownloadMissingParams(APIException):
    status_code = 503
    default_detail = "Looks like storage_point_id is missing from your request. Please try again."
    default_code = "download_missing_params"

    def __init__(
        self,
        message="Looks like storage_point_id is missing from your request. Please try again.",
    ):
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f"{self.message}"


class DownloadStoragePointNotFound(APIException):
    status_code = 503
    default_detail = "Looks like storage_point_id is missing. Please contact support."
    default_code = "storage_point_missing"

    def __init__(
        self,
        message="Looks like storage_point_id is missing. Please contact support",
    ):
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f"{self.message}"


class AccountNotGoodStanding(APIException):
    status_code = 403
    default_detail = "Sorry, your account cannot perform this action as it is currently not in good standing."
    default_code = "account_not_in_good_standing"

    def __init__(
        self,
        message=default_detail,
    ):
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f"{self.message}"


class TransferStorageNotFound(APIException):
    status_code = 503
    default_detail = "Looks like storage_id is invalid. Please contact support."
    default_code = "storage_id__invalid"

    def __init__(
        self,
        message="Looks like storage_id is invalid. Please contact support.",
    ):
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f"{self.message}"


class DownloadStoragePointError(APIException):
    status_code = 503
    default_detail = "Unable to download file from storage point. Please contact support."
    default_code = "download_storage_point_failed"

    def __init__(
        self,
        message="",
    ):
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f"{self.message}"


class StoragePointError(APIException):
    status_code = 503
    default_detail = "Unable to find storage points. Please contact support."
    default_code = "list_storage_point_failed"

    def __init__(
        self,
        message="",
    ):
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f"{self.message}"


class SnapshotCreateError(APIException):
    status_code = 503
    default_detail = "Unable to create snapshot. Please contact support."
    default_code = "snapshot_create_failed"

    def __init__(
        self,
        message="",
    ):
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f"{self.message}"
