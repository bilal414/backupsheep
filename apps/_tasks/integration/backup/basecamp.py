import subprocess
import os
import requests
from sentry_sdk import capture_exception
from apps._tasks.exceptions import NodeBackupFailedError
from apps.api.v1.utils.api_helpers import aws_s3_upload_log_file
from apps.api.v1.utils.api_helpers import mkdir_p
from apps._tasks.helper.tasks import delete_from_disk
from apps.console.utils.models import UtilBackup


def collect_vaults_urls(item, path, client):
    urls = []

    path += f"/{item['title']}"

    response = requests.request("GET", item["vaults_url"], headers=client, params={})
    nested_vaults = response.json()
    nested_vaults_urls = []

    for nested_vault in nested_vaults:
        nested_vaults_urls.extend(collect_vaults_urls(nested_vault, path, client))

    urls.append(
        {
            "title": item["title"],
            "path": path,
            "uploads_count": item["uploads_count"],
            "uploads_url": item["uploads_url"],
            "url": item["url"],
            "nested_vaults": nested_vaults_urls,
        }
    )

    return urls


def flatten_vaults_urls(nested_vaults_urls):
    flat_urls = []

    for item in nested_vaults_urls:
        flat_urls.append(
            {
                "title": item["title"],
                "path": item["path"],
                "uploads_count": item["uploads_count"],
                "uploads_url": item["uploads_url"],
                "url": item["url"],
            }
        )
        flat_urls.extend(flatten_vaults_urls(item["nested_vaults"]))

    return flat_urls


def snapshot_basecamp(backup):
    node = backup.basecamp.node
    encryption_key = node.connection.account.get_encryption_key()
    account = node.connection.account

    backup.status = UtilBackup.Status.DOWNLOAD_IN_PROGRESS
    backup.save()

    working_dir = f"/home/ubuntu/backupsheep"
    local_dir = f"_storage/{backup.uuid}/"
    local_zip = f"_storage/{backup.uuid}.zip"
    mkdir_p(local_dir)

    # Backup Log
    log_file_path = f"{working_dir}/_storage/{backup.uuid}.log"
    log_file = open(log_file_path, "a+")
    log_file.write(f"Node:{node.name}\n")
    log_file.write(f"UUID: {backup.uuid} \n")
    log_file.write(f"Time: {backup.created} \n")
    log_file.write(f"Attempt Number: {backup.attempt_no} \n")
    tree_log_path = f"/home/ubuntu/backupsheep/_storage/{backup.uuid}-dir-tree.log"

    try:
        """
        Checking for connection
        """
        node.connection.auth_basecamp.validate()

        """
        Trigger Backup in Basecamp
        """
        client = node.connection.auth_basecamp.get_client()

        for project in node.basecamp.projects:
            basecamp_api = None

            # Basecamp 2
            if project["account_product"] == "bcx":
                basecamp_api = f"https://basecamp.com/{project['account_id']}/api/v1"

                # Get Project details
                response = requests.request(
                    "GET", f"{basecamp_api}/projects/{project['id']}.json", headers=client, data={}
                )

                if response.status_code == 200:
                    project_json = response.json()

                    project_name = (
                        project_json["name"].encode("utf-8", errors="ignore").decode("utf-8")
                    ).replace("/", "-")

                    project_dir = f"{local_dir}{project_name}/"
                    mkdir_p(project_dir)

                    # Get list of attachments for this project
                    page = 1
                    has_more_data = True

                    # Download until page has 0 attachments. Each page has around 50 items by default.
                    while has_more_data:
                        response = requests.request(
                            "GET", project_json["attachments"]["url"], headers=client, params={"page": page}
                        )

                        if response.status_code == 200:
                            attachments_json = response.json()

                            # Only proceed is there's attachment object
                            if len(attachments_json) > 0:
                                # Download all files in this list
                                for attachment in attachments_json:
                                    response = requests.request(
                                        "GET", attachment["url"], headers=client, allow_redirects=True, stream=True
                                    )

                                    if response.status_code == 200:
                                        # save attachment to file.
                                        attachment_name = (
                                            attachment["name"].encode("utf-8", errors="ignore").decode("utf-8")
                                        ).replace("/", "-")

                                        with open(f"{project_dir}{attachment_name}", "wb") as b_file:
                                            for chunk in response.iter_content(chunk_size=1024):
                                                if chunk:
                                                    b_file.write(chunk)
                                    else:
                                        log_file.write(f"Unable to download file: {attachment_name} \n")
                                # Go to the next page
                                page += 1
                            else:
                                has_more_data = False
                        else:
                            print(f"Bad response from Basecamp API while getting list of attachments.")
                            has_more_data = False
            # Basecamp 3 or 4
            elif project["account_product"] == "bc3":
                basecamp_api = f"https://3.basecampapi.com/{project['account_id']}"

                # Get Project details
                response = requests.request(
                    "GET", f"{basecamp_api}/projects/{project['id']}.json", headers=client, data={}
                )

                if response.status_code == 200:
                    project_json = response.json()

                    project_name = (
                        project_json["name"].encode("utf-8", errors="ignore").decode("utf-8")
                    ).replace("/", "-")

                    project_dir = f"{local_dir}{project_name}"
                    mkdir_p(project_dir, add_bs_file=False)

                    list_of_vaults = []

                    for dock in project_json["dock"]:
                        if dock["name"] == "vault" and dock["enabled"] == True:
                            vault_url = dock["url"]

                            response = requests.request("GET", vault_url, headers=client, params={})

                            if response.status_code == 200:
                                vault_json = response.json()
                                list_of_vaults.extend(flatten_vaults_urls(collect_vaults_urls(vault_json, "", client)))

                    for vault in list_of_vaults:
                        has_more_uploads = True
                        uploads_url = vault["uploads_url"]

                        while has_more_uploads:
                            # now fetch all uploads in this vault
                            response = requests.request("GET", uploads_url, headers=client)

                            if response.status_code == 200:
                                # Now checking for next page.
                                next_page_link = response.headers.get("Link")

                                # If Link value is empty then we don't have more pages of uploads.
                                if next_page_link is None or next_page_link == "":
                                    has_more_uploads = False
                                else:
                                    # Set the new value for uploads_url - for next run
                                    uploads_url = next_page_link[
                                                  next_page_link.find("<") + 1: next_page_link.find(">")]

                                # Now lets process uploads
                                uploads_json = response.json()

                                # Download all uploads.
                                for upload_item in uploads_json:
                                    response = requests.request(
                                        "GET", upload_item["download_url"], headers=client, allow_redirects=True, stream=True
                                    )

                                    if response.status_code == 200:
                                        # save upload file.
                                        upload_name = (upload_item["filename"].encode("utf-8", errors="ignore").decode("utf-8")).replace("/", "-")
                                        mkdir_p(f"{project_dir}{vault['path']}", add_bs_file=False)
                                        with open(f"{project_dir}{vault['path']}/{upload_name}", "wb") as b_file:
                                            for chunk in response.iter_content(chunk_size=1024):
                                                if chunk:
                                                    b_file.write(chunk)
                                        print(f"saved attachment {upload_item['id']}")
                                    else:
                                        log_file.write(f"Unable to download file: {upload_name} \n")

        # Update Permissions
        execstr = f"sudo chown ubuntu:ubuntu ../{backup.uuid_str} -R"
        subprocess.run(
            execstr,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=43200,
            shell=True,
            cwd=local_dir,
        )

        # ZIP all downloaded files.
        execstr = f"/usr/bin/zip -y -r ../{backup.uuid_str} . -i \*"
        subprocess.run(
            execstr,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=43200,
            shell=True,
            cwd=local_dir,
        )

        # Generate Report
        try:
            execstr = f"sudo tree -a -f -h -F -v -i -N -n -o {tree_log_path}"

            subprocess.run(
                execstr, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, timeout=900, cwd=local_dir
            )
            log_file.write(f"---Directory Tree--- \n")

            # open both files
            with open(tree_log_path, "r", errors="ignore") as tree_log_file:
                for line in tree_log_file:
                    log_file.write(f"{line} \n")
            os.remove(tree_log_path)
        except Exception as e:
            capture_exception(e)

        if os.path.exists(local_zip):
            backup.size = os.stat(local_zip).st_size
            backup.status = UtilBackup.Status.DOWNLOAD_COMPLETE
            backup.save()
            log_file.write(f"Size (compressed): {backup.size_display()} \n")

        """
        Delete directory because no need for it now that we have zip
        """
        queue = f"delete_from_disk__{node.connection.location.queue}"
        delete_from_disk.apply_async(
            args=[backup.uuid_str, "dir"],
            queue=queue,
        )
    except Exception as e:
        log_file.write(f"Error: {e.__str__()} \n")
        capture_exception(e)
        """
        Delete files
        """
        queue = f"delete_from_disk__{node.connection.location.queue}"
        delete_from_disk.apply_async(
            args=[backup.uuid_str, "both"],
            queue=queue,
        )
        raise NodeBackupFailedError(node, backup.uuid_str, backup.attempt_no, backup.type, e.__str__())
    finally:
        """
        Upload log file and report file to BackupSheep storage.
        """
        log_file.close()

        # Upload first part of file here. Second will be pushed when files are uploaded.
        if os.path.exists(log_file_path):
            aws_s3_upload_log_file(log_file_path, f"{backup.uuid}.log")
