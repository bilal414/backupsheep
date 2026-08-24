import subprocess
import os
import json
import re
import unicodedata
from urllib.parse import urljoin, urlsplit

from django.conf import settings
from apps.api.v1.utils.http import requests
from sentry_sdk import capture_exception
from apps._tasks.integration.backup.errors import safe_backup_failure
from apps._tasks.exceptions import NodeBackupFailedError
from apps._tasks.integration.backup._archive import create_zip
from apps.api.v1.utils.api_helpers import aws_s3_upload_log_file
from apps.api.v1.utils.api_helpers import mkdir_p
from apps._tasks.helper.tasks import delete_from_disk
from apps.console.utils.models import BackupExecutionLeaseLostError, UtilBackup


BASECAMP_API_HOSTS = frozenset({"basecamp.com", "3.basecampapi.com"})
BASECAMP_DIRECT_DOWNLOAD_HOSTS = BASECAMP_API_HOSTS | {
    "storage.3.basecamp.com",
}
BASECAMP_DELIVERY_REDIRECT_DOMAINS = (
    "amazonaws.com",
    "cloudfront.net",
)
BASECAMP_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


class BasecampIngestionError(ValueError):
    """Provider data violated a bounded local-ingestion policy."""


def _bounded_limit(name, default, maximum):
    try:
        value = int(getattr(settings, name, default))
    except (TypeError, ValueError):
        value = default
    if value <= 0:
        value = default
    return min(value, maximum)


def _safe_component(value, *, fallback="unnamed", maximum=180):
    """Turn an untrusted provider label into one portable path component."""
    value = unicodedata.normalize("NFKC", str(value or ""))
    value = re.sub(r"[\\/\x00-\x1f\x7f]+", "_", value)
    value = value.replace("..", "_").replace(":", "_")
    value = re.sub(r"\s+", " ", value).strip(" .")
    if value in {"", ".", ".."}:
        value = fallback
    if len(value) > maximum:
        stem, extension = os.path.splitext(value)
        extension = extension[:20]
        value = stem[: max(1, maximum - len(extension))] + extension
    return value


def _safe_join(root, *components):
    root = os.path.realpath(root)
    safe_components = []
    for component in components:
        component = str(component)
        if (
            not component
            or component in {".", ".."}
            or os.path.isabs(component)
            or "/" in component
            or "\\" in component
            or "\x00" in component
        ):
            raise BasecampIngestionError("Basecamp supplied an unsafe local path")
        safe_components.append(component)
    target = os.path.realpath(os.path.join(root, *safe_components))
    try:
        confined = os.path.commonpath((root, target)) == root
    except ValueError:
        confined = False
    if not confined:
        raise BasecampIngestionError("Basecamp supplied an unsafe local path")
    return target


def _host_in_domain(hostname, domain):
    return hostname == domain or hostname.endswith(f".{domain}")


def _is_basecamp_asset_host(hostname):
    # Basecamp 2 publishes private attachment URLs on asset1.basecamp.com,
    # asset2.basecamp.com, and similarly numbered first-party origins.
    return re.fullmatch(r"asset[0-9]+\.basecamp\.com", hostname) is not None


def _validated_remote_url(value, *, api_only=False, allow_delivery_redirect=False):
    if not isinstance(value, str) or not value:
        raise BasecampIngestionError("Basecamp supplied an invalid remote URL")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise BasecampIngestionError("Basecamp supplied an invalid remote URL") from error
    hostname = (parsed.hostname or "").lower().rstrip(".")
    if (
        parsed.scheme.lower() != "https"
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or port not in (None, 443)
        or parsed.fragment
    ):
        raise BasecampIngestionError("Basecamp supplied an invalid remote URL")
    if api_only:
        allowed = hostname in BASECAMP_API_HOSTS
    else:
        allowed = (
            hostname in BASECAMP_DIRECT_DOWNLOAD_HOSTS
            or _is_basecamp_asset_host(hostname)
            or (
                allow_delivery_redirect
                and any(
                    _host_in_domain(hostname, domain)
                    for domain in BASECAMP_DELIVERY_REDIRECT_DOMAINS
                )
            )
        )
    if not allowed:
        raise BasecampIngestionError("Basecamp supplied an untrusted remote host")
    return value, hostname


def _close_response(response):
    close = getattr(response, "close", None)
    if callable(close):
        close()


def _basecamp_api_request(method, url, client, **kwargs):
    """Call only exact Basecamp API hosts and never follow an auth redirect."""
    url, _hostname = _validated_remote_url(url, api_only=True)
    kwargs.setdefault("stream", True)
    response = requests.request(
        method,
        url,
        headers=dict(client or {}),
        allow_redirects=False,
        **kwargs,
    )
    if response.status_code in BASECAMP_REDIRECT_STATUSES:
        _close_response(response)
        raise BasecampIngestionError("Basecamp API unexpectedly redirected")
    return response


def _download_response(url, client):
    """Follow a small HTTPS allowlisted chain, recalculating headers per hop."""
    current_url, _hostname = _validated_remote_url(url)
    seen = set()
    credentials_allowed = True
    max_redirects = _bounded_limit("BASECAMP_BACKUP_MAX_REDIRECTS", 5, 20)
    for hop in range(max_redirects + 1):
        if current_url in seen:
            raise BasecampIngestionError("Basecamp download redirect cycle detected")
        seen.add(current_url)
        current_url, hostname = _validated_remote_url(
            current_url,
            allow_delivery_redirect=hop > 0,
        )
        # OAuth credentials are sent only to exact API origins and Basecamp 2's
        # documented numbered asset origins. Storage/CDN hops receive no
        # inherited Authorization/header bundle.
        authenticated_host = (
            hostname in BASECAMP_API_HOSTS or _is_basecamp_asset_host(hostname)
        )
        headers = (
            dict(client or {})
            if credentials_allowed and authenticated_host
            else {}
        )
        if not authenticated_host:
            # Match browser/requests redirect behavior: once a chain leaves a
            # credentialed origin, never reattach OAuth headers later.
            credentials_allowed = False
        response = requests.request(
            "GET",
            current_url,
            headers=headers,
            allow_redirects=False,
            stream=True,
        )
        if response.status_code not in BASECAMP_REDIRECT_STATUSES:
            return response
        location = response.headers.get("Location")
        _close_response(response)
        if not location:
            raise BasecampIngestionError("Basecamp download redirect was incomplete")
        current_url, _hostname = _validated_remote_url(
            urljoin(current_url, location),
            allow_delivery_redirect=True,
        )
    raise BasecampIngestionError("Basecamp download exceeded the redirect limit")


def _response_json(response):
    max_bytes = _bounded_limit(
        "BASECAMP_BACKUP_MAX_METADATA_BYTES",
        16 * 1024 ** 2,
        256 * 1024 ** 2,
    )
    declared_length = response.headers.get("Content-Length")
    if declared_length is not None:
        try:
            declared_length = int(declared_length)
        except (TypeError, ValueError) as error:
            raise BasecampIngestionError(
                "Basecamp returned an invalid metadata content length"
            ) from error
        if declared_length < 0 or declared_length > max_bytes:
            raise BasecampIngestionError("Basecamp metadata exceeded the size limit")

    body = bytearray()
    for chunk in response.iter_content(chunk_size=1024 * 1024):
        if not chunk:
            continue
        if not isinstance(chunk, (bytes, bytearray)):
            raise BasecampIngestionError("Basecamp returned invalid metadata")
        body.extend(chunk)
        if len(body) > max_bytes:
            raise BasecampIngestionError("Basecamp metadata exceeded the size limit")
    try:
        return json.loads(body)
    except (TypeError, ValueError, UnicodeDecodeError) as error:
        raise BasecampIngestionError("Basecamp returned invalid JSON") from error


def _response_json_list(response):
    try:
        data = _response_json(response)
    except BasecampIngestionError:
        raise
    except Exception as error:
        raise BasecampIngestionError("Basecamp returned invalid JSON") from error
    if not isinstance(data, list):
        raise BasecampIngestionError("Basecamp returned an invalid collection")
    return data


def _next_link(link_header):
    if not isinstance(link_header, str) or not link_header.strip():
        return None
    matches = re.findall(r"<([^<>]+)>\s*(?:;\s*rel=\"?([^\",; ]+)\"?)?", link_header)
    for url, relation in matches:
        if relation.lower() == "next":
            return url
    if len(matches) == 1 and not matches[0][1]:
        return matches[0][0]
    return None


def _iter_numbered_pages(url, client):
    url, _hostname = _validated_remote_url(url, api_only=True)
    max_pages = _bounded_limit("BASECAMP_BACKUP_MAX_PAGES", 1000, 10000)
    max_items = _bounded_limit("BASECAMP_BACKUP_MAX_FILES", 100000, 1000000)
    item_count = 0
    for page in range(1, max_pages + 1):
        response = _basecamp_api_request("GET", url, client, params={"page": page})
        try:
            if response.status_code != 200:
                raise BasecampIngestionError("Basecamp attachment listing failed")
            items = _response_json_list(response)
        finally:
            _close_response(response)
        if not items:
            return
        item_count += len(items)
        if item_count > max_items:
            raise BasecampIngestionError("Basecamp attachment count exceeded the limit")
        yield from items
    raise BasecampIngestionError("Basecamp pagination exceeded the page limit")


def _iter_linked_pages(url, client):
    current_url, _hostname = _validated_remote_url(url, api_only=True)
    max_pages = _bounded_limit("BASECAMP_BACKUP_MAX_PAGES", 1000, 10000)
    max_items = _bounded_limit("BASECAMP_BACKUP_MAX_FILES", 100000, 1000000)
    seen = set()
    item_count = 0
    for _page in range(max_pages):
        if current_url in seen:
            raise BasecampIngestionError("Basecamp pagination cycle detected")
        seen.add(current_url)
        response = _basecamp_api_request("GET", current_url, client)
        try:
            if response.status_code != 200:
                raise BasecampIngestionError("Basecamp upload listing failed")
            items = _response_json_list(response)
            next_url = _next_link(response.headers.get("Link"))
        finally:
            _close_response(response)
        item_count += len(items)
        if item_count > max_items:
            raise BasecampIngestionError("Basecamp upload count exceeded the limit")
        yield from items
        if not next_url:
            return
        current_url, _hostname = _validated_remote_url(
            urljoin(current_url, next_url), api_only=True
        )
    raise BasecampIngestionError("Basecamp pagination exceeded the page limit")


class _DownloadBudget:
    def __init__(self):
        self.max_files = _bounded_limit("BASECAMP_BACKUP_MAX_FILES", 100000, 1000000)
        self.max_file_bytes = _bounded_limit(
            "BASECAMP_BACKUP_MAX_FILE_BYTES", 5 * 1024 ** 3, 5 * 1024 ** 4
        )
        self.max_total_bytes = _bounded_limit(
            "BASECAMP_BACKUP_MAX_TOTAL_BYTES", 100 * 1024 ** 3, 10 * 1024 ** 4
        )
        self.files = 0
        self.total_bytes = 0
        self.current_file_bytes = 0

    def start_file(self, declared_length=None):
        if self.files >= self.max_files:
            raise BasecampIngestionError("Basecamp attachment count exceeded the limit")
        if declared_length is not None:
            try:
                declared_length = int(declared_length)
            except (TypeError, ValueError) as error:
                raise BasecampIngestionError("Basecamp returned an invalid content length") from error
            if declared_length < 0:
                raise BasecampIngestionError("Basecamp returned an invalid content length")
            if declared_length > self.max_file_bytes:
                raise BasecampIngestionError("Basecamp attachment exceeded the file-size limit")
            if self.total_bytes + declared_length > self.max_total_bytes:
                raise BasecampIngestionError("Basecamp backup exceeded the total-size limit")
        self.files += 1
        self.current_file_bytes = 0
        return declared_length

    def consume(self, length):
        self.current_file_bytes += length
        self.total_bytes += length
        if self.current_file_bytes > self.max_file_bytes:
            raise BasecampIngestionError("Basecamp attachment exceeded the file-size limit")
        if self.total_bytes > self.max_total_bytes:
            raise BasecampIngestionError("Basecamp backup exceeded the total-size limit")


def _unique_destination(directory, raw_name, root):
    name = _safe_component(raw_name, fallback="attachment")
    stem, extension = os.path.splitext(name)
    for counter in range(10000):
        candidate = name if counter == 0 else f"{stem}-{counter}{extension}"
        destination = _safe_join(directory, candidate)
        try:
            confined = (
                os.path.commonpath((os.path.realpath(root), destination))
                == os.path.realpath(root)
            )
        except ValueError:
            confined = False
        if not confined:
            raise BasecampIngestionError("Basecamp supplied an unsafe local path")
        if not os.path.lexists(destination) and not os.path.lexists(f"{destination}.partial"):
            return destination
    raise BasecampIngestionError("Basecamp supplied too many duplicate filenames")


def _download_to_file(url, destination, root, client, budget):
    root = os.path.realpath(root)
    destination = os.path.realpath(destination)
    try:
        confined = os.path.commonpath((root, destination)) == root
    except ValueError:
        confined = False
    if not confined:
        raise BasecampIngestionError("Basecamp supplied an unsafe local path")
    response = _download_response(url, client)
    partial = f"{destination}.partial"
    try:
        if response.status_code != 200:
            raise BasecampIngestionError("Basecamp attachment download failed")
        declared_length = budget.start_file(response.headers.get("Content-Length"))
        content_encoding = str(response.headers.get("Content-Encoding") or "").lower()
        os.makedirs(os.path.dirname(destination), exist_ok=True)
        descriptor = os.open(
            partial,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        try:
            with os.fdopen(descriptor, "wb") as output:
                for chunk in response.iter_content(chunk_size=1024 * 1024):
                    if not chunk:
                        continue
                    if not isinstance(chunk, (bytes, bytearray)):
                        raise BasecampIngestionError("Basecamp returned an invalid download chunk")
                    budget.consume(len(chunk))
                    output.write(chunk)
                if (
                    declared_length is not None
                    and content_encoding in {"", "identity"}
                    and budget.current_file_bytes != declared_length
                ):
                    raise BasecampIngestionError("Basecamp download length did not match")
        except Exception:
            if os.path.lexists(partial):
                os.unlink(partial)
            raise
        os.replace(partial, destination)
    finally:
        _close_response(response)
        if os.path.lexists(partial):
            os.unlink(partial)
    return destination


def collect_vaults_urls(item, path, client, _state=None, _depth=0, _path_parts=None):
    max_depth = _bounded_limit("BASECAMP_BACKUP_MAX_VAULT_DEPTH", 24, 100)
    max_vaults = _bounded_limit("BASECAMP_BACKUP_MAX_VAULTS", 10000, 100000)
    if _depth > max_depth:
        raise BasecampIngestionError("Basecamp vault nesting exceeded the depth limit")
    if not isinstance(item, dict):
        raise BasecampIngestionError("Basecamp returned an invalid vault")
    state = _state or {"seen": set(), "count": 0}
    vaults_url, _hostname = _validated_remote_url(item.get("vaults_url"), api_only=True)
    uploads_url, _hostname = _validated_remote_url(item.get("uploads_url"), api_only=True)
    item_url, _hostname = _validated_remote_url(item.get("url"), api_only=True)
    identity = (item_url, vaults_url)
    if identity in state["seen"]:
        raise BasecampIngestionError("Basecamp vault cycle detected")
    state["seen"].add(identity)
    state["count"] += 1
    if state["count"] > max_vaults:
        raise BasecampIngestionError("Basecamp vault count exceeded the limit")

    if _path_parts is None:
        _path_parts = tuple(
            _safe_component(part, fallback="vault")
            for part in str(path or "").split("/")
            if part
        )
    title = _safe_component(item.get("title"), fallback="vault")
    path_parts = tuple(_path_parts) + (title,)

    response = _basecamp_api_request("GET", vaults_url, client, params={})
    try:
        if response.status_code != 200:
            raise BasecampIngestionError("Basecamp vault listing failed")
        nested_vaults = _response_json_list(response)
    finally:
        _close_response(response)
    nested_urls = []
    for nested_vault in nested_vaults:
        nested_urls.extend(
            collect_vaults_urls(
                nested_vault,
                "",
                client,
                _state=state,
                _depth=_depth + 1,
                _path_parts=path_parts,
            )
        )
    return [
        {
            "title": title,
            "path": "/" + "/".join(path_parts),
            "path_parts": path_parts,
            "uploads_count": item.get("uploads_count", 0),
            "uploads_url": uploads_url,
            "url": item_url,
            "nested_vaults": nested_urls,
        }
    ]


def flatten_vaults_urls(nested_vaults_urls):
    max_depth = _bounded_limit("BASECAMP_BACKUP_MAX_VAULT_DEPTH", 24, 100)
    max_vaults = _bounded_limit("BASECAMP_BACKUP_MAX_VAULTS", 10000, 100000)
    if not isinstance(nested_vaults_urls, list):
        raise BasecampIngestionError("Basecamp returned an invalid vault tree")
    flat_urls = []
    seen = set()
    stack = [(item, 0) for item in reversed(nested_vaults_urls)]
    while stack:
        item, depth = stack.pop()
        if depth > max_depth:
            raise BasecampIngestionError("Basecamp vault nesting exceeded the depth limit")
        if not isinstance(item, dict) or id(item) in seen:
            raise BasecampIngestionError("Basecamp vault cycle detected")
        seen.add(id(item))
        flat_urls.append(
            {
                "title": item["title"],
                "path": item["path"],
                "path_parts": tuple(item.get("path_parts") or ()),
                "uploads_count": item["uploads_count"],
                "uploads_url": item["uploads_url"],
                "url": item["url"],
            }
        )
        if len(flat_urls) > max_vaults:
            raise BasecampIngestionError("Basecamp vault count exceeded the limit")
        nested = item.get("nested_vaults", [])
        if not isinstance(nested, list):
            raise BasecampIngestionError("Basecamp returned an invalid vault tree")
        stack.extend((child, depth + 1) for child in reversed(nested))
    return flat_urls


def _provider_identifier(value):
    value = str(value or "")
    if not re.fullmatch(r"[0-9]{1,32}", value):
        raise BasecampIngestionError("Basecamp returned an invalid identifier")
    return value


def _response_json_object(response):
    try:
        data = _response_json(response)
    except BasecampIngestionError:
        raise
    except Exception as error:
        raise BasecampIngestionError("Basecamp returned invalid JSON") from error
    if not isinstance(data, dict):
        raise BasecampIngestionError("Basecamp returned an invalid object")
    return data


def snapshot_basecamp(backup):
    node = backup.basecamp.node
    encryption_key = node.connection.account.get_encryption_key()
    account = node.connection.account

    backup.status = UtilBackup.Status.DOWNLOAD_IN_PROGRESS
    backup.save()

    working_dir = f"."
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
    tree_log_path = f"_storage/{backup.uuid}-dir-tree.log"

    try:
        """
        Checking for connection
        """
        node.connection.auth_basecamp.validate()

        """
        Trigger Backup in Basecamp
        """
        client = node.connection.auth_basecamp.get_client()
        projects = node.basecamp.projects
        max_projects = _bounded_limit("BASECAMP_BACKUP_MAX_PROJECTS", 10000, 100000)
        if not isinstance(projects, list) or len(projects) > max_projects:
            raise BasecampIngestionError("Basecamp project count exceeded the limit")
        download_budget = _DownloadBudget()

        for project in projects:
            if not isinstance(project, dict):
                raise BasecampIngestionError("Basecamp returned an invalid project")
            account_id = _provider_identifier(project.get("account_id"))
            project_id = _provider_identifier(project.get("id"))
            account_product = project.get("account_product")

            # Basecamp 2
            if account_product == "bcx":
                basecamp_api = f"https://basecamp.com/{account_id}/api/v1"

                # Get Project details
                response = _basecamp_api_request(
                    "GET", f"{basecamp_api}/projects/{project_id}.json", client, data={}
                )
                try:
                    if response.status_code != 200:
                        raise BasecampIngestionError("Basecamp project request failed")
                    project_json = _response_json_object(response)
                finally:
                    _close_response(response)

                project_name = _safe_component(
                    f"{project_json.get('name') or 'project'}-{account_id}-{project_id}",
                    fallback=f"project-{account_id}-{project_id}",
                )
                project_dir = _safe_join(local_dir, project_name)
                os.makedirs(project_dir, exist_ok=True)

                attachments = project_json.get("attachments")
                if not isinstance(attachments, dict):
                    raise BasecampIngestionError("Basecamp returned an invalid attachment listing")
                for attachment in _iter_numbered_pages(attachments.get("url"), client):
                    if not isinstance(attachment, dict):
                        raise BasecampIngestionError("Basecamp returned an invalid attachment")
                    destination = _unique_destination(
                        project_dir,
                        attachment.get("name"),
                        local_dir,
                    )
                    _download_to_file(
                        attachment.get("url"),
                        destination,
                        local_dir,
                        client,
                        download_budget,
                    )
            # Basecamp 3 or 4
            elif account_product == "bc3":
                basecamp_api = f"https://3.basecampapi.com/{account_id}"

                # Get Project details
                response = _basecamp_api_request(
                    "GET", f"{basecamp_api}/projects/{project_id}.json", client, data={}
                )
                try:
                    if response.status_code != 200:
                        raise BasecampIngestionError("Basecamp project request failed")
                    project_json = _response_json_object(response)
                finally:
                    _close_response(response)

                project_name = _safe_component(
                    f"{project_json.get('name') or 'project'}-{account_id}-{project_id}",
                    fallback=f"project-{account_id}-{project_id}",
                )
                project_dir = _safe_join(local_dir, project_name)
                os.makedirs(project_dir, exist_ok=True)
                docks = project_json.get("dock")
                if not isinstance(docks, list) or len(docks) > _bounded_limit(
                    "BASECAMP_BACKUP_MAX_VAULTS", 10000, 100000
                ):
                    raise BasecampIngestionError("Basecamp returned an invalid dock listing")

                list_of_vaults = []
                vault_state = {"seen": set(), "count": 0}
                for dock in docks:
                    if not isinstance(dock, dict):
                        raise BasecampIngestionError("Basecamp returned an invalid dock")
                    if dock.get("name") == "vault" and dock.get("enabled") is True:
                        response = _basecamp_api_request(
                            "GET", dock.get("url"), client, params={}
                        )
                        try:
                            if response.status_code != 200:
                                raise BasecampIngestionError("Basecamp vault request failed")
                            vault_payload = _response_json(response)
                        except BasecampIngestionError:
                            raise
                        except Exception as error:
                            raise BasecampIngestionError("Basecamp returned invalid JSON") from error
                        finally:
                            _close_response(response)
                        roots = vault_payload if isinstance(vault_payload, list) else [vault_payload]
                        for vault_root in roots:
                            list_of_vaults.extend(
                                flatten_vaults_urls(
                                    collect_vaults_urls(
                                        vault_root,
                                        "",
                                        client,
                                        _state=vault_state,
                                    )
                                )
                            )

                for vault in list_of_vaults:
                    path_parts = tuple(vault.get("path_parts") or ())
                    if not path_parts:
                        raise BasecampIngestionError("Basecamp returned an invalid vault path")
                    vault_dir = _safe_join(project_dir, *path_parts)
                    os.makedirs(vault_dir, exist_ok=True)
                    for upload_item in _iter_linked_pages(vault["uploads_url"], client):
                        if not isinstance(upload_item, dict):
                            raise BasecampIngestionError("Basecamp returned an invalid upload")
                        destination = _unique_destination(
                            vault_dir,
                            upload_item.get("filename"),
                            local_dir,
                        )
                        _download_to_file(
                            upload_item.get("download_url"),
                            destination,
                            local_dir,
                            client,
                            download_budget,
                        )
            else:
                raise BasecampIngestionError("Basecamp returned an unsupported account product")

        # ZIP all downloaded files.
        create_zip(
            local_dir,
            local_zip,
            timeout=43200,
            before_publish=backup.ensure_execution_fence,
        )

        # Generate Report
        try:
            subprocess.run(
                [
                    "tree", "-a", "-f", "-h", "-F", "-v", "-i", "-N", "-n",
                    "-o", tree_log_path,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=900,
                cwd=local_dir,
            )
            log_file.write(f"---Directory Tree--- \n")

            # open both files
            with open(tree_log_path, "r", errors="ignore") as tree_log_file:
                for line in tree_log_file:
                    log_file.write(f"{line} \n")
            os.remove(tree_log_path)
        except Exception as e:
            capture_exception(e)

        backup.size = os.stat(local_zip).st_size
        backup.status = UtilBackup.Status.DOWNLOAD_COMPLETE
        backup.save()
        log_file.write(f"Size (compressed): {backup.size_display()} \n")

        """
        Delete directory because no need for it now that we have zip
        """
        delete_from_disk.apply_async(
            args=[backup.uuid_str, "dir"],
        )
    except BackupExecutionLeaseLostError:
        raise
    except Exception as e:
        capture_exception(e)
        failure = safe_backup_failure(e, stage="basecamp_backup")
        log_file.write(f"Error [{failure.code}]: {failure.detail}\n")
        """
        Delete files
        """
        delete_from_disk.apply_async(
            args=[backup.uuid_str, "both"],
        )
        raise NodeBackupFailedError(
            node, backup.uuid_str, backup.attempt_no, backup.type, failure.detail
        )
    finally:
        """
        Upload log file and report file to BackupSheep storage.
        """
        log_file.close()

        # Upload first part of file here. Second will be pushed when files are uploaded.
        if os.path.exists(log_file_path):
            aws_s3_upload_log_file(log_file_path, f"{backup.uuid}.log")
