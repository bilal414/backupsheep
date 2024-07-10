from __future__ import print_function
import random
from cryptography.fernet import Fernet
from django.contrib.sessions.middleware import SessionMiddleware
from random import choice
from string import ascii_lowercase, digits
from ....models import *
import socket
import os
from stat import S_ISDIR, ST_SIZE, S_ISLNK, S_ISREG
import errno
import re
from pytz import timezone as pytz_timezone
import pytz
import json
import boto3
import urllib
import urllib.parse
import ftplib
import ssl
from urllib3.poolmanager import PoolManager
from requests.adapters import HTTPAdapter
import hashlib
import hmac
import base64
from google.cloud import storage as gc_storage
from google.oauth2 import service_account


def validate_crontab(cron_syntax, data=None):
    cron_list = cron_syntax.split()
    if len(cron_list) != 5:
        return "Syntax error in cron"

    validate_crontab_regex = re.compile(
        "{0}\s+{1}\s+{2}\s+{3}\s+{4}".format(
            "(?P<minutes>([0-5]?\d)\-([0-5]?\d)|(\*|[0-5]?\d)\/(60|[0-5]?\d)|(([0-5]?\d)\,){0,}([0-5]?\d)|\*)",
            "(?P<hours>(2[0-3]|[01]?\d)\-(2[0-3]|[01]?\d)|(2[0-3]|[01]?\d|\*)\/(2[0-3]|[01]?\d)|((2[0-3]|[01]?\d)\,){0,}(2[0-3]|[01]?\d)|\*)",
            "(?P<days>(3[01]|[12]\d|0?[1-9])\-(3[01]|[12]\d|0?[1-9])|(\*|3[01]|[12]\d|0?[1-9])\/(3[01]|[12]\d|0?[1-9])|((3[01]|[12]\d|0?[1-9])\,){0,}(3[01]|[12]\d|0?[1-9])|\*)",
            "(?P<months>((?i)jan|(?i)feb|(?i)mar|(?i)apr|(?i)may|(?i)jun|(?i)jul|(?i)aug|(?i)sep|(?i)oct|(?i)nov|(?i)dec|1[012]|0?[1-9])\-((?i)jan|(?i)feb|(?i)mar|(?i)apr|(?i)may|(?i)jun|(?i)jul|(?i)aug|(?i)sep|(?i)oct|(?i)nov|(?i)dec|1[012]|0?[1-9])|((?i)jan|(?i)feb|(?i)mar|(?i)apr|(?i)may|(?i)jun|(?i)jul|(?i)aug|(?i)sep|(?i)oct|(?i)nov|(?i)dec|\*|1[012]|0?[1-9])\/((?i)jan|(?i)feb|(?i)mar|(?i)apr|(?i)may|(?i)jun|(?i)jul|(?i)aug|(?i)sep|(?i)oct|(?i)nov|(?i)dec|1[012]|0?[1-9])|(((?i)jan|(?i)feb|(?i)mar|(?i)apr|(?i)may|(?i)jun|(?i)jul|(?i)aug|(?i)sep|(?i)oct|(?i)nov|(?i)dec|1[012]|0?[1-9])\,){0,}((?i)jan|(?i)feb|(?i)mar|(?i)apr|(?i)may|(?i)jun|(?i)jul|(?i)aug|(?i)sep|(?i)oct|(?i)nov|(?i)dec|1[012]|0?[1-9])|\*|(?i)jan|(?i)feb|(?i)mar|(?i)apr|(?i)may|(?i)jun|(?i)jul|(?i)aug|(?i)sep|(?i)oct|(?i)nov|(?i)dec)",
            "(?P<weekdays>(((?i)sun|(?i)mon|(?i)tue|(?i)wed|(?i)fri|(?i)sat|[0-6])\-((?i)sun|(?i)mon|(?i)tue|(?i)wed|(?i)fri|(?i)sat|[0-6]))|(((?i)sun|(?i)mon|(?i)tue|(?i)wed|(?i)fri|(?i)sat|\*|[0-6])\/((?i)sun|(?i)mon|(?i)tue|(?i)wed|(?i)fri|(?i)sat|[0-6]))|(((?i)sun|(?i)mon|(?i)tue|(?i)wed|(?i)fri|(?i)sat|[0-6])\,){0,}((?i)sun|(?i)mon|(?i)tue|(?i)wed|(?i)fri|(?i)sat|[0-6])|\*|(?i)sun|(?i)mon|(?i)tue|(?i)wed|(?i)fri|(?i)sat)",
        )
    )
    try:
        crontab = validate_crontab_regex.match(cron_syntax).groupdict()

        if cron_list[4] != crontab["weekdays"]:
            return False
        elif cron_list[3] != crontab["months"]:
            return False
        elif cron_list[2] != crontab["days"]:
            return False
        elif cron_list[1] != crontab["hours"]:
            return False
        elif cron_list[0] != crontab["minutes"]:
            return False
        else:
            return True
    except Exception as error:
        return False


def convert_to_utc(hour=None, timezone=None):
    tz = pytz_timezone(timezone)

    local_time = datetime.datetime.now(tz=tz).replace(hour=int(hour))

    utc_time = local_time.astimezone(pytz.UTC)

    return str(utc_time.hour)


def get_md5_hash(string=None):
    md5 = hashlib.md5()

    md5.update(string)

    return md5.hexdigest()


def validate_email(email):
    from django.core.validators import validate_email
    from django.core.exceptions import ValidationError

    try:
        validate_email(email)
        return True
    except ValidationError:
        return False


def validate_url(url):
    from django.core.validators import URLValidator
    from django.core.exceptions import ValidationError

    validate = URLValidator()

    try:
        validate(url)
        return True
    except ValidationError:
        return False


def email_present_exclude_own(email, id):
    if User.objects.filter(email=email).exclude(id=id).count():
        return True

    return False


def get_random_password():
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    pw_length = 14
    mypw = ""

    for i in range(pw_length):
        next_index = random.randrange(len(alphabet))
        mypw = mypw + alphabet[next_index]

    return mypw


def stripe_get_access_token_from_code(code):
    secret_key = getattr(settings, "STRIPE_SECRET_KEY")

    data_type = "JSON"

    api_url = "https://connect.stripe.com/oauth/token"

    data = {
        "client_secret": secret_key,
        "grant_type": "authorization_code",
        "code": code,
    }

    headers = {"Content-type": "application/x-www-form-urlencoded"}

    result = requests.post(api_url, data=data, headers=headers)

    return result


def generate_random_email_verification(length=16, chars=ascii_lowercase + digits, split=4, delimiter="-"):
    code = "".join([choice(chars) for i in xrange(length)])
    if split:
        code = delimiter.join([code[start : start + split] for start in range(0, len(code), split)])

    try:
        if CoreMember.objects.get(email_token=code):
            return generate_random_email_verification(length=length, chars=chars, split=split, delimiter=delimiter)
        else:
            return code
    except CoreMember.DoesNotExist:
        return code


def generate_random_username(length=16, chars=ascii_lowercase + digits, split=4, delimiter="-"):
    username = "".join([choice(chars) for i in range(length)])

    if split:
        username = delimiter.join([username[start : start + split] for start in range(0, len(username), split)])

    try:
        User.objects.get(username=username)
        return generate_random_username(length=length, chars=chars, split=split, delimiter=delimiter)
    except User.DoesNotExist:
        return username


def random_code(
    model,
    field="code",
    length=16,
    chars=ascii_lowercase + digits,
    split=4,
    delimiter="-",
):
    code = "".join([choice(chars) for i in range(length)])

    if split:
        code = delimiter.join([code[start : start + split] for start in range(0, len(code), split)])
    try:
        model.objects.get(**{field: code})
        return random_code(
            model,
            field=field,
            length=length,
            chars=chars,
            split=split,
            delimiter=delimiter,
        )
    except model.DoesNotExist:
        return code


def get_client_ip(request):
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        ip = x_forwarded_for.split(",")[0]
    else:
        ip = request.META.get("REMOTE_ADDR")
    return ip


def represents_int(s):
    try:
        int(s)
        return True
    except Exception as e:
        return False


def convert_to_int(s):
    try:
        return int(s)
    except Exception as e:
        return s


def get_start_end_of_previous_day(days):
    yesterday = datetime.datetime.now() - datetime.timedelta(days=days)
    yesterday_beginning = datetime.datetime(yesterday.year, yesterday.month, yesterday.day, 0, 0, 0, 0)
    yesterday_beginning_time = int(time.mktime(yesterday_beginning.timetuple()))
    yesterday_end = datetime.datetime(yesterday.year, yesterday.month, yesterday.day, 23, 59, 59, 999)
    yesterday_end_time = int(time.mktime(yesterday_end.timetuple()))

    start_end = dict()

    start_end["start_time"] = yesterday_beginning_time
    start_end["end_time"] = yesterday_end_time

    return start_end


def get_start_end_of_a_day(date_object):
    day_start_end = dict()

    start_time = datetime.datetime(date_object.year, date_object.month, date_object.day, 0, 0, 0, 0)

    end_time = datetime.datetime(date_object.year, date_object.month, date_object.day, 23, 59, 59, 999)

    day_start_end["start_time"] = int(time.mktime(start_time.timetuple()))

    day_start_end["end_time"] = int(time.mktime(end_time.timetuple()))

    return day_start_end


def sizify(value):
    """
    Simple kb/mb/gb size snippet for templates:

    {{ product.file.size|sizify }}
    """
    # value = ing(value)
    if value < 512000:
        value = value / 1024.0
        ext = "kb"
    elif value < 4194304000:
        value = value / 1048576.0
        ext = "mb"
    else:
        value = value / 1073741824.0
        ext = "gb"
    return f"{str(round(value, 2))} {ext}"


def get_coordinates(query, from_sensor=False):
    import urllib
    import json

    googleGeocodeUrl = "https://maps.googleapis.com/maps/api/geocode/json?"

    query = query.encode("utf-8")
    params = {
        "address": query,
        "key": "AIzaSyBvj20P6aP-DowWicCrp3ON-ZzSyXYPOOM",
        "sensor": "true" if from_sensor else "false",
    }
    url = googleGeocodeUrl + urllib.urlencode(params)
    json_response = urllib.urlopen(url)
    response = json.loads(json_response.read())
    if response["results"]:
        location = response["results"][0]["geometry"]["location"]
        latitude, longitude = location["lat"], location["lng"]
        print(query, latitude, longitude)
    else:
        latitude, longitude = None, None
        print(query, "<no results>")
    return latitude, longitude


def color_variant(hex_color, brightness_offset=1):
    """takes a color like #87c95f and produces a lighter or darker variant"""
    if len(hex_color) != 7:
        raise Exception("Passed %s into color_variant(), needs to be in #87c95f format." % hex_color)
    rgb_hex = [hex_color[x : x + 2] for x in [1, 3, 5]]
    new_rgb_int = [int(hex_value, 16) + brightness_offset for hex_value in rgb_hex]
    new_rgb_int = [min([255, max([0, i])]) for i in new_rgb_int]  # make sure new values are between 0 and 255
    # hex() produces "0x88", we want just "88"
    return "#" + "".join([hex(i)[2:] for i in new_rgb_int])


def add_session_to_request(request):
    """Annotate a request object with a session"""
    middleware = SessionMiddleware()
    middleware.process_request(request)
    request.session.save()


def dictfetchall(cursor):
    "Return all rows from a cursor as a dict"
    columns = [col[0] for col in cursor.description]
    return [dict(zip(columns, row)) for row in cursor.fetchall()]


def does_service_exist(host, port):
    captive_dns_addr = ""
    host_addr = ""

    try:
        captive_dns_addr = socket.gethostbyname("BlahThisDomaynDontExist22.com")
    except:
        pass

    try:
        host_addr = socket.gethostbyname(host)

        if captive_dns_addr == host_addr:
            return False

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect((host, port))
        s.close()
    except:
        return False

    return True


class FtpSession(ftplib.FTP):
    def __init__(self, host, userid, password, port):
        """Act like ftplib.FTP's constructor but connect to another port."""
        ftplib.FTP.__init__(self)
        self.connect(host, port, 10)
        self.login(userid, password)


class FtpTlsSession(ftplib.FTP_TLS):
    def __init__(self, host, userid, password, port):
        """Act like ftplib.FTP's constructor but connect to another port."""
        ftplib.FTP_TLS.__init__(self)
        self.connect(host, port, 10)
        self.login(userid, password)
        # Set up encrypted data connection.
        self.prot_p()


def zipdir(path, ziph):
    # ziph is zipfile handle
    for root, dirs, files in os.walk(path, onerror=None, followlinks=False):
        for file in files:
            try:
                ziph.write(
                    os.path.join(root, file),
                    os.path.relpath(os.path.join(root, file), os.path.join(path, ".")),
                )
            except:
                pass


def isdir(path, sftp):
    try:
        return S_ISDIR(sftp.stat(path).st_mode)
    except IOError:
        return False


def isFile(path, sftp):
    try:
        return S_ISREG(sftp.stat(path).st_mode)
    except IOError:
        # Path does not exist, so by definition not a directory
        return False


def isLink(path, sftp):
    try:
        return S_ISLNK(sftp.stat(path).st_mode)
    except:
        return False


def lessThan5GB(path, sftp):
    try:
        if sftp.stat(path).st_size <= 107374182400:
            return True
        else:
            return True
    except:
        # Path does not exist, so by definition not a directory
        return True


def sftp_get_recursive(path, sftp, remote_files):
    if isdir(path, sftp) and not isLink(path, sftp):
        item_list = sftp.listdir(path)

        for item in item_list:
            # item = str(item)
            if isdir(path + "/" + item, sftp):
                sftp_get_recursive(path + "/" + item, sftp, remote_files)
            else:
                if lessThan5GB((path + "/" + item), sftp):
                    print(path + "/" + item)
                    remote_files.append(path + "/" + item)
    else:
        if lessThan5GB(path, sftp) and not isLink(path, sftp):
            print(path)
            remote_files.append(path)


def create_directory(directory):
    if not os.path.exists(os.path.dirname(directory)):
        try:
            os.makedirs(os.path.dirname(directory))
        except OSError as exc:  # Guard against race condition
            if exc.errno != errno.EEXIST:
                raise


def create_directory_v2(file_path):
    os.makedirs(os.path.dirname(file_path), exist_ok=True)


def mkdir_p(path, add_bs_file=True):
    try:
        os.makedirs(path)
        if add_bs_file:
            # add basic file to avoid corrupt zip file backups
            if not os.path.exists(f"{path}backupsheep.txt"):
                with open(f"{path}backupsheep.txt", "w") as file:
                    file.write(
                        "This is just a placeholder file to avoid zip file corruption. "
                        "If you don't see your files then we were unable to download them. "
                        "Check your user permissions or contact support@backupsheep.com"
                    )
    except OSError as exc:  # Python >2.5
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            capture_exception(exc)
    except Exception as e:
        capture_exception(e)


def get_error(error_text):
    try:
        return str(error_text)
    except:
        return "n/a"


def get_all_files_in_directory(directory):
    all_files = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            if not os.path.islink(os.path.join(root, file)):
                all_files.append(os.path.join(root, file))
                # for dir in dirs:
                #     all_files.append(os.path.join(root, dir))
    return all_files


def get_directory_size(start_path="."):
    total_size = 0
    for dirpath, dirnames, filenames in os.walk(start_path):
        for f in filenames:
            fp = os.path.join(dirpath, f)
            try:
                total_size += os.path.getsize(fp)
            except:
                pass
    return total_size


def get_directory_number_of_files(path="."):
    return sum([len(files) for r, d, files in os.walk(path)])


def get_directory_number_of_directories(path="."):
    return sum([len(d) for r, d, files in os.walk(path)])


def bs_encrypt(plaintext, key):
    if plaintext:
        if plaintext.strip() != "":
            try:
                f = Fernet(key)
                return f.encrypt(plaintext.encode("utf-8"))
            except Exception as e:
                capture_exception(e)
        else:
            return None
    else:
        return None


def bs_decrypt(ciphertext, key):
    if ciphertext:
        try:
            f = Fernet(key)
            return f.decrypt(bytes(ciphertext)).decode("utf-8")
        except Exception as e:
            capture_exception(e)
    else:
        return None


def bs_encryption_convert(ciphertext, encryption_key):
    return bs_encrypt(kms_decrypt(ciphertext), encryption_key)


def s3_upload_files(single_file, bucket_name, access_key, secret_key, region_name, endpoint_url):
    try:
        session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region_name,
            profile_name="wasabi",
        )
        capture_message("sessio ok")

        s3 = session.resource("s3", endpoint_url=endpoint_url)

        file_path = single_file.decode("utf8", "surrogateescape")

        key_name = urllib.parse.quote(single_file).replace("_storage/", "", 1)

        upload_result = s3.meta.client.upload_file(file_path, bucket_name, key_name)
        capture_message(upload_result)

    except Exception as e:
        capture_exception(e)


def get_start_end_of_previous_day(days):
    from datetime import timedelta

    day = datetime.datetime.now() - timedelta(days=days)
    day_beginning = datetime.datetime(day.year, day.month, day.day, 0, 0, 0, 0)
    day_beginning_time = int(time.mktime(day_beginning.timetuple()))
    day_end = datetime.datetime(day.year, day.month, day.day, 23, 59, 59, 999)
    day_end_time = int(time.mktime(day_end.timetuple()))

    start_end = dict()

    start_end["start_time"] = day_beginning_time
    start_end["end_time"] = day_end_time

    return start_end


def get_start_end_of_a_day(date_object):
    day_start_end = dict()

    start_time = datetime.datetime(date_object.year, date_object.month, date_object.day, 0, 0, 0, 0)

    end_time = datetime.datetime(date_object.year, date_object.month, date_object.day, 23, 59, 59, 999)

    day_start_end["start_time"] = int(time.mktime(start_time.timetuple()))

    day_start_end["end_time"] = int(time.mktime(end_time.timetuple()))

    return day_start_end


class ImplicitFTP_TLS(ftplib.FTP_TLS):
    """FTP_TLS subclass that automatically wraps sockets in SSL to support implicit FTPS."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._sock = None

    @property
    def sock(self):
        """Return the socket."""
        return self._sock

    @sock.setter
    def sock(self, value):
        """When modifying the socket, ensure that it is ssl wrapped."""
        if value is not None and not isinstance(value, ssl.SSLSocket):
            value = self.context.wrap_socket(value)
        self._sock = value


class CurrentMemberDefault:
    requires_context = True

    def __call__(self, serializer_field):
        return serializer_field.context["request"].user.member

    def __repr__(self):
        return "%s()" % self.__class__.__name__


class CurrentAccountDefault:
    requires_context = True

    def __call__(self, serializer_field):
        return serializer_field.context["request"].user.member.get_current_account()

    def __repr__(self):
        return "%s()" % self.__class__.__name__


class GenerateGroup:
    requires_context = True

    def __call__(self, serializer_field):
        from apps.console.account.models import CoreAccountGroup
        from django.contrib.auth.models import Group
        from django.utils.text import slugify

        group = None

        if serializer_field.context["request"].data.get("type") and serializer_field.context["request"].data.get(
            "name"
        ):
            account = serializer_field.context["request"].user.member.get_current_account()
            type_choices = dict(CoreAccountGroup.Type.choices)
            type_name = type_choices[int(serializer_field.context["request"].data["type"])]
            group_name = serializer_field.context["request"].data["name"]
            group, _ = Group.objects.get_or_create(name=slugify(f"{account.id}-{group_name}-{type_name}"))
        return group

    def __repr__(self):
        return "%s()" % self.__class__.__name__


class AccountGroupDefault:
    requires_context = True

    def __call__(self, serializer_field):
        return False

    def __repr__(self):
        return "%s()" % self.__class__.__name__


class IntegrationDefault:
    requires_context = True

    def __init__(self, integration_code):
        self.integration_code = integration_code

    def __call__(self, serializer_field):
        from apps.console.connection.models import CoreIntegration

        return CoreIntegration.objects.get(code=self.integration_code)

    def __repr__(self):
        return "%s()" % self.__class__.__name__


class StorageDefault:
    requires_context = True

    def __init__(self, type_code):
        self.type_code = type_code

    def __call__(self, serializer_field):
        from apps.console.storage.models import CoreStorageType

        return CoreStorageType.objects.get(code=self.type_code)

    def __repr__(self):
        return "%s()" % self.__class__.__name__


def check_string_in_file(file_path, find_string):
    with open(file_path, errors='ignore') as temp_f:
        datafile = temp_f.readlines()
    for line in datafile:
        if find_string in line:
            return True
    return False


def check_path_overlap(target_path, paths_list):
    for path in paths_list:
        if os.path.commonpath([target_path, path]) == os.path.commonprefix([target_path, path]):
            return True
    return False


def download_snar_file(file_path, object_name):
    try:
        service_key_json = json.loads(settings.BS_GOOGLE_CLOUD_SERVICE_KEY)
        credentials = service_account.Credentials.from_service_account_info(service_key_json)
        storage_client = gc_storage.Client(credentials=credentials)
        bucket = storage_client.bucket(settings.BS_GOOGLE_CLOUD_SNAR_BUCKET)

        blob = bucket.blob(object_name)

        if blob.exists():
            blob = bucket.blob(object_name)
            blob.download_to_filename(file_path)
    except Exception as e:
        capture_exception(e)


def delete_snar_file(object_name):
    try:
        service_key_json = json.loads(settings.BS_GOOGLE_CLOUD_SERVICE_KEY)
        credentials = service_account.Credentials.from_service_account_info(service_key_json)
        storage_client = gc_storage.Client(credentials=credentials)
        bucket = storage_client.bucket(settings.BS_GOOGLE_CLOUD_SNAR_BUCKET)

        blob = bucket.blob(object_name)

        if blob.exists():
            blob.delete()
    except Exception as e:
        capture_exception(e)


def google_cloud_signed_upload_url(object_name):
    try:
        service_key_json = json.loads(settings.BS_GOOGLE_CLOUD_SERVICE_KEY)
        credentials = service_account.Credentials.from_service_account_info(service_key_json)
        storage_client = gc_storage.Client(credentials=credentials)
        bucket = storage_client.bucket(settings.BS_GOOGLE_CLOUD_SNAR_BUCKET)

        blob = bucket.blob(object_name)

        url = blob.generate_signed_url(
            version="v4",
            # This URL is valid for 15 minutes
            expiration=datetime.timedelta(hours=48),
            # Allow PUT requests using this URL.
            method="PUT",
            content_type="application/octet-stream",
        )
        return url
    except Exception as e:
        capture_exception(e)


def upload_snar_file(file_path, object_name, replace=None):
    try:
        service_key_json = json.loads(settings.BS_GOOGLE_CLOUD_SERVICE_KEY)
        credentials = service_account.Credentials.from_service_account_info(service_key_json)
        storage_client = gc_storage.Client(credentials=credentials)
        bucket = storage_client.bucket(settings.BS_GOOGLE_CLOUD_SNAR_BUCKET)

        blob = bucket.blob(object_name)
        if not blob.exists() or replace:
            blob.upload_from_filename(file_path)
    except Exception as e:
        capture_exception(e)


def aws_s3_upload_log_file(file_path, object_name):
    try:
        if object_name is None:
            object_name = os.path.basename(file_path)
        #
        # s3_endpoint = f"https://{settings.AWS_S3_LOGS_ENDPOINT}"
        # bucket_name = settings.AWS_S3_LOGS_BUCKET
        #
        # if "fra.idrivee" in s3_endpoint:
        #     access_key = settings.IDRIVE_FRA_ACCESS_KEY
        #     secret_key = settings.IDRIVE_FRA_SECRET_ACCESS_KEY
        # else:
        #     access_key = settings.AWS_S3_ACCESS_KEY
        #     secret_key = settings.AWS_S3_SECRET_ACCESS_KEY
        #
        # s3_client = boto3.client(
        #     "s3",
        #     endpoint_url=s3_endpoint,
        #     aws_access_key_id=access_key,
        #     aws_secret_access_key=secret_key,
        # )

        service_key_json = json.loads(settings.BS_GOOGLE_CLOUD_SERVICE_KEY)
        credentials = service_account.Credentials.from_service_account_info(service_key_json)
        storage_client = gc_storage.Client(credentials=credentials)
        bucket = storage_client.bucket(settings.AWS_S3_LOGS_BUCKET)

        # Only upload if file exists
        if os.path.exists(file_path):
            # s3_client.upload_file(
            #     file_path,
            #     bucket_name,
            #     object_name,
            # )

            blob = bucket.blob(object_name)
            blob.upload_from_filename(file_path)
    except Exception as e:
        capture_exception(e)


def aws_s3_create_presigned_url(bucket_name, object_name, expiration=3600):
    try:
        if bucket_name is None:
            bucket_name = settings.LOGS_S3_BUCKET

        s3_client = boto3.client(
            "s3",
            # region_name="nyc3",
            endpoint_url=settings.LOGS_S3_ENDPOINT,
            aws_access_key_id=settings.LOGS_S3_ACCESS_KEY_ID,
            aws_secret_access_key=settings.LOGS_S3_SECRET_ACCESS_KEY,
        )
        response = s3_client.generate_presigned_url(
            "get_object", Params={"Bucket": bucket_name, "Key": object_name}, ExpiresIn=expiration
        )
    except Exception as e:
        capture_exception(e)


class Ssl23HttpAdapter(HTTPAdapter):
    """ "Transport adapter" that allows us to use SSLv3."""

    def init_poolmanager(self, connections, maxsize, block=False):
        self.poolmanager = PoolManager(
            num_pools=connections, maxsize=maxsize, block=block, ssl_version=ssl.PROTOCOL_SSLv3
        )


def make_digest(message, key):
    key = bytes(key, "UTF-8")
    message = bytes(message, "UTF-8")

    digester = hmac.new(key, message, hashlib.sha1)
    # signature1 = digester.hexdigest()
    signature1 = digester.digest()
    # print(signature1)

    # signature2 = base64.urlsafe_b64encode(bytes(signature1, 'UTF-8'))
    signature2 = base64.urlsafe_b64encode(signature1)
    # print(signature2)

    return str(signature2, "UTF-8")


def check_error(error_text):
    valid_error = None
    try:
        valid_error = len(error_text.strip()) > 0
    except Exception:
        pass
    return valid_error
