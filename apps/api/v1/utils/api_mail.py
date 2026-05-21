import json
from django.conf import settings


class SendEmail:
    def __init__(self):
        self.recipient = ''
        self.activation_token = ''

    @staticmethod
    def app_message(message=None, email=settings.APP_EMAIL):
        # if settings.DJANGO_SERVER != 'prod':
        #     email = settings.APP_EMAIL
        pass
        # mail.send(
        #     [email],
        #     priority='now',
        #     template='app_message',
        #     # headers={'X-MSYS-API': json.dumps({"options": {"ip_pool": "default"}})},
        #     context={
        #         'message': message,
        #     }
        # )

    @staticmethod
    def send_email(template=None, recipient=None, **kwargs):
        pass
        # if settings.DJANGO_SERVER != 'prod':
        #     recipient = settings.APP_EMAIL
        # mail.send(
        #     [recipient],
        #     priority='now',
        #     template=template,
        #     # headers={'X-MSYS-API': json.dumps({"options": {"ip_pool": "default"}})},
        #     context=kwargs
        # )
        # mail.send(
        #     [settings.APP_EMAIL],
        #     priority='now',
        #     template=template,
        #     context=kwargs
        # )

    @staticmethod
    def send_notification(template=None, recipient=None, data=dict):
        # if settings.DJANGO_SERVER != 'prod':
        #     recipient = settings.APP_EMAIL
        pass
        # mail.send(
        #     [recipient],
        #     priority='now',
        #     template=template,
        #     # headers={'X-MSYS-API': json.dumps({"options": {"ip_pool": "default"}})},
        #     context=data
        # )
        # mail.send(
        #     [settings.APP_EMAIL],
        #     priority='now',
        #     template=template,
        #     context=data
        # )
