import pytz
from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password

User = get_user_model()

INPUT = ("block w-full rounded-md border border-gray-300 px-3 py-2 text-sm "
         "focus:border-indigo-500 focus:ring-indigo-500")

_TZ_CHOICES = [(tz, tz) for tz in pytz.common_timezones]
_PROTOCOL_CHOICES = [("https://", "https://"), ("http://", "http://")]
_EMAIL_PROVIDER_CHOICES = [
    ("none", "Disabled (no transactional email)"),
    ("postmark", "Postmark"),
    ("mailgun", "Mailgun"),
    ("ses", "Amazon SES"),
]


class AccountForm(forms.Form):
    """Creates the first admin (account owner). Email is also the login username."""

    full_name = forms.CharField(max_length=150, widget=forms.TextInput(attrs={"class": INPUT}))
    organization = forms.CharField(
        max_length=255, required=False, widget=forms.TextInput(attrs={"class": INPUT})
    )
    email = forms.EmailField(widget=forms.EmailInput(attrs={"class": INPUT, "autocomplete": "username"}))
    password1 = forms.CharField(
        label="Password",
        widget=forms.PasswordInput(attrs={"class": INPUT, "autocomplete": "new-password"}),
    )
    password2 = forms.CharField(
        label="Confirm password",
        widget=forms.PasswordInput(attrs={"class": INPUT, "autocomplete": "new-password"}),
    )

    def clean_email(self):
        email = self.cleaned_data["email"].strip().lower()
        if User.objects.filter(email__iexact=email).exists() or User.objects.filter(
            username__iexact=email
        ).exists():
            raise forms.ValidationError("A user with this email already exists.")
        return email

    def clean_password2(self):
        p1 = self.cleaned_data.get("password1")
        p2 = self.cleaned_data.get("password2")
        if p1 and p2 and p1 != p2:
            raise forms.ValidationError("The two passwords do not match.")
        validate_password(p2)
        return p2


class AppSettingsForm(forms.Form):
    app_name = forms.CharField(max_length=255, widget=forms.TextInput(attrs={"class": INPUT}))
    app_protocol = forms.ChoiceField(
        choices=_PROTOCOL_CHOICES, widget=forms.Select(attrs={"class": INPUT})
    )
    app_domain = forms.CharField(
        max_length=255,
        help_text="The public host this install is reached at, e.g. backup.example.com",
        widget=forms.TextInput(attrs={"class": INPUT, "placeholder": "backup.example.com"}),
    )
    default_timezone = forms.ChoiceField(
        choices=_TZ_CHOICES, initial="UTC", widget=forms.Select(attrs={"class": INPUT})
    )


class EmailForm(forms.Form):
    """Transactional email provider. Fields are validated only for the chosen provider."""

    email_provider = forms.ChoiceField(
        choices=_EMAIL_PROVIDER_CHOICES, widget=forms.Select(attrs={"class": INPUT, "x-model": "provider"})
    )
    postmark_api_key = forms.CharField(required=False, widget=forms.TextInput(attrs={"class": INPUT}))
    postmark_email = forms.EmailField(required=False, widget=forms.EmailInput(attrs={"class": INPUT}))
    mailgun_api_key = forms.CharField(required=False, widget=forms.TextInput(attrs={"class": INPUT}))
    mailgun_domain = forms.CharField(required=False, widget=forms.TextInput(attrs={"class": INPUT}))
    mailgun_email = forms.EmailField(required=False, widget=forms.EmailInput(attrs={"class": INPUT}))
    ses_access_key_id = forms.CharField(required=False, widget=forms.TextInput(attrs={"class": INPUT}))
    ses_secret_access_key = forms.CharField(required=False, widget=forms.TextInput(attrs={"class": INPUT}))
    ses_region_name = forms.CharField(required=False, widget=forms.TextInput(attrs={"class": INPUT}))
    ses_from_email = forms.EmailField(required=False, widget=forms.EmailInput(attrs={"class": INPUT}))

    _REQUIRED = {
        "postmark": ["postmark_api_key", "postmark_email"],
        "mailgun": ["mailgun_api_key", "mailgun_domain", "mailgun_email"],
        "ses": ["ses_access_key_id", "ses_secret_access_key", "ses_region_name", "ses_from_email"],
    }

    def clean(self):
        cleaned = super().clean()
        provider = cleaned.get("email_provider")
        for field in self._REQUIRED.get(provider, []):
            if not cleaned.get(field):
                self.add_error(field, "Required for the selected provider.")
        return cleaned

    def credentials(self):
        """Provider -> credentials dict, in the shape CoreSiteSettings.email_cred expects."""
        c = self.cleaned_data
        return {
            "postmark": {"api_key": c.get("postmark_api_key"), "email": c.get("postmark_email")},
            "mailgun": {"api_key": c.get("mailgun_api_key"), "domain": c.get("mailgun_domain"),
                        "email": c.get("mailgun_email")},
            "ses": {"access_key_id": c.get("ses_access_key_id"),
                    "secret_access_key": c.get("ses_secret_access_key"),
                    "region_name": c.get("ses_region_name"), "from_email": c.get("ses_from_email")},
        }
