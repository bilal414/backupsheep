from cryptography.fernet import Fernet
from django.conf import settings as dj_settings
from django.contrib import messages
from django.contrib.auth import get_user_model, login
from django.db import transaction
from django.shortcuts import redirect, render
from django.utils import timezone

import os
import secrets

from apps.console.account.models import CoreAccount
from apps.console.member.models import CoreMember, CoreMemberAccount
from apps.console.setting.models import CoreSiteSettings
from apps.console.storage.models import CoreStorageType

from .forms import AccountForm, AppSettingsForm, EmailForm

User = get_user_model()
STEPS = ["Account", "Settings", "Email", "Storage", "Sources"]


def _ctx(step, **extra):
    site = CoreSiteSettings.load()
    ctx = {"steps": STEPS, "step": step, "app_name": site.get_app_name()}
    ctx.update(extra)
    return ctx


def _require_admin(request):
    return request.user.is_authenticated and hasattr(request.user, "member")


def _expected_install_token():
    """Token the installer must present to create the first admin account.

    Priority: the ONBOARDING_INSTALL_TOKEN environment setting; otherwise a random
    per-install token written to a file that is only readable with host/container
    access (generated on first request). Either way, completing the wizard over the
    network requires proving access to the machine it runs on.
    """
    if dj_settings.ONBOARDING_INSTALL_TOKEN:
        return dj_settings.ONBOARDING_INSTALL_TOKEN
    path = dj_settings.ONBOARDING_INSTALL_TOKEN_FILE
    try:
        with open(path) as fh:
            token = fh.read().strip()
            if token:
                return token
    except OSError:
        pass
    token = secrets.token_urlsafe(24)
    try:
        with open(path, "w") as fh:
            fh.write(token)
        os.chmod(path, 0o600)
    except OSError:
        pass
    return token


def _install_token_ok(request, expected):
    presented = request.POST.get("install_token", "").strip()
    if not presented or not expected:
        return False
    return secrets.compare_digest(presented, expected)


def index(request):
    if not User.objects.exists():
        return redirect("console:onboarding:account")
    if not request.user.is_authenticated:
        return redirect(dj_settings.LOGIN_URL)
    return redirect("console:onboarding:app_settings")


def account(request):
    # Once an admin exists the wizard must never create a second one.
    if User.objects.exists():
        if request.user.is_authenticated:
            return redirect("console:onboarding:app_settings")
        return render(request, "console/onboarding/account_exists.html", _ctx(1))

    if request.method == "POST":
        form = AccountForm(request.POST)
        token_ok = _install_token_ok(request, _expected_install_token())
        if not token_ok:
            form.add_error(
                "install_token",
                "Invalid install token. Read it from the server with: "
                "docker compose exec app cat /code/_storage/install_token",
            )
        if token_ok and form.is_valid():
            with transaction.atomic():
                user = User.objects.create_user(
                    username=form.cleaned_data["email"],
                    email=form.cleaned_data["email"],
                    password=form.cleaned_data["password1"],
                    first_name=form.cleaned_data["full_name"][:150],
                )
                member = CoreMember.objects.create(user=user, timezone="UTC")
                core_account = CoreAccount.objects.create(
                    name=form.cleaned_data.get("organization") or form.cleaned_data["full_name"],
                    encryption_key=Fernet.generate_key(),
                )
                CoreMemberAccount.objects.create(
                    member=member,
                    account=core_account,
                    status=CoreMemberAccount.Status.ACTIVE,
                    current=True,
                    primary=True,
                )
            login(request, user)  # single ModelBackend, so no backend kwarg needed
            return redirect("console:onboarding:app_settings")
    else:
        form = AccountForm()
    return render(request, "console/onboarding/account.html", _ctx(1, form=form))


def app_settings(request):
    if not _require_admin(request):
        return redirect("console:onboarding:index")
    site = CoreSiteSettings.load()
    if request.method == "POST":
        form = AppSettingsForm(request.POST)
        if form.is_valid():
            site.app_name = form.cleaned_data["app_name"]
            site.app_protocol = form.cleaned_data["app_protocol"]
            site.app_domain = form.cleaned_data["app_domain"]
            site.default_timezone = form.cleaned_data["default_timezone"]
            site.save()
            request.user.member.timezone = site.default_timezone
            request.user.member.save()
            return redirect("console:onboarding:email")
    else:
        form = AppSettingsForm(initial={
            "app_name": site.get_app_name(),
            "app_protocol": site.app_protocol or "https://",
            "app_domain": site.get_app_domain(),
            "default_timezone": site.get_default_timezone(),
        })
    return render(request, "console/onboarding/app_settings.html", _ctx(2, form=form))


def email(request):
    if not _require_admin(request):
        return redirect("console:onboarding:index")
    site = CoreSiteSettings.load()
    if request.method == "POST":
        form = EmailForm(request.POST)
        if form.is_valid():
            site.email_provider = form.cleaned_data["email_provider"]
            site.set_email_credentials(form.credentials())
            site.save()
            if request.POST.get("action") == "test":
                if site.get_email_provider() == "none":
                    messages.warning(request, "Select a provider before sending a test email.")
                else:
                    ok, detail = site.send_test_email(request.user.email)
                    if ok:
                        messages.success(request, f"Test email sent to {request.user.email}.")
                    else:
                        messages.error(request, f"Test failed: {detail}")
            else:
                return redirect("console:onboarding:storage")
    else:
        form = EmailForm(initial={"email_provider": site.get_email_provider()})
    return render(request, "console/onboarding/email.html", _ctx(3, form=form))


def storage(request):
    if not _require_admin(request):
        return redirect("console:onboarding:index")
    providers = CoreStorageType.objects.filter(is_enabled=True).order_by("position")
    return render(request, "console/onboarding/storage.html", _ctx(4, providers=providers))


def source(request):
    if not _require_admin(request):
        return redirect("console:onboarding:index")
    return render(request, "console/onboarding/source.html", _ctx(5))


def finish(request):
    if not _require_admin(request):
        return redirect("console:onboarding:index")
    if request.method == "POST":
        site = CoreSiteSettings.load()
        site.setup_completed = True
        site.setup_completed_at = timezone.now()
        site.save()
        messages.success(request, "Setup complete. Welcome to BackupSheep.")
        return redirect(dj_settings.HOME_URL)
    return redirect("console:onboarding:source")
