from django.contrib.auth import get_user_model, login
from django.contrib import messages
from django.db import transaction
from django.shortcuts import get_object_or_404, redirect, render

from apps.console.invite.forms import InviteSignupForm
from apps.console.invite.models import CoreInvite
from apps.console.member.models import CoreMember

User = get_user_model()


def _record_member_log(account, data):
    """Team-activity audit log. Never allowed to break the action it describes."""
    try:
        from apps.console.log.models import CoreLog

        CoreLog.record(account, CoreLog.Type.MEMBER, data)
    except Exception as e:
        print(f"Unable to record member log: {e}")


def _finish_accept(request, invite, member):
    """Shared tail of both accept paths (logged-in accept + signup accept):
    grant access, make the invited account the member's current one and record
    the activity log."""
    invite.accept(member)

    # Make the new account current: clear the previous marker first (a member can
    # have only one current membership), then delegate to set_current_account.
    member.memberships.filter(current=True).exclude(account=invite.account).update(current=False)
    member.set_current_account(invite.account)

    _record_member_log(
        invite.account,
        {
            "message": f"Invite accepted by {member.email}.",
            "actor_email": member.email,
            "invite_id": invite.id,
            "invitee_email": invite.email,
        },
    )


def accept(request, uuid):
    """Public invite landing page (/invite/<uuid>/).

    - logged in with the invited email -> accept button (POST) joins the account
    - anonymous -> signup form creating User + CoreMember, then the same accept
    - accepted/cancelled/expired/unknown invites render a friendly notice
    """
    invite = get_object_or_404(CoreInvite, uuid=uuid)
    invite.expire_if_needed()  # lazily flip past-expiry pending invites

    if invite.status != CoreInvite.Status.PENDING:
        return render(
            request,
            "console/invite/accept.html",
            {"invite": invite, "invite_unavailable": True, "heading": "Invite unavailable"},
        )

    email_matches = (
        request.user.is_authenticated
        and request.user.email.lower() == invite.email.lower()
    )

    if request.method == "POST":
        if request.user.is_authenticated:
            if not email_matches:
                # A different user is logged in; they must switch accounts first.
                return render(request, "console/invite/accept.html", _ctx(invite))
            _finish_accept(request, invite, request.user.member)
            messages.success(
                request, f"Invite accepted. You now have access to {invite.account.get_name()}."
            )
            return redirect("console:home:index")

        form = InviteSignupForm(request.POST)
        email_taken = User.objects.filter(email__iexact=invite.email).exists()
        if email_taken:
            # Existing users must log in and accept, not re-register.
            form.add_error(None, "An account with this email already exists. Please log in to accept this invite.")
        if not email_taken and form.is_valid():
            with transaction.atomic():
                user = User.objects.create_user(
                    username=invite.email,
                    email=invite.email,
                    password=form.cleaned_data["password1"],
                    first_name=form.cleaned_data["first_name"][:150],
                    last_name=form.cleaned_data["last_name"][:150],
                )
                member = CoreMember.objects.create(user=user, timezone=invite.timezone or "UTC")
                _finish_accept(request, invite, member)
            login(request, user)  # single ModelBackend, so no backend kwarg needed
            messages.success(
                request, f"Welcome! You now have access to {invite.account.get_name()}."
            )
            return redirect("console:home:index")
        return render(request, "console/invite/accept.html", _ctx(invite, form=form))

    # GET
    return render(request, "console/invite/accept.html", _ctx(invite))


def _ctx(invite, form=None):
    if form is None:
        form = InviteSignupForm(
            initial={"first_name": invite.first_name, "last_name": invite.last_name}
        )
    return {
        "heading": f"Join {invite.account.get_name()}",
        "invite": invite,
        "form": form,
        "groups": invite.groups.all(),
    }
