from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password

User = get_user_model()

INPUT = ("block w-full rounded-lg border-0 px-3.5 py-2.5 text-slate-900 shadow-sm "
         "ring-1 ring-inset ring-slate-300 placeholder:text-slate-400 "
         "focus:ring-2 focus:ring-inset focus:ring-indigo-600 sm:text-sm sm:leading-6")


class InviteSignupForm(forms.Form):
    """Signup form shown on the public invite page to an invitee who does not have
    an account yet. The email is fixed by the invite (displayed read-only); names
    are prefilled from the invite. Accepting creates User + CoreMember."""

    first_name = forms.CharField(
        max_length=64, widget=forms.TextInput(attrs={"class": INPUT, "autocomplete": "given-name"})
    )
    last_name = forms.CharField(
        max_length=64, widget=forms.TextInput(attrs={"class": INPUT, "autocomplete": "family-name"})
    )
    password1 = forms.CharField(
        label="Password",
        widget=forms.PasswordInput(attrs={"class": INPUT, "autocomplete": "new-password"}),
    )
    password2 = forms.CharField(
        label="Confirm password",
        widget=forms.PasswordInput(attrs={"class": INPUT, "autocomplete": "new-password"}),
    )

    def clean_password2(self):
        p1 = self.cleaned_data.get("password1")
        p2 = self.cleaned_data.get("password2")
        if p1 and p2 and p1 != p2:
            raise forms.ValidationError("The two passwords do not match.")
        validate_password(p2)
        return p2
