from django.contrib import admin

from apps.console.member.models import CoreMember


class CoreMemberAdmin(admin.ModelAdmin):
    list_display = ("id", "created", "user")
    search_fields = [field.name for field in CoreMember._meta.get_fields()]

admin.site.register(CoreMember, CoreMemberAdmin)
