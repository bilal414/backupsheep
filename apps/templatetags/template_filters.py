from django import template
from django.utils.html import json_script
from django.template.defaultfilters import default

register = template.Library()
from django.utils.safestring import mark_safe


@register.filter
def jsonify(value):
    return json_script(default(value))


@register.filter
def value_to_strong(value):
    return mark_safe(f"'{value}'")
