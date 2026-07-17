from django import template
from django.utils.html import json_script
from django.template.defaultfilters import default

register = template.Library()


@register.filter
def jsonify(value):
    return json_script(default(value))
