from django import template

register = template.Library()


@register.filter(name='split')
def split(value, key):
    return [x.strip() for x in value.split(key)]


@register.filter(name='none_or_never')
def none_or_never(value):
    return 'Never' if value is None else value


# https://stackoverflow.com/a/32801096
@register.filter
def next(some_list, current_index):
    """
    Returns the next element of the list using the current index if it exists.
    Otherwise returns an empty string.
    """
    try:
        return some_list[int(current_index) + 1] # access the next element
    except:
        return '' # return empty string in case of exception
