from collections import Iterable


def get_attr_mult(obj, attr):
    attrs = attr.split("__", 1)
    if isinstance(obj, dict):
        value = obj.get(attrs[0])
    else:
        value = getattr(obj, attrs[0])
    if len(attrs) == 1:
        return value
    return get_attr_mult(value, attrs[1])


def remove_items(ls1, ls2):
    return list(set(ls1) - set(ls2))


class PermissionLogic(object):
    owner = None
    profile = "profile"
    groups = None
    default_group = "anonymous"
    allowable_actions = None
    base_actions = []
    permission_vars = None

    def __init__(self, request, instance, **kwargs):
        self.instance = instance
        self.request = request
        self.user = request.user
        self.kwargs = kwargs
        self.group = self.get_group()
        self.actions = self.scrub()

    def get_class_attr(self, attr):
        return get_attr_mult(self, attr)

    def get_profile(self):
        if self.profile:
            return getattr(self.user, self.profile, None)
        return self.user

    def get_group(self):
        profile = self.get_profile()
        if profile == getattr(self.instance, self.owner, None):
            return "owner"
        else:
            for group in self.groups:
                group_set = getattr(self.instance, group, [])
                if not isinstance(group_set, Iterable):
                    group_set = group_set.all()
                if profile in group_set:
                    return group
        return self.default_group

    def get_actions(self):
        actions = self.base_actions
        if self.group and self.allowable_actions:
            actions += self.allowable_actions.get(self.group, [])
        return actions

    def get_permission_vars(self):
        permission_vars = []
        profile = self.get_profile()
        for var in self.permission_vars:
            val = getattr(self.instance, var, None)
            if callable(val):
                val = val(profile)
            permission_vars.append(val)

        return permission_vars

    def remove_items(self, attr_name, items_to_remove):
        new_value = getattr(self, attr_name, [])
        if items_to_remove == "__all__":
            new_value = []
        elif isinstance(items_to_remove, list):
            new_value = [x for x in new_value if x not in items_to_remove]
        setattr(self, attr_name, new_value)

    def scrub(self):
        return self.get_actions()

    def has_perm(self, action):
        return action in self.actions
