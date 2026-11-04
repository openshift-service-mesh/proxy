"""Shared dependency-injection helpers for Envoy registry modules.

This file is duplicated verbatim across the Envoy librdkafka/grpc/protobuf
modules. Keep the copies identical so they can be consolidated later.
"""

def envoy_value(tag, name):
    return getattr(tag, name, None)


def envoy_module_id(mod):
    if mod.version:
        return "%s@%s" % (mod.name, mod.version)
    return mod.name


def _canonical_label(label):
    if label == None:
        return None
    return str(label)


def _pick_one(extension_name, attr_name, values):
    chosen = None
    chosen_module = None
    chosen_canonical = None
    for module_name, label in values:
        if label == None:
            continue
        canonical = _canonical_label(label)
        if chosen == None:
            chosen = label
            chosen_module = module_name
            chosen_canonical = canonical
            continue
        if chosen_canonical != canonical:
            fail(
                "Conflicting %s.deps(%s=...) labels from modules %s (%s) and %s (%s)." % (
                    extension_name,
                    attr_name,
                    chosen_module,
                    chosen_canonical,
                    module_name,
                    canonical,
                ),
            )
    return chosen


def envoy_pick(extension_name, attr_name, root_values, non_root_values, default):
    chosen = _pick_one(extension_name, attr_name, root_values)
    if chosen != None:
        return chosen
    chosen = _pick_one(extension_name, attr_name, non_root_values)
    if chosen != None:
        return chosen
    return default
