"""Static mapping from vulnforge attack_type labels to CWE IDs.

These are broad-class mappings, not precise. The intent is to surface related
CVEs from the offline database, not to assert a definitive CWE classification.
"""

ATTACK_TYPE_TO_CWES: dict[str, list[str]] = {
    "sql_injection": ["CWE-89"],
    "code_execution": ["CWE-78", "CWE-94", "CWE-95"],
    "path_traversal": ["CWE-22"],
    "xss": ["CWE-79"],
    "buffer_overflow": ["CWE-120", "CWE-122"],
    "dos": ["CWE-400"],
    "ssrf": ["CWE-918"],
    "logical": ["CWE-840"],
    "command_injection": ["CWE-78"],
    "open_redirect": ["CWE-601"],
    "deserialisation": ["CWE-502"],
    "format_string": ["CWE-134"],
    "integer_overflow": ["CWE-190"],
    "use_after_free": ["CWE-416"],
    "race_condition": ["CWE-362"],
}
