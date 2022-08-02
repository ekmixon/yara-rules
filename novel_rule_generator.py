#!/usr/bin/env python
import re
import sys
YARA_TEMPLATE = """
    rule {rule_name}
    {{
        strings:
        {string_defs}
        condition:
            any of them
    }}
"""
if len(sys.argv) != 3:
    sys.exit(f"usage: {sys.argv[0]} RULE_NAME INPUT")
strings = []
with open(sys.argv[2], "r") as fp:
    strings.extend(
        "$s%d = /%s/" % (number, re.escape(line.strip()))
        for number, line in enumerate(fp)
    )

print(YARA_TEMPLATE.format(rule_name=sys.argv[1], string_defs="\n\t".join(strings)))
