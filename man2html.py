#!/usr/bin/env python
# Use this script to convert Bit-Twist manual pages in doc/ directory to HTML files.
# Reuse venv from tests/ directory to run this script.

import subprocess

manuals = [
    ("bittwist", "pcap based ethernet packet generator"),
    ("bittwiste", "pcap capture file editor"),
]

for name, description in manuals:
    command = f"/usr/bin/groff -man -T ascii doc/{name}.1 | /usr/bin/col -bx"
    output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
    output = output.decode("utf-8")
    output = output.replace("<ayeowch@gmail.com>", "&lt;ayeowch@gmail.com&gt;")
    output = output.strip()
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{name}.1</title>
    <meta name="description" content="{name} -- {description}">
</head>
<body>
<pre>
{output}
</pre>
</body>
</html>
"""
    with open(f"doc/{name}.1.html", "w") as f:
        f.write(html)
