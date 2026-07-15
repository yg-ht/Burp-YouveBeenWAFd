# Burp WAF Detector

This project is a Python/Jython Burp extension that passively identifies WAF
indicators and performs safe, explicitly requested active probes.

The first milestone contains the shared, Burp-independent rule and confidence
engine. Burp integration is being added incrementally so the detection logic
can be regression-tested without a running Burp instance.

Active probe definitions live in [`rules/probes.json`](rules/probes.json), not
in the execution code. Each entry records its provider associations and
expected actions. The planner always uses the selected request as the control,
changes only the selected insertion point, and performs raw-value encoding via
Burp's insertion-point API. The default traversal probe targets a deliberately
non-existent marker rather than a real sensitive file.

Python extensions require a configured Jython standalone JAR in Burp's Python
environment. The legacy Extender API is used because it is the current route
for Python extensions; it is no longer actively maintained by PortSwigger.
