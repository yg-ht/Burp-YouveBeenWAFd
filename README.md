# Burp WAF Detector

This project is a Python/Jython Burp extension that passively identifies WAF
indicators and performs safe, explicitly requested active probes.

The first milestone contains the shared, Burp-independent rule and confidence
engine. Burp integration is being added incrementally so the detection logic
can be regression-tested without a running Burp instance.

Python extensions require a configured Jython standalone JAR in Burp's Python
environment. The legacy Extender API is used because it is the current route
for Python extensions; it is no longer actively maintained by PortSwigger.
