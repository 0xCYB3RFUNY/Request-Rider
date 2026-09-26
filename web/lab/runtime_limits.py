"""Runtime configuration compatibility module.

RequestRider does not impose application-level runtime limits. Historical
environment-backed caps were removed; user-controlled values are passed through
without upper-bound truncation.
"""
