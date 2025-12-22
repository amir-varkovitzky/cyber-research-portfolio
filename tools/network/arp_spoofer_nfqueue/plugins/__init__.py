from .dns_spoof import DnsSpoofPlugin
from .http_redirect import HttpRedirectPlugin

ALL_PLUGINS = [
    DnsSpoofPlugin(),
    HttpRedirectPlugin(),
]
