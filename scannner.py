import warnings
from scanner import scan_target

warnings.warn("scannner.py is deprecated, please import from scanner.py instead", DeprecationWarning, stacklevel=2)

def create_result(port, service, banner, software, version):
    warnings.warn("create_result is deprecated", DeprecationWarning, stacklevel=2)
    return {
        "port": port,
        "service": service,
        "banner": banner,
        "software": software,
        "version": version
    }