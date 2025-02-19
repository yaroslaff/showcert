class CertException(Exception):
    pass

class InvalidCertificate(CertException):
    pass

class InvalidAddress(CertException):
    pass

class ServerError(CertException):
    pass
