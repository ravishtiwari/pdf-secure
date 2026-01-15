class SecurePDFException(Exception):
    pass


class SecurePDFPolicyException(SecurePDFException):
    pass


class SecurePDFReceiptException(SecurePDFException):
    pass


class SecurePDFEngineException(SecurePDFException):
    pass


class SecurePDFSDKException(SecurePDFException):
    pass
