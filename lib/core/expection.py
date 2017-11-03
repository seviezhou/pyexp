class PyExpBaseException(Exception):
    pass

class PyExpSystemException(PyExpBaseException):
    pass

class PyExpSyntaxException(PyExpBaseException):
    pass

class PyExpFileNotFoundException(PyExpBaseException):
    pass