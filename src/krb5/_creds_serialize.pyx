import typing

from krb5._exceptions import Krb5Error

from krb5._context cimport Context
from krb5._creds cimport Creds
from krb5._krb5_types cimport *

cdef extern from "python_krb5.h":
    krb5_error_code krb5_marshal_credentials(
        krb5_context context,
        krb5_creds *creds_in,
        krb5_data **data_out
    ) nogil

    krb5_error_code krb5_unmarshal_credentials(
        krb5_context context,
        const krb5_data *data,
        krb5_creds **creds_out
    ) nogil

    void krb5_free_data(
        krb5_context context,
        krb5_data *val
    )

    void krb5_free_creds(
        krb5_context context,
        krb5_creds *creds
    )

cdef class CredsPtr:
    cdef Context ctx
    cdef krb5_creds *raw
    cdef int needs_free

    def __cinit__(CredsPtr self, Context context):
        self.ctx = context
        self.raw = NULL
        self.needs_free = 0

    def __dealloc__(CredsPtr self):
        if self.needs_free and self.raw:
            krb5_free_creds(self.ctx.raw, self.raw)
            self.needs_free = 0
            self.raw = NULL

    def __str__(CredsPtr self) -> str:
        return "CredsPtr"

def marshal_credentials(
    Context context not None,
    Creds creds not None
) -> bytes:
    cdef krb5_error_code err = 0
    cdef krb5_data *data_ptr = NULL

    with nogil:
        err = krb5_marshal_credentials(
            context.raw,
            &creds.raw,
            &data_ptr
        )

    if err:
        raise Krb5Error(context, err)

    try:
        data = data_ptr[0]
        buf = data.data
        len = data.length
        return <bytes>(buf[:len])

    finally:
        krb5_free_data(context.raw, data_ptr)

def unmarshal_credentials(
    Context context not None,
    const unsigned char[:] data not None
)->CredsPtr:
    cdef krb5_error_code err = 0;
    cdef krb5_data buf;

    pykrb5_set_krb5_data(&buf, len(data), <char *>&data[0])
    creds = CredsPtr(context)

    err = krb5_unmarshal_credentials(
        context.raw,
        &buf,
        &creds.raw
    )

    if err:
        raise Krb5Error(context, err)

    creds.needs_free = 1
    return creds
