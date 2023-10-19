from typing import Optional

from pydantic import BaseModel, Extra, Field, StrictStr


class Certificate(BaseModel):
    """Represent a Certificate."""

    cert_type: StrictStr
    common_name: StrictStr
    cert: StrictStr
    key: StrictStr

    def __init__(self, cert_type, common_name, cert, key, chain=None):
        if chain:
            cert += "\n" + chain
        super().__init__(
            cert_type=cert_type, common_name=common_name, cert=cert, key=key
        )


class Data(BaseModel, extra=Extra.allow):
    """Databag from the relation."""

    ca: StrictStr = Field(alias="ca")
    chain: Optional[StrictStr] = Field(default=None, alias="chain")
    client_cert: StrictStr = Field(alias="client.cert")
    client_key: StrictStr = Field(alias="client.key")
