from typing import Optional

from pydantic import BaseModel, Extra, Field, StrictStr


class Certificate(BaseModel):
    """Represent a Certificate."""

    cert_type: StrictStr
    common_name: StrictStr
    cert: StrictStr
    key: StrictStr


class Data(BaseModel, extra=Extra.allow):
    """Databag from the relation."""

    ca: StrictStr = Field(alias="ca")
    chain: Optional[StrictStr] = Field(default=None, alias="chain")
    client_cert: StrictStr = Field(alias="client.cert")
    client_key: StrictStr = Field(alias="client.key")
