from pydantic import BaseModel, EmailStr, constr, HttpUrl, conint, validator, Field
from uuid import uuid4 as uuid

class SessionSchema(BaseModel):
    logged_in: bool
    