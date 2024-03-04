from pydantic import BaseModel, EmailStr, constr, HttpUrl, conint, validator, Field


class LoginUserSchema(BaseModel):
    email: EmailStr
    password: constr(min_length=2, max_length=128) # type: ignore

class SignUPUserSchema(BaseModel):
    username: constr(min_length=2, max_length=50) # type: ignore
    email: EmailStr
    password: constr(min_length=3, max_length=128) # type: ignore