from pydantic import BaseModel, EmailStr, constr, HttpUrl, conint, validator, Field

class ShortenedUrl(BaseModel):
    short_url: str
    original_url: str