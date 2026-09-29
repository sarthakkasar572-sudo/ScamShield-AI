from pydantic import BaseModel,Field
from typing import Optional

class TextRequest(BaseModel):
    text:str=Field(min_length=3,max_length=20000)
class URLRequest(BaseModel):
    url:str=Field(min_length=4,max_length=4000)
class FeedbackRequest(BaseModel):
    analysis_id:Optional[int]=None
    helpful:bool
    issue:Optional[str]=None
class IncidentRequest(BaseModel):
    action:str
