from sqlalchemy import Column,Integer,String,Text,DateTime,Boolean
from datetime import datetime
from app.database.db import Base

class Analysis(Base):
    __tablename__='analyses'
    id=Column(Integer,primary_key=True)
    kind=Column(String(40),nullable=False)
    title=Column(String(120),default='Analysis')
    risk_score=Column(Integer,default=0)
    risk_level=Column(String(20),default='LOW')
    threat_type=Column(String(120),default='Unknown')
    summary=Column(Text,default='')
    created_at=Column(DateTime,default=datetime.utcnow)

class Feedback(Base):
    __tablename__='feedback'
    id=Column(Integer,primary_key=True)
    analysis_id=Column(Integer,nullable=True)
    helpful=Column(Boolean,nullable=False)
    issue=Column(String(80),nullable=True)
    created_at=Column(DateTime,default=datetime.utcnow)
