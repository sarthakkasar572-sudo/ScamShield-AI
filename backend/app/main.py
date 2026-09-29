from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.database.db import Base,engine
from app.api.routes import router

Base.metadata.create_all(bind=engine)
app=FastAPI(title='ScamShield AI API',version='1.0.0',description='Defensive, explainable digital safety assistant')
app.add_middleware(CORSMiddleware,allow_origins=['http://localhost:5173'],allow_credentials=True,allow_methods=['*'],allow_headers=['*'])
app.include_router(router)
@app.get('/health')
def health(): return {'status':'ok','service':'ScamShield AI'}
