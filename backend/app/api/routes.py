from fastapi import APIRouter,Depends,UploadFile,File,HTTPException
from sqlalchemy.orm import Session
from datetime import datetime
from app.database.db import get_db
from app.models.models import Analysis,Feedback
from app.schemas.schemas import TextRequest,URLRequest,FeedbackRequest,IncidentRequest
from app.services.risk_engine import analyze_message,analyze_url
import io

router=APIRouter(prefix='/api')

def save(db,kind,result,title='Analysis'):
    row=Analysis(kind=kind,title=title,risk_score=result.get('risk_score',0),risk_level=result.get('risk_level','LOW'),threat_type=result.get('threat_type','Unknown'),summary=' '.join(result.get('indicators',[])[:2]))
    db.add(row); db.commit(); db.refresh(row); result['analysis_id']=row.id; return result

@router.post('/analyze/message')
def message(req:TextRequest,db:Session=Depends(get_db)):
    return save(db,'message',analyze_message(req.text),'Message Analysis')

@router.post('/analyze/email')
def email(req:TextRequest,db:Session=Depends(get_db)):
    result=analyze_message(req.text)
    result['threat_type']='Potential Impersonation / '+result['threat_type']
    return save(db,'email',result,'Email Analysis')

@router.post('/analyze/url')
def url(req:URLRequest,db:Session=Depends(get_db)):
    return save(db,'url',analyze_url(req.url),'URL Analysis')

@router.post('/analyze/screenshot')
async def screenshot(file:UploadFile=File(...),db:Session=Depends(get_db)):
    if file.content_type not in ['image/png','image/jpeg','image/webp']:
        raise HTTPException(400,'Only PNG, JPEG, or WebP images are supported.')
    data=await file.read()
    if len(data)>5*1024*1024: raise HTTPException(413,'Image exceeds the 5 MB limit.')
    extracted=''
    try:
        from PIL import Image
        import pytesseract
        extracted=pytesseract.image_to_string(Image.open(io.BytesIO(data)))[:20000]
    except Exception:
        extracted='OCR engine unavailable in this environment. Demo fallback: no text extracted.'
    result=analyze_message(extracted) if extracted and not extracted.startswith('OCR engine unavailable') else {'risk_score':0,'risk_level':'LOW','threat_type':'OCR Unavailable','indicators':['OCR could not be completed. You can paste the message text into the Message Analyzer.'],'recommended_actions':['Do not interact with the content until it is independently verified.'],'confidence':'Low','disclaimer':'OCR output can contain recognition errors.'}
    result['extracted_text']=extracted
    return save(db,'screenshot',result,'Screenshot Analysis')

@router.post('/analyze/qr')
async def qr(file:UploadFile=File(...),db:Session=Depends(get_db)):
    if file.content_type not in ['image/png','image/jpeg','image/webp']:
        raise HTTPException(400,'Only PNG, JPEG, or WebP images are supported.')
    data=await file.read()
    if len(data)>5*1024*1024: raise HTTPException(413,'Image exceeds the 5 MB limit.')
    destination=None
    try:
        import cv2, numpy as np
        img=cv2.imdecode(np.frombuffer(data,np.uint8),cv2.IMREAD_COLOR)
        val,_,_=cv2.QRCodeDetector().detectAndDecode(img)
        destination=val or None
    except Exception: pass
    if destination:
        result=analyze_url(destination); result['qr_destination']=destination
    else:
        result={'risk_score':0,'risk_level':'LOW','threat_type':'QR Destination Not Extracted','indicators':['No QR destination could be extracted.'],'recommended_actions':['Do not scan/open the QR destination until you can verify where it leads.'],'confidence':'Low','disclaimer':'QR extraction can fail because of image quality or QR format.'}
    return save(db,'qr',result,'QR Analysis')

@router.post('/incident-response')
def incident(req:IncidentRequest):
    plans={
      'clicked':['Close the suspicious page.','Do not download or run anything it offered.','Run your device security scan if you downloaded a file.','Review browser downloads and account activity.'],
      'password':['Change the password immediately from the legitimate website/app.','Sign out of other sessions where possible.','Enable MFA.','Do not reuse the compromised password elsewhere.'],
      'otp':['Contact the affected service through an official channel if an account action occurred.','Review account activity and security settings.','Never share another OTP with the requester.'],
      'banking':['Contact your bank/payment provider using an official number or app.','Monitor transactions and follow the institution’s fraud-reporting process.','Preserve screenshots and transaction details.'],
      'download':['Do not open the downloaded file.','Delete/quarantine it using your security software.','Run a device security scan.','If executed, review accounts and device security promptly.'],
      'app':['Do not grant further permissions.','Uninstall suspicious apps if safe to do so.','Review accessibility/device-admin permissions.','Change important passwords from a trusted device if compromise is suspected.'],
      'payment':['Contact the bank/payment provider immediately through an official channel.','Preserve transaction IDs and screenshots.','Follow the provider’s fraud/dispute process.'],
      'unknown':['Stop interacting with the content.','Verify through an independent official channel.','If credentials or money may be affected, contact the relevant provider promptly.']}
    return {'action':req.action,'steps':plans.get(req.action,plans['unknown']),'warning':'Never enter passwords, OTPs, PINs, CVVs, or recovery codes into ScamShield AI.'}

@router.get('/history')
def history(db:Session=Depends(get_db)):
    rows=db.query(Analysis).order_by(Analysis.created_at.desc()).limit(30).all()
    return [{'id':r.id,'kind':r.kind,'title':r.title,'risk_score':r.risk_score,'risk_level':r.risk_level,'threat_type':r.threat_type,'created_at':r.created_at.isoformat()} for r in rows]

@router.get('/dashboard')
def dashboard(db:Session=Depends(get_db)):
    rows=db.query(Analysis).all(); total=len(rows); high=sum(r.risk_score>=50 for r in rows); critical=sum(r.risk_score>=75 for r in rows)
    return {'scans':total,'high_risk':high,'critical':critical,'phishing':sum('Phish' in r.threat_type for r in rows),'suspicious_urls':sum(r.kind=='url' for r in rows),'security_score':78,'recent':[{'title':r.title,'risk_level':r.risk_level,'score':r.risk_score,'threat':r.threat_type,'created_at':r.created_at.isoformat()} for r in sorted(rows,key=lambda x:x.created_at,reverse=True)[:5]]}

@router.post('/feedback')
def feedback(req:FeedbackRequest,db:Session=Depends(get_db)):
    db.add(Feedback(analysis_id=req.analysis_id,helpful=req.helpful,issue=req.issue)); db.commit(); return {'ok':True}
