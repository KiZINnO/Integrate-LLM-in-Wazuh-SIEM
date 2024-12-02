from fastapi import FastAPI, Depends, Request, HTTPException
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from sqlalchemy import create_engine, Column, Integer, JSON, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from datetime import datetime
from pytz import timezone
import logging
import requests

# Define the timezone
ict = timezone('Asia/Bangkok')
bangkok_tz = timezone('Asia/Bangkok')

from ollama import Client
client = Client(host='http://localhost:11434')
OLLAMA_API_URL = "http://localhost:11434/api/generate" 

#Retrieve CVE info 
cve_id = "CVE-2024-3094"
url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
response = requests.get(url)
data = response.json()
nvd_response = data['vulnerabilities'][0]['cve']
if 'references' in nvd_response:
    del nvd_response['references']

# Database setup
SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class Alert(Base):
    __tablename__ = "alerts"
    id = Column(Integer, primary_key=True, index=True)
    alert_time = Column(DateTime, nullable=False)  # Timestamp when the log is received
    alert_data = Column(JSON)

# Create the database table
Base.metadata.create_all(bind=engine)

# Dependency to get the database session
def get_db():
    db = SessionLocal()
    try:
        yield db    
    finally:
        db.close()
db = SessionLocal()

app = FastAPI()
 #Mount the static files folder
app.mount("/static", StaticFiles(directory="static"), name="static")

# Set up templates folder
templates = Jinja2Templates(directory="templates")

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s")
logger = logging.getLogger(__name__)


# Serve the frontend (HTML)
@app.get("/")
async def root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


# Endpoint to receive Fluentbit logs
@app.post("/fluentbit")
async def receive_logs(request: Request, db: Session = Depends(get_db)):
    try:
        # Read raw JSON payload
        payload = await request.json()

        # Ensure the payload is a list
        if not isinstance(payload, list) or len(payload) == 0:
            raise HTTPException(status_code=400, detail="Payload must be a non-empty list of JSON objects")

        # Extract the first JSON object from the list
        payload_1 = payload[0]

        # Ensure payload is a list
        if not isinstance(payload_1, dict):
            raise HTTPException(status_code=400, detail="Expected a list of logs")
        
        if "date" in payload_1:
            del payload_1["date"]

            # Record the current time in Bangkok timezone
            alert_time = datetime.now(bangkok_tz)

            # Convert the log to a string representation (you can format it differently if needed)
            alert_data = payload_1
            print(type(alert_data))

            # Log the processed data
            logger.info(f"Storing log: {alert_data}")

            # Save the log to the database
            db_alert = Alert(alert_time=alert_time, alert_data=alert_data)
            db.add(db_alert)

        db.commit()

        # Respond to Fluentbit with an acknowledgment
        return {"status": "success", "message": "Logs received and stored successfully"}

    except Exception as e:
        logger.error(f"Error processing log: {e}")
        raise HTTPException(status_code=400, detail="Invalid JSON format")


@app.get("/alerts")
def get_alerts(db: Session = Depends(get_db)):
    alerts = db.query(Alert).all()
    return alerts

@app.get("/alert/{alert_id}")
def get_alert_by_id(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        return {"error": "Alert not found"}

    #CVE retrieval alert doesn't contain full_log
    if "full_log" in alert.alert_data:
        # Prompt - 1
        # prompt = f"""You are assistant for SOC analyst. Help to explain the alert which is sent from Wazuh SIEM system. 
        # ID: {alert.id}, Log: {alert.alert_data}"""
    
        
        # Prompt - 2
        prompt = f"""Please explain the security incident and how to fix it.
        ID : {alert.id},
        Log : {alert.alert_data}"""

        # Prompt -3
        # prompt = f"""Analyze the following alert data to assist a Tier 1 SOC analyst. If the alert includes CVE information, retrieve its details, 
        # explain the CVE's potential impact, and suggest remediation steps using the latest data from the NVD database. 
        # ID: {alert.id}, Log: {alert.alert_data}"""
   
    else:
        # Prompt - 1
        # prompt = f"""You are assistant for SOC analyst. Help to explain the alert which is sent from Wazuh SIEM system.
        # ID: {alert.id}, Log: {alert.alert_data}, Extract CVE info from NVD Database: {nvd_response}"""
        
        # Prompt - 2
        prompt = f"""Please explain the security incident and how to fix it.
        ID : {alert.id},
        Log : {alert.alert_data},
        Extract CVE info from NVD Database : {nvd_response}"""

        # Prompt - 3 
        # prompt = f"""Analyze the following alert data to assist a Tier 1 SOC analyst. If the alert includes CVE information, retrieve its details, 
        # explain the CVE's potential impact, and suggest remediation steps using the latest data from the NVD database. 
        # ID: {alert.id}, Log: {alert.alert_data}, Extract CVE info from NVD Database: {nvd_response}"""
    
    # return prompt
    data = client.chat(model='llama3.1:latest', messages=[
        {
            'role': 'user',
            'content': prompt
        },
    ])
    return data['message']['content']
    




