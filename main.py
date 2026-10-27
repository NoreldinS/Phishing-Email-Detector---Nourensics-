from fastapi import FastAPI
from pydantic import BaseModel #helps fastapi check incoming data is correct type
from detector import pipeline #connects API to the detector.py file so that the API can use the pipeline function from detector.py
from fastapi.middleware.cors import CORSMiddleware


app = FastAPI() #puts FastAPI into variable called "app"

# COR middleware configuration to allow requests from the website 
app.add_middleware(
    CORSMiddleware,
     allow_origins=[
        "http://127.0.0.1:5500",
        "http://localhost:5500"
    ],
    allow_credentials=False,
    allow_methods=["POST"],
    allow_headers=["Content-Type"]
)

class EmailClass(BaseModel):
    sender: str #must contain a string
    body: str
    subject: str
    hiddenURL: str = ""

#when user sends a post request with his email data,  analyse method will be called and it will check the data is correct type and return the data back to user
@app.post("/analyse")
def analyse(posted_email: EmailClass): #posted email stores all data posted by user 
    email_reasons, url_reasons, risk, risk_score, bayes_result = pipeline(posted_email.sender, posted_email.body, posted_email.subject, posted_email.hiddenURL)  #returns a dictionary with all results to be viewed by the user in the API response

    return {    
        "email_reasons": email_reasons, #shows all the reasons why the email is considered suspicious
        "url_reasons": url_reasons, #shows all the reasons why the urls in the email are considered suspicious
        "risk": risk, #shows the overall risk level of the email based on the total score
        "risk_score": risk_score ,#shows the numerical score representing the risk level
        "bayes_result": bayes_result
    }
 