The architecture must support:
- Smartphone users.
- Yam-phone users.
- Shared fraud intelligence.
- AI-powered threat analysis.
- Transaction risk assessment.


SafeGuard Platform Architecture
* Interface layer (Two access channels · One intelligence platform)

1) SafeGuard Smart
Android application
- SMS analysis
- Call safety 
- Reporting 
- Risk checks

2) SafeGuard Lite
Feature phone
- USSD
- SMS 
- Number lookup 
- Scam reporting


* Communication Layer
REST API · USSD Gateway · SMS Gateway


* SafeGuard Backend — FastAPI
- Fraud Intelligence
  Threat data and reports
- Intelligent Shield
  AI threat analysis
- Transaction Intelligence
  Recipient and behaviour risk
- Notification Engine
  Warnings and responses

* Shared Intelligence Engine
Correlation · Risk scoring · Verification · Classification

* Fraud Intelligence Repository (FIR)
  Unified report index · Incidents · Evidence · Extracted entities · Findings · Assessments · Investigation history

* Data Layer
	- PostgreSQL
		Users, reports, threats, risk records
	- Redis
		Caching, rate limits, short-lived sessions

FIR indexes both report intake paths and connects them to shared incidents.
Reports and incidents are many-to-many: one submission may describe several
events, and each event can accumulate reports from different users or channels.
The source report remains auditable while assessments and investigation actions
are appended as history.

Report descriptions flow through the shared Fraud Intelligence Orchestrator.
Its pattern matches, identity analysis, behaviour-model signals, and risk snapshot
are attached to the corresponding FIR report and incident with source and model
version. Transaction-history behaviour remains attached to the user's own
transaction assessment rather than being attributed to an incident subject.

### Prototype request routing

Typed messages and pasted SMS from SafeGuard Smart and SafeGuard Lite pass
through the in-process conversation adapter at
`POST /v1/conversation/adapter-turn`. The adapter runs in the same FastAPI
process and delegates to the canonical conversation pipeline, which returns
case context, interpreted communication, intelligence, risk, and intervention.
There is no separate Gradio service or port in this browser request path. The
standalone Gradio UI in `app.py` is optional and is not required to run Smart or
Lite.

Explicit actions such as number lookup, transaction assessment, and scam
reporting call FastAPI directly. Voice and transcription are outside the
current prototype scope.



### High-Level Overview ####
SafeGuard is designed as a hybrid multi-channel system with three main layers:

    * Client Layer (how users interact)
    * Intelligence & Processing Layer (the brain)
    * Data & Storage Layer (the memory)


- Two(2) types of users:
   - Smartphone users → Full mobile app
   - Yam phone users → USSD + SMS

   

                 [ USERS ]
                     |
          +----------+----------+
          |                     |
    Smartphone App          Yam Phone
          |                 USSD / SMS
          |                     |
          +----------+----------+
                     |
             [ API GATEWAY ]
                     |
          +----------+----------+
          |          |          |
       Mobile      USSD       SMS
        API       Gateway    Gateway
          |          |          |
          +----------+----------+
                     |
              [ CORE SERVICES ]
                     |
     +---------------+----------------+
     |               |                |
     ▼               ▼                ▼
 FRAUD           INTELLIGENT       TRANSACTION
 INTELLIGENCE       SHIELD         INTELLIGENCE
     |               |                |
     |          +----+-----+          |
     |          |          |          |
     |       SMS         SafeCall      |
     |     Analyzer       Guard        |
     |                              |
     +---------------+--------------+
                     |
             [ RISK ENGINE ]
                     |
             [ SHARED FRAUD DB ]
                     |
       +-------------+-------------+
       |             |             |
   Scam Numbers  Fraudulent     Scam
                 SMS & Links    Patterns
                     |
                 Risk Scores



. Detailed Components

A. Client Layer

Smartphone App

    Message interception / notification listener
    SafeCall Guard (microphone access only when user activates it)
    Transaction risk checker
    Report scam button
    Clear warning UI

Yam Phone

    USSD menu (e.g. *XYZ#)
        Check number
        Report scam
        Pre-transfer safety check
    SMS short code
        Forward suspicious message
        Receive risk alerts

B. Core Services

    Fraud Intelligence Service
        Receives reports from users
        Stores and updates scam numbers, messages, links, and patterns
        Calculates basic risk scores
        Shares data with other services

    Intelligent Shield Service
        Message Analyzer: Scans incoming SMS for scam patterns using AI/rules
        SafeCall Guard:
            Only activates when user presses “Protect this call”
            Works only on unknown numbers
            Uses on-device or cloud speech-to-text + keyword/pattern detection
            Triggers real-time alert if high-risk language is detected

    Transaction Intelligence Service
        Checks recipient number against fraud database
        Analyses transaction patterns (amount, frequency, new recipient, etc.)
        Returns risk level + simple safety advice

C. Data Layer

    Central Fraud Database (can start with a simple cloud database)
    User reports
    Risk scores and patterns
    Basic analytics

One backend. One shared intelligence network. Two access channels. Three protection layers.
