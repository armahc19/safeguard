"""
SafeGuard - text chat with a Conversation Manager

Setup:
    pip install -r requirements.txt
    export GROQ_API_KEY="your_key_here"
    python app.py
"""

import copy
import asyncio
import json
import os
import gradio as gr
import httpx
from groq import Groq
from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from types import SimpleNamespace
from backend.app.services.awareness_gradio import create_awareness_gradio

MODEL = "openai/gpt-oss-120b"       # main conversation
RECENT_MESSAGES = 12                # raw messages sent to the model each turn
SAFEGUARD_API_URL = os.environ.get("SAFEGUARD_API_URL", "http://localhost:8000/v1").rstrip("/")
SAFEGUARD_ACCESS_TOKEN = os.environ.get("SAFEGUARD_ACCESS_TOKEN", "")

SYSTEM_PROMPT = """You are SafeGuard, a calm, friendly fraud-protection assistant for mobile money users in Ghana.
You talk with people the way a caring, knowledgeable friend would: natural, warm, and short.

How to talk:
- Reply in 1 to 3 short sentences, in plain words. Your replies may be read aloud later.
- Greetings and small talk get a normal friendly reply. Do not give a risk rating for "hi".
- If the person wants to report or check something but has not given details, ask ONE simple question,
  like "What happened? Did someone call or send you a message?"
- Ask only one question at a time. Never give a list of questions or instructions.
- Use the case notes you are given: connect new details to what is already known. Do not ask again
  for things the notes already contain.

When you have enough information to judge:
- Say plainly how worried you are (for example "This looks very risky" or "This seems fine") and why,
  in a sentence or two.
- Then tell them clearly what to do next, such as "Please do not dial that code. Call the official
  customer care line yourself to check."
- Use the words Low, Medium, High, or Critical risk only at this point, and only when it helps.

If someone is in the middle of a scam right now (about to send money, dial a code, or share a PIN or OTP),
be calm but direct: tell them to stop first, then explain.

Rules:
- NEVER ask for or accept a MoMo PIN, OTP, or password. If they offer one, tell them not to share it.
- Never say something is definitely fraud when the evidence is thin. Say "likely" or "possible".
- If the message looks harmless, say so calmly.
- Advise verifying through the provider's official customer care line, not numbers or links given by
  the caller or message.
- Do not accuse any named person based on weak evidence.
- If the person writes in Twi or mixes Twi and English, understand it and reply in the same way.
  If you are not sure you understood, say so and ask them to rephrase.
"""

EMPTY_NOTES = {
    "channel": "",
    "claimed_identity": "",
    "story": "",
    "requests_made": [],
    "signals": [],
    "user_actions_taken": [],
    "stage": "unclear",
    "risk": "Low",
    "confidence": "low",
}

INTELLIGENCE_EMPTY = {
    "context_summary": {},
    "evidence": {"positive": [], "negative": [], "missing": []},
    "retrieval": {"method": "", "candidate_count": 0},
    "evidence_validation": {},
    "claimed_identity": "",
    "requested_action": "",
    "detected_patterns": [],
    "behaviour_indicators": [],
    "similar_cases": [],
    "risk_level": "Low",
    "confidence": "low",
    "risk_evidence": [],
    "unknowns": [],
    "recommended_action": "Ask for more details before making a risk judgement.",
}


client = Groq(api_key=os.environ["GROQ_API_KEY"]) if os.environ.get("GROQ_API_KEY") else None


class ConversationManager:
    """Keeps the messages and the case notes for one session."""

    def __init__(self):
        self.messages = []                    # full list, shown in the UI
        self.notes = dict(EMPTY_NOTES)        # running case notes
        self.intelligence = copy.deepcopy(INTELLIGENCE_EMPTY)
        self.case_id = None
        self.context = {}
        self.backend_error = None

    def add(self, role, content):
        self.messages.append({"role": role, "content": content})

    def build_prompt(self):
        """System prompt + case notes + the most recent messages."""
        system = SYSTEM_PROMPT
        if self.notes != EMPTY_NOTES:
            system += "\n\nCase notes so far (trust these; they cover the whole conversation):\n"
            system += json.dumps(self.notes, ensure_ascii=False)
        if self.intelligence != INTELLIGENCE_EMPTY:
            system += "\n\nFraud Intelligence findings (use as evidence, not certainty):\n"
            system += json.dumps(self.intelligence, ensure_ascii=False)
        return [{"role": "system", "content": system}] + self.messages[-RECENT_MESSAGES:]

    def update_backend(self, message, access_token=None, channel="app"):
        """Send the turn to FastAPI; backend owns notes, retrieval and risk."""
        token = access_token or SAFEGUARD_ACCESS_TOKEN
        if not token:
            self.backend_error = "Set SAFEGUARD_ACCESS_TOKEN to connect the chat to SafeGuard API."
            return False
        try:
            response = httpx.post(
                f"{SAFEGUARD_API_URL}/conversation/turn",
                json={"message": message, "case_id": self.case_id, "channel": channel},
                headers={"Authorization": f"Bearer {token}"},
                timeout=20.0,
            )
            response.raise_for_status()
            payload = response.json()
            self.case_id = payload.get("case_id")
            self.context = payload.get("context", self.context)
            self.notes = payload.get("notes", self.notes)
            self.intelligence = payload.get("intelligence", self.intelligence)
            self.intelligence["intervention"] = payload.get("intervention", {})
            self.backend_error = None
            return True
        except (httpx.HTTPError, ValueError) as error:
            self.backend_error = f"SafeGuard API conversation analysis failed: {error}"
            return False


def generate_reply(manager):
    """Phrase backend findings for the user; backend remains the risk authority."""
    if client is None:
        return manager.intelligence.get("recommended_action", "Please verify through an official channel.")
    try:
        response = client.chat.completions.create(
            model=MODEL,
            messages=manager.build_prompt(),
            temperature=0.3,
            max_tokens=200,
        )
        return response.choices[0].message.content
    except Exception:
        return manager.intelligence.get("recommended_action", "Please verify through an official channel.")


def process_turn(message, manager, access_token=None, channel="app"):
    message = (message or "").strip()
    if not message:
        raise ValueError("Message cannot be empty.")
    manager.add("user", message)
    if not manager.update_backend(message, access_token=access_token, channel=channel):
        raise RuntimeError(manager.backend_error or "SafeGuard API is unavailable.")
    answer = generate_reply(manager)
    manager.add("assistant", answer)
    return answer


def respond(message, manager):
    message = (message or "").strip()
    if not message:
        return "", manager, manager.messages

    try:
        answer = process_turn(message, manager)
    except (RuntimeError, ValueError) as error:
        answer = str(error)
        manager.add("assistant", answer)
    return "", manager, manager.messages


def refresh_notes(manager):
    return manager, manager.notes, manager.intelligence


def reset():
    m = ConversationManager()
    return "", m, [], m.notes, m.intelligence



with gr.Blocks(title="SafeGuard") as demo:
    with gr.Tab("SafeGuard chat"):
        gr.Markdown("# SafeGuard\nTell me what happened. I'll help you check if it could be a scam.")

        manager_state = gr.State(ConversationManager())  # one private copy per browser session

        with gr.Row():
            with gr.Column(scale=3):
                chatbot = gr.Chatbot(type="messages", height=450)
                box = gr.Textbox(placeholder="Type here and press Enter...", show_label=False)
                new_chat = gr.Button("New conversation")
            with gr.Column(scale=2):
                notes_view = gr.JSON(value=EMPTY_NOTES, label="Case notes (what SafeGuard remembers)")
                intelligence_view = gr.JSON(value=INTELLIGENCE_EMPTY, label="Fraud Intelligence")

        box.submit(respond, [box, manager_state], [box, manager_state, chatbot]).then(
            refresh_notes, manager_state, [manager_state, notes_view, intelligence_view]
        )
        new_chat.click(reset, None, [box, manager_state, chatbot, notes_view, intelligence_view])

    with gr.Tab("Awareness campaigns"):
        create_awareness_gradio(SimpleNamespace(api_prefix="/v1")).render()



# Browser clients submit conversational SMS/text here. This Gradio-side adapter
# forwards the structured turn to FastAPI's canonical conversation pipeline.
app = FastAPI(title="SafeGuard Gradio Conversation Gateway")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)


@app.post("/api/turn")
async def gradio_turn(payload: dict, authorization: str | None = Header(default=None)):
    message = str(payload.get("message", "")).strip()
    if not message:
        raise HTTPException(status_code=422, detail="Message cannot be empty.")
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="A SafeGuard access token is required.")
    manager = ConversationManager()
    manager.case_id = payload.get("case_id")
    channel = payload.get("channel", "app")
    try:
        reply = await asyncio.to_thread(
            process_turn, message, manager, authorization.split(" ", 1)[1], channel
        )
    except (RuntimeError, ValueError) as error:
        raise HTTPException(status_code=502, detail=str(error)) from error
    return {
        "reply": reply,
        "case_id": manager.case_id,
        "notes": manager.notes,
        "intelligence": manager.intelligence,
    }


app = gr.mount_gradio_app(app, demo, path="/")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=7860)
