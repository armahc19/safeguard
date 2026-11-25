"""Runtime knowledge base and explainable fraud intelligence.

The JSON artifacts remain the source of truth. This module builds lightweight
inverted indexes at startup and turns conversation notes into evidence-backed
candidate findings. It deliberately returns uncertainty instead of declaring
that a person or number is fraudulent.
"""

import math
import os
import re
import warnings
from collections import defaultdict
from pathlib import Path


RISK_ORDER = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}
MATCH_STOPWORDS = {
    "account", "wallet", "action", "request", "requested", "asked", "caller",
    "customer", "message", "provider", "support", "service", "official", "target",
    "person", "user", "information", "transaction", "conversation", "process", "call",
    "contact", "using", "used", "direct", "directed", "instructions", "claim", "claims",
}
HIGH_SIGNAL_TERMS = {
    "otp", "pin", "password", "passcode", "blocked", "blocking", "refund", "mistaken",
    "prize", "bonus", "reward", "urgent", "urgency", "deadline", "family", "friend",
    "relative", "verification", "verify", "secret", "cashout", "cash-out", "sim",
}


def tokenize(value):
    return {
        token for token in re.findall(r"[a-z0-9]+", str(value).lower())
        if len(token) > 2
    }


def meaningful_overlap(left, right):
    overlap = tokenize(left) & tokenize(right)
    meaningful = overlap - MATCH_STOPWORDS
    signal = meaningful & HIGH_SIGNAL_TERMS
    return meaningful, signal


def text_from_notes(notes, messages):
    fields = [
        notes.get("channel", ""),
        notes.get("claimed_identity", ""),
        notes.get("story", ""),
        notes.get("stage", ""),
        " ".join(notes.get("requests_made", [])),
        " ".join(notes.get("signals", [])),
        " ".join(notes.get("user_actions_taken", [])),
        " ".join(item.get("content", "") for item in messages[-6:]),
    ]
    return " ".join(fields)


def build_context_summary(notes, messages):
    """Create the handoff from Conversation Intelligence to Fraud Intelligence."""
    evidence = list(notes.get("signals", []))
    evidence.extend(notes.get("user_actions_taken", []))
    recent_user_messages = [
        item.get("content", "") for item in messages[-6:]
        if item.get("role") == "user"
    ]
    return {
        "channel": notes.get("channel", ""),
        "claimed_identity": notes.get("claimed_identity", ""),
        "story": notes.get("story", ""),
        "requested_actions": list(notes.get("requests_made", [])),
        "user_actions_taken": list(notes.get("user_actions_taken", [])),
        "signals": evidence,
        "stage": notes.get("stage", "unclear"),
        "known_facts": [notes.get("story", "")] if notes.get("story") else [],
        "unknowns": [
            label for label, value in (
                ("claimed identity", notes.get("claimed_identity")),
                ("requested action", notes.get("requests_made")),
            ) if not value
        ],
        "recent_user_messages": recent_user_messages,
        "search_text": text_from_notes(notes, messages),
    }


def extract_evidence(context):
    """Separate what supports concern from what weakens it or is unknown."""
    search_text = context.get("search_text", "").lower()
    positive = []
    negative = []
    missing = list(context.get("unknowns", []))

    if context.get("claimed_identity"):
        positive.append(f"The other party claims to be {context['claimed_identity']}.")
    if context.get("requested_actions"):
        positive.append("A specific action was requested: " + "; ".join(context["requested_actions"]) + ".")
    if context.get("signals"):
        positive.extend(context["signals"][:5])
    if context.get("user_actions_taken"):
        positive.append("The user reports that an action may already have been taken.")

    high_risk_terms = ("otp", "pin", "password", "passcode", "send money", "transfer", "dial", "ussd")
    for term in high_risk_terms:
        if term in search_text:
            positive.append(f"The conversation contains the high-risk term or action: {term}.")

    reassuring_phrases = (
        "official app", "official channel", "independently verified", "checked the balance",
        "checked transaction history", "refused to share", "no request for otp",
        "no request for pin", "normal procedure", "known relative",
    )
    for phrase in reassuring_phrases:
        if phrase in search_text:
            negative.append(f"The conversation contains reassuring evidence: {phrase}.")
    if not context.get("requested_actions"):
        negative.append("No requested action has been established.")
    if not context.get("user_actions_taken"):
        negative.append("No harmful user action has been established.")
    if not context.get("claimed_identity"):
        missing.append("The other party's identity is unknown.")
    if not context.get("requested_actions"):
        missing.append("The requested action is unknown.")

    return {
        "positive": list(dict.fromkeys(positive)),
        "negative": list(dict.fromkeys(negative)),
        "missing": list(dict.fromkeys(missing)),
    }


class TrainedMultiLabelClassifier:
    """Adapter for SafeGuard's joblib TF-IDF + one-vs-rest classifiers."""

    def __init__(self, path):
        self.path = str(path)
        self.available = False
        self.error = None
        self.version = None
        self.labels = []
        self.vectorizer = None
        self.models = {}
        try:
            import joblib
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                bundle = joblib.load(path)
            self.vectorizer = bundle["vectorizer"]
            self.models = bundle["models"]
            self.labels = list(bundle.get("classes", self.models.keys()))
            self.version = bundle.get("version")
            self.available = True
        except Exception as exc:
            self.error = f"{type(exc).__name__}: {exc}"

    def predict(self, text, threshold=0.5):
        if not self.available:
            return []
        matrix = self.vectorizer.transform([text])
        predictions = []
        for label in self.labels:
            model = self.models[label]
            probabilities = model.predict_proba(matrix)[0]
            classes = list(model.classes_)
            probability = float(probabilities[classes.index(1)]) if 1 in classes else 0.0
            predictions.append({
                "id": label,
                "probability": round(probability, 4),
                "threshold": threshold,
                "selected": probability >= threshold,
            })
        return sorted(predictions, key=lambda item: item["probability"], reverse=True)


class FraudKnowledgeBase:
    """Searchable view over the taxonomy, cases, and their relationships."""

    def __init__(self, taxonomy, cases_bundle):
        self.taxonomy = taxonomy
        self.patterns = {item["id"]: item for item in taxonomy["fraud_patterns"]}
        self.tactics = {item["id"]: item for item in taxonomy["behaviour_tactics"]}
        self.cases = {
            item["case_id"]: item
            for item in cases_bundle.get("case_evidence_records", [])
        }
        self.pattern_index = self._build_index(self.patterns.values(), self._pattern_text)
        self.tactic_index = self._build_index(self.tactics.values(), self._tactic_text)
        self.case_index = self._build_index(self.cases.values(), self._case_text)
        self.case_tokens = {
            case_id: tokenize(self._case_text(case))
            for case_id, case in self.cases.items()
        }
        document_frequency = defaultdict(int)
        for tokens in self.case_tokens.values():
            for token in tokens:
                document_frequency[token] += 1
        self.case_idf = {
            token: math.log((1 + len(self.cases)) / (1 + count)) + 1
            for token, count in document_frequency.items()
        }
        self.case_vectors = {
            case_id: self._vector(tokens) for case_id, tokens in self.case_tokens.items()
        }
        self.semantic_model = None
        self.semantic_embeddings = None
        self.semantic_status = "not_loaded"
        self.semantic_model_name = os.environ.get(
            "SAFEGUARD_EMBEDDING_MODEL", "all-MiniLM-L6-v2"
        )
        model_dir = Path(os.environ.get(
            "SAFEGUARD_MODEL_DIR", Path(__file__).resolve().parent / "models"
        ))
        self.pattern_classifier = TrainedMultiLabelClassifier(
            model_dir / "safeguard_pattern_classifier_v2.joblib"
        )
        self.behaviour_classifier = TrainedMultiLabelClassifier(
            model_dir / "safeguard_behaviour_classifier.joblib"
        )
        self.model_threshold = float(os.environ.get("SAFEGUARD_MODEL_THRESHOLD", "0.5"))

    @staticmethod
    def _build_index(records, text_builder):
        index = defaultdict(set)
        for record in records:
            for token in tokenize(text_builder(record)):
                index[token].add(record["id"] if "id" in record else record["case_id"])
        return dict(index)

    @staticmethod
    def _pattern_text(item):
        return " ".join([
            item.get("name", ""), item.get("definition", ""),
            " ".join(item.get("indicators", [])),
        ])

    @staticmethod
    def _tactic_text(item):
        return " ".join([
            item.get("name", ""), item.get("definition", ""),
            " ".join(item.get("observable_cues", [])),
        ])

    @staticmethod
    def _case_text(item):
        return " ".join([
            item.get("summary", ""), item.get("source_summary", ""),
            " ".join(item.get("channels", [])),
        ])

    def _vector(self, tokens):
        return {
            token: self.case_idf.get(token, 1)
            for token in set(tokens)
        }

    @staticmethod
    def _cosine(left, right):
        if not left or not right:
            return 0.0
        numerator = sum(value * right.get(token, 0.0) for token, value in left.items())
        left_norm = math.sqrt(sum(value * value for value in left.values()))
        right_norm = math.sqrt(sum(value * value for value in right.values()))
        return numerator / (left_norm * right_norm) if left_norm and right_norm else 0.0

    def _load_semantic_model(self):
        """Load the optional embedding backend lazily.

        The first run may download the configured model. If the dependency or
        model is unavailable, retrieval safely remains TF-IDF based.
        """
        if self.semantic_status != "not_loaded":
            return self.semantic_model is not None
        try:
            from sentence_transformers import SentenceTransformer
            self.semantic_model = SentenceTransformer(self.semantic_model_name)
            texts = [self._case_text(self.cases[case_id]) for case_id in self.cases]
            self.semantic_embeddings = self.semantic_model.encode(
                texts, normalize_embeddings=True, convert_to_numpy=True
            )
            self.semantic_status = "available"
        except Exception as exc:
            self.semantic_status = f"unavailable: {type(exc).__name__}"
            self.semantic_model = None
            self.semantic_embeddings = None
        return self.semantic_model is not None

    def _match(self, query, records, text_builder, minimum=0.28):
        query_tokens = tokenize(query)
        matches = []
        for record in records:
            record_tokens = tokenize(text_builder(record))
            overlap = query_tokens & record_tokens
            # Compare against the shorter side. Taxonomy records are verbose,
            # while real user messages are usually only one or two sentences.
            score = len(overlap) / max(min(len(query_tokens), len(record_tokens)), 1)
            # Requiring two shared words prevents common words such as “account”
            # from producing a finding on their own.
            if len(overlap) >= 2 and score >= minimum:
                matches.append((score, overlap, record))
        return sorted(matches, key=lambda item: item[0], reverse=True)

    def search_cases(self, query, limit=3):
        """Retrieve cases with semantic embeddings, falling back to TF-IDF."""
        query_vector = self._vector(tokenize(query))
        tfidf_scores = {}
        for case_id, vector in self.case_vectors.items():
            tfidf_scores[case_id] = self._cosine(query_vector, vector)

        semantic_scores = {}
        method = "tfidf_vector_cosine_initial"
        if self._load_semantic_model():
            query_embedding = self.semantic_model.encode(
                [query], normalize_embeddings=True, convert_to_numpy=True
            )[0]
            # Embeddings are normalized, so dot product is cosine similarity.
            for index, case_id in enumerate(self.cases):
                semantic_scores[case_id] = float(
                    query_embedding.dot(self.semantic_embeddings[index])
                )
            method = "semantic_embedding_plus_tfidf"

        ranked = []
        for case_id, case in self.cases.items():
            semantic_score = semantic_scores.get(case_id, 0.0)
            tfidf_score = tfidf_scores.get(case_id, 0.0)
            if semantic_scores:
                combined_score = (0.75 * semantic_score) + (0.25 * tfidf_score)
                threshold = 0.25
            else:
                combined_score = tfidf_score
                threshold = 0.12
            if combined_score >= threshold:
                ranked.append((combined_score, semantic_score, tfidf_score, case))
        self.last_retrieval = {
            "method": method,
            "embedding_model": self.semantic_model_name if semantic_scores else None,
            "semantic_status": self.semantic_status,
        }
        return [
            {
                "case_id": case["case_id"],
                "summary": case["summary"],
                "retrieval_score": round(score, 3),
                "semantic_score": round(semantic_score, 3),
                "tfidf_score": round(tfidf_score, 3),
                "verification_status": case.get("verification_status", ""),
                "fraud_pattern_ids": case.get("fraud_pattern_ids", []),
                "behaviour_tactic_ids": case.get("behaviour_tactic_ids", []),
            }
            for score, semantic_score, tfidf_score, case in sorted(
                ranked, reverse=True, key=lambda item: item[0]
            )[:limit]
        ]

    def detect_patterns(self, query, similar_cases=None):
        findings = []
        retrieved_pattern_ids = {
            pattern_id
            for case in similar_cases or []
            for pattern_id in case.get("fraud_pattern_ids", [])
        }
        candidates = [
            pattern for pattern in self.patterns.values()
            if not retrieved_pattern_ids or pattern["id"] in retrieved_pattern_ids
        ]
        for _, overlap, pattern in self._match(query, candidates, self._pattern_text, 0.08):
            matched_indicators = [
                indicator for indicator in pattern.get("indicators", [])
                if (
                    len(meaningful_overlap(query, indicator)[0]) >= 2
                    or meaningful_overlap(query, indicator)[1]
                )
            ]
            # A retrieved case can suggest a candidate, but it cannot validate
            # a pattern unless the current context supports an indicator.
            if len(matched_indicators) == 0:
                continue
            findings.append({
                "id": pattern["id"],
                "name": pattern["name"],
                "match_score": round(min(1.0, len(overlap) / 12), 2),
                "evidence": matched_indicators[:2] or [pattern["definition"]],
                "case_ids": pattern.get("case_ids", []),
                "retrieved_support": bool(retrieved_pattern_ids & {pattern["id"]}),
                "validated": True,
            })
        return findings[:4]

    def analyse_behaviour(self, query, similar_cases=None):
        findings = []
        retrieved_tactic_ids = {
            tactic_id
            for case in similar_cases or []
            for tactic_id in case.get("behaviour_tactic_ids", [])
        }
        candidates = [
            tactic for tactic in self.tactics.values()
            if not retrieved_tactic_ids or tactic["id"] in retrieved_tactic_ids
        ]
        for _, overlap, tactic in self._match(query, candidates, self._tactic_text, 0.08):
            cues = [
                cue for cue in tactic.get("observable_cues", [])
                if (
                    len(meaningful_overlap(query, cue)[0]) >= 2
                    or meaningful_overlap(query, cue)[1]
                )
            ]
            if not cues:
                continue
            findings.append({
                "id": tactic["id"],
                "name": tactic["name"],
                "evidence": cues[:2],
                "case_ids": tactic.get("case_ids", []),
                "retrieved_support": bool(retrieved_tactic_ids & {tactic["id"]}),
                "validated": True,
            })
        return findings[:4]

    def assess_risk(self, notes, patterns, behaviours, similar_cases, query, evidence_report=None):
        evidence = []
        unknowns = []
        score = 0
        lower = query.lower()
        requests = " ".join(notes.get("requests_made", [])).lower()
        actions = " ".join(notes.get("user_actions_taken", [])).lower()
        signals = notes.get("signals", [])

        confirmed_patterns = [item for item in patterns if item.get("validated")]
        confirmed_behaviours = [item for item in behaviours if item.get("validated")]
        if confirmed_patterns:
            score += 2
            evidence.append(f"{len(confirmed_patterns)} fraud pattern(s) have supporting evidence.")
        elif patterns:
            evidence.append("The classifier found candidate pattern(s), but evidence validation is incomplete.")
        if confirmed_behaviours:
            score += min(2, len(confirmed_behaviours))
            evidence.append(f"{len(confirmed_behaviours)} manipulation tactic(s) have observable cues.")
        if similar_cases:
            score += 1
            evidence.append("The account resembles documented case material; similarity is supporting evidence only.")
        if any(word in lower or word in requests for word in ("otp", "pin", "password", "passcode")):
            score += 3
            evidence.append("A credential or authentication secret is being requested or discussed.")
        if any(word in lower or word in requests for word in ("send money", "transfer", "refund", "dial", "ussd")):
            score += 2
            evidence.append("The conversation involves a potentially irreversible wallet action.")
        if actions:
            score += 3
            evidence.append("The user reports that an action may already have been taken.")
        if signals:
            evidence.extend(signals[:3])
        negative_evidence = (evidence_report or {}).get("negative", [])
        if negative_evidence and not actions and not any(
            term in lower for term in ("otp", "pin", "password", "passcode")
        ):
            score = max(0, score - min(3, len(negative_evidence)))
            evidence.append("Reassuring or contradictory evidence lowers the assessment.")
        if not patterns:
            unknowns.append("No documented fraud pattern has enough supporting evidence yet.")
        if not notes.get("claimed_identity"):
            unknowns.append("The other party's claimed identity is not established.")
        if not notes.get("requests_made"):
            unknowns.append("The requested action is not yet clear.")

        level = "Critical" if score >= 8 else "High" if score >= 5 else "Medium" if score >= 2 else "Low"
        supplied = notes.get("risk", "Low")
        if RISK_ORDER.get(supplied, 0) > RISK_ORDER[level]:
            level = supplied
        confidence = "high" if confirmed_patterns and confirmed_behaviours and evidence else "medium" if confirmed_patterns or similar_cases else "low"

        if level in {"High", "Critical"}:
            action = "Stop the interaction. Do not share a PIN or OTP or send money; verify through the provider's official channel."
        elif patterns:
            action = "Do not follow the request yet. Verify the claim independently through the provider's official channel."
        else:
            action = "Ask one more focused question before making a risk judgement."
        return level, confidence, evidence, unknowns, action

    def analyse(self, notes, messages):
        context_summary = build_context_summary(notes, messages)
        evidence = extract_evidence(context_summary)
        # Structured fields lead the analysis; recent messages remain available
        # for retrieval when the note model has not yet captured a new detail.
        query = " ".join([
            context_summary.get("claimed_identity", ""),
            context_summary.get("story", ""),
            " ".join(context_summary.get("requested_actions", [])),
            " ".join(context_summary.get("signals", [])),
            " ".join(context_summary.get("user_actions_taken", [])),
            " ".join(context_summary.get("recent_user_messages", [])),
        ])
        similar_cases = self.search_cases(query)
        patterns = self.detect_patterns(query, similar_cases)
        behaviours = self.analyse_behaviour(query, similar_cases)
        classifier_text = " ".join([
            query,
            " ".join(evidence["positive"]),
            " ".join(evidence["negative"]),
            " ".join(case["summary"] for case in similar_cases),
        ])
        model_pattern_predictions = self.pattern_classifier.predict(
            classifier_text, self.model_threshold
        )
        model_behaviour_predictions = self.behaviour_classifier.predict(
            classifier_text, self.model_threshold
        )

        pattern_by_id = {item["id"]: item for item in patterns}
        for prediction in model_pattern_predictions:
            if not prediction["selected"]:
                continue
            label = prediction["id"]
            if label in pattern_by_id:
                pattern_by_id[label]["classifier_probability"] = prediction["probability"]
                pattern_by_id[label]["model_source"] = "safeguard_pattern_classifier_v2"
            else:
                pattern = self.patterns.get(label)
                if pattern:
                    pattern_by_id[label] = {
                        "id": label,
                        "name": pattern["name"],
                        "match_score": prediction["probability"],
                        "classifier_probability": prediction["probability"],
                        "evidence": ["ML classifier candidate; direct evidence still required."],
                        "case_ids": pattern.get("case_ids", []),
                        "retrieved_support": False,
                        "validated": False,
                        "model_source": "safeguard_pattern_classifier_v2",
                    }
        pattern_findings = list(pattern_by_id.values())

        behaviour_by_id = {item["id"]: item for item in behaviours}
        for prediction in model_behaviour_predictions:
            if not prediction["selected"]:
                continue
            label = prediction["id"]
            if label in behaviour_by_id:
                behaviour_by_id[label]["classifier_probability"] = prediction["probability"]
                behaviour_by_id[label]["model_source"] = "safeguard_behaviour_classifier"
            else:
                tactic = self.tactics.get(label)
                if tactic:
                    behaviour_by_id[label] = {
                        "id": label,
                        "name": tactic["name"],
                        "evidence": ["ML classifier candidate; observable cue validation still required."],
                        "case_ids": tactic.get("case_ids", []),
                        "retrieved_support": False,
                        "validated": False,
                        "classifier_probability": prediction["probability"],
                        "model_source": "safeguard_behaviour_classifier",
                    }
        behaviour_findings = list(behaviour_by_id.values())
        if (
            len(evidence["negative"]) >= 2
            and not context_summary.get("requested_actions")
            and not context_summary.get("user_actions_taken")
            and not any(term in query.lower() for term in HIGH_SIGNAL_TERMS)
        ):
            pattern_findings = []
            behaviour_findings = []
        evidence_validation = {
            "validated_pattern_ids": [item["id"] for item in patterns],
            "retrieved_only_pattern_ids": sorted({
                pattern_id
                for case in similar_cases
                for pattern_id in case.get("fraud_pattern_ids", [])
                if pattern_id not in {item["id"] for item in patterns}
            }),
            "rule": "Retrieved cases support investigation; direct evidence is required to confirm a pattern.",
        }
        level, confidence, risk_evidence, risk_unknowns, action = self.assess_risk(
            notes, pattern_findings, behaviour_findings, similar_cases, query, evidence
        )
        return {
            "context_summary": context_summary,
            "evidence": evidence,
            "retrieval": {
                **getattr(self, "last_retrieval", {
                    "method": "tfidf_vector_cosine_initial",
                    "embedding_model": None,
                    "semantic_status": self.semantic_status,
                }),
                "candidate_count": len(similar_cases),
            },
            "evidence_validation": evidence_validation,
            "model_status": {
                "pattern_classifier": {
                    "available": self.pattern_classifier.available,
                    "version": self.pattern_classifier.version,
                    "error": self.pattern_classifier.error,
                    "threshold": self.model_threshold,
                },
                "behaviour_classifier": {
                    "available": self.behaviour_classifier.available,
                    "version": self.behaviour_classifier.version,
                    "error": self.behaviour_classifier.error,
                    "threshold": self.model_threshold,
                },
            },
            "model_pattern_predictions": model_pattern_predictions,
            "model_behaviour_predictions": model_behaviour_predictions,
            "claimed_identity": notes.get("claimed_identity", ""),
            "requested_action": "; ".join(notes.get("requests_made", [])),
            "detected_patterns": pattern_findings,
            "behaviour_indicators": behaviour_findings,
            "similar_cases": similar_cases,
            "risk_level": level,
            "confidence": confidence,
            "risk_evidence": risk_evidence,
            "unknowns": list(dict.fromkeys(evidence["missing"] + risk_unknowns)),
            "recommended_action": action,
        }
