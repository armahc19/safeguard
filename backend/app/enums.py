"""Domain enums. Dependency-free so schemas, scoring and models can all share them."""
import enum


class AccountStatus(str, enum.Enum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    DELETED = "deleted"


class UserRole(str, enum.Enum):
    USER = "user"
    REVIEWER = "reviewer"  # can verify reports and manage threats
    ADMIN = "admin"


class ReportStatus(str, enum.Enum):
    PENDING = "pending"
    UNDER_REVIEW = "under_review"
    VERIFIED = "verified"
    REJECTED = "rejected"


class RiskLevel(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ReviewDecision(str, enum.Enum):
    APPROVED = "approved"
    REJECTED = "rejected"
    NEEDS_INFO = "needs_info"


class ReportType(str, enum.Enum):
    CALL = "call"
    SMS = "sms"
    WHATSAPP = "whatsapp"
    OTHER = "other"


class CaseStatus(str, enum.Enum):
    OPEN = "open"
    CLOSED = "closed"


class EvidenceType(str, enum.Enum):
    PHONE_NUMBER = "phone_number"
    MESSAGE = "message"
    LINK = "link"
    CALL = "call"
    TRANSACTION = "transaction"
    REPORT = "report"
    ASSESSMENT = "assessment"
    IDENTITY = "identity"
    OTHER = "other"


class CommunicationChannel(str, enum.Enum):
    APP = "app"
    USSD = "ussd"
    SMS = "sms"
    CALL = "call"
    WHATSAPP = "whatsapp"
    UNKNOWN = "unknown"


class CommunicationIntent(str, enum.Enum):
    GREETING = "greeting"
    REPORT_SCAM = "report_scam"
    CHECK_NUMBER = "check_number"
    ANALYZE_MESSAGE = "analyze_message"
    TRANSACTION_CHECK = "transaction_check"
    SAFETY_ADVICE = "safety_advice"
    UNKNOWN = "unknown"


class ConversationStage(str, enum.Enum):
    CONTACT = "contact"
    CONVERSATION = "conversation"
    MANIPULATION = "manipulation"
    ACTION = "action"
    LOSS = "loss"
    UNCLEAR = "unclear"


class FeedbackOutcome(str, enum.Enum):
    INTERVENTION_DELIVERED = "intervention_delivered"
    ADVICE_FOLLOWED = "advice_followed"
    ADVICE_IGNORED = "advice_ignored"
    TRANSACTION_CANCELLED = "transaction_cancelled"
    TRANSACTION_COMPLETED = "transaction_completed"
    REPORT_SUBMITTED = "report_submitted"
    REVIEWER_DECISION = "reviewer_decision"
    CONFIRMED_FRAUD = "confirmed_fraud"
    FALSE_POSITIVE = "false_positive"
    LOSS_REPORTED = "loss_reported"
    LOSS_PREVENTED = "loss_prevented"
    NEEDS_REVIEW = "needs_review"


class ThreatIndicatorType(str, enum.Enum):
    REPORT_VOLUME = "report_volume"  # automatic: recomputed from reports
    REVIEWER_CLASSIFICATION = "reviewer_classification"  # automatic: set when a reviewer approves with a category
    BLOCKLIST = "blocklist"  # manual: reviewer+
    ALLOWLIST = "allowlist"  # manual: admin only (known-legitimate numbers, e.g. a bank)


MANUAL_INDICATOR_TYPES = {ThreatIndicatorType.BLOCKLIST, ThreatIndicatorType.ALLOWLIST}


class CommunityReportStatus(str, enum.Enum):
    SUBMITTED = "submitted"
    UNDER_REVIEW = "under_review"
    ACCEPTED = "accepted"
    REJECTED = "rejected"


class CommunityEntityType(str, enum.Enum):
    PHONE = "phone"
    LINK = "link"
    ACCOUNT = "account"
    MESSAGE = "message"
    PERSON = "person"
    ORGANIZATION = "organization"
    WALLET = "wallet"
    EMAIL = "email"


class CommunityIncidentStatus(str, enum.Enum):
    OPEN = "open"
    UNDER_REVIEW = "under_review"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    RESOLVED = "resolved"


class FraudOutcome(str, enum.Enum):
    UNRESOLVED = "unresolved"
    CONFIRMED_FRAUD = "confirmed_fraud"
    FALSE_REPORT = "false_report"
    FUNDS_RECOVERED = "funds_recovered"


class IntelligenceStatus(str, enum.Enum):
    DRAFT = "draft"
    ACTIVE = "active"
    EXPIRED = "expired"
    WITHDRAWN = "withdrawn"
