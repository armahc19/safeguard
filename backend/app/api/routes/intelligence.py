from fastapi import APIRouter

from app.schemas.intelligence import IntelligenceCapabilitiesOut, IntelligenceCapability

router = APIRouter(prefix="/intelligence", tags=["intelligence-platform"])


@router.get("/capabilities", response_model=IntelligenceCapabilitiesOut)
async def capabilities() -> IntelligenceCapabilitiesOut:
    """Expose the canonical intelligence boundary used by all clients.

    This is deliberately metadata-only: it lets clients discover the backend
    contract without creating a second intelligence implementation in a UI.
    """
    return IntelligenceCapabilitiesOut(
        supported_channels=["app", "ussd", "sms", "call", "whatsapp", "chat"],
        capabilities=[
            IntelligenceCapability(
                name="communication_intelligence", status="active", owner="backend",
                description="Normalizes channel, language, intent, stage and privacy context.",
            ),
            IntelligenceCapability(
                name="fraud_intelligence_orchestrator", status="active", owner="fraud_intelligence_orchestrator",
                description="Composes communication, message shield, pattern, identity, risk and intervention outputs into one shared result.",
            ),
            IntelligenceCapability(
                name="unified_model_runtime", status="active_with_fallback", owner="model_runtime",
                description="Loads the pattern and behavioural joblib artifacts through one versioned runtime with deterministic fallback when artifacts are unavailable.",
            ),
            IntelligenceCapability(
                name="case_context", status="active", owner="case_service",
                description="Owns durable cases and typed evidence shared by all channels.",
            ),
            IntelligenceCapability(
                name="risk_decision", status="active", owner="risk_engine",
                description="The only service allowed to produce final risk levels, scores, confidence and recommended action.",
            ),
            IntelligenceCapability(
                name="intervention", status="active", owner="intervention_engine",
                description="The sole owner of channel-specific warnings, safe actions, confirmation gates and escalation plans.",
            ),
            IntelligenceCapability(
                name="pattern_classifier", status="active_with_fallback", owner="pattern_intelligence",
                description="Uses the versioned pattern artifact when available and a deterministic fallback otherwise.",
            ),
            IntelligenceCapability(
                name="behaviour_classifier", status="active_with_fallback", owner="model_runtime",
                description="Uses the shared behavioural joblib artifact for text signals and combines it with transaction-history behaviour evidence.",
            ),
            IntelligenceCapability(
                name="client_surfaces", status="backend_authoritative", owner="api_gateway",
                description="Gradio, Smart, Lite and Admin must consume this backend boundary rather than make independent risk decisions.",
            ),
            IntelligenceCapability(
                name="multi_layer_ai_graph_analysis", status="active_with_rule_fallback", owner="intelligence_layers",
                description="Fuses shared FIR pattern and behaviour findings with graph activity and cross-institution signals in entity profiles.",
            ),
            IntelligenceCapability(
                name="liveness_detection", status="trusted_provider_attestation", owner="liveness_verification",
                description="Uses one-time challenges and signed trusted-provider liveness verdicts; SafeGuard does not store biometric media.",
            ),
            IntelligenceCapability(
                name="real_time_detection", status="active_synchronous_projection", owner="intelligence_layers",
                description="Refreshes graph signals and high fan-in/fan-out review candidates when FIR or partner data is ingested.",
            ),
            IntelligenceCapability(
                name="real_time_intelligence_sharing", status="active_partner_poll_feed", owner="partner_integration",
                description="Queues privacy-minimized intelligence alerts in a durable partner feed for authenticated polling and acknowledgement.",
            ),
        ],
    )
