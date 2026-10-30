from __future__ import annotations

from .managed_actions import ManagedActionInput

from typing import Annotated, Literal, Optional, Union

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    model_validator,
)


# ============================================================
# General API schemas
# ============================================================

class StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
    )


ActionText = Annotated[
    str,
    Field(min_length=1, max_length=2000),
]


class ReviewRequest(StrictModel):
    decision: Literal[
        "accepted",
        "accepted_with_edits",
        "rejected",
    ]
    final_root_cause: str = Field(
        min_length=1,
        max_length=5000,
    )
    selected_actions: list[ActionText] = Field(
        default_factory=list,
        max_length=20,
    )
    comment: str = Field(
        default="",
        max_length=2000,
    )
    promote_to_knowledge_base: bool = False


class SopUpdateRequest(StrictModel):
    investigation_sop: str = Field(
        min_length=1,
        max_length=50000,
    )
    expected_hash: str = Field(
        pattern=r"^[a-f0-9]{64}$",
    )
    change_note: str = Field(
        min_length=1,
        max_length=500,
    )


class RemediationRequestCreate(StrictModel):
    action_id: str = Field(
        pattern=r"^[a-z0-9][a-z0-9_-]{2,127}$",
    )
    request_reason: str = Field(
        min_length=1,
        max_length=2000,
    )
    idempotency_key: Optional[str] = Field(
        default=None,
        pattern=(
            r"^[0-9a-fA-F]{8}-"
            r"[0-9a-fA-F]{4}-"
            r"[1-5][0-9a-fA-F]{3}-"
            r"[89abAB][0-9a-fA-F]{3}-"
            r"[0-9a-fA-F]{12}$"
        ),
    )


class RemediationDecisionRequest(StrictModel):
    comment: str = Field(
        default="",
        max_length=2000,
    )


class RemediationManualResolutionRequest(StrictModel):
    outcome: Literal[
        "SUCCEEDED",
        "FAILED",
        "CANCELLED",
    ]
    comment: str = Field(
        min_length=1,
        max_length=2000,
    )


class ApiMessage(StrictModel):
    message: str


# ============================================================
# Onboarding draft schemas
# ============================================================

class OnboardingStrictModel(BaseModel):
    """Strict contract used for LLM-generated onboarding drafts."""

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        strict=True,
    )


class OnboardingConversationMessage(OnboardingStrictModel):
    role: Literal["user", "assistant"]
    content: str = Field(
        min_length=1,
        max_length=10000,
    )


class OnboardingCommandCheckDraft(OnboardingStrictModel):
    kind: Literal["command"]
    name: str = Field(
        default="",
        max_length=128,
    )
    command: str = Field(
        default="",
        max_length=16000,
    )
    expected_exit_codes: list[int] = Field(
        default_factory=lambda: [0],
        min_length=1,
        max_length=20,
    )
    unhealthy_exit_codes: list[int] = Field(
        default_factory=lambda: [1],
        min_length=1,
        max_length=20,
    )
    timeout_seconds: int = Field(
        default=15,
        ge=1,
        le=300,
    )
    require_stdout: bool = False
    healthy_stdout_regex: Optional[str] = Field(
        default=None,
        max_length=2000,
    )
    unhealthy_stdout_regex: Optional[str] = Field(
        default=None,
        max_length=2000,
    )


class OnboardingHttpCheckDraft(OnboardingStrictModel):
    kind: Literal["http"]
    name: str = Field(
        default="",
        max_length=128,
    )
    url: str = Field(
        default="",
        max_length=2000,
    )
    expected_status_codes: list[int] = Field(
        default_factory=lambda: [200],
        min_length=1,
        max_length=20,
    )
    timeout_seconds: int = Field(
        default=10,
        ge=1,
        le=300,
    )


OnboardingCheckDraft = Annotated[
    Union[
        OnboardingCommandCheckDraft,
        OnboardingHttpCheckDraft,
    ],
    Field(discriminator="kind"),
]


class OnboardingExecutionSpecDraft(OnboardingStrictModel):
    schema_version: Literal[1] = 1
    command: str = Field(
        default="",
        max_length=16000,
    )
    command_timeout_seconds: int = Field(
        default=60,
        ge=1,
        le=3600,
    )
    prechecks: list[OnboardingCheckDraft] = Field(
        default_factory=list,
        max_length=20,
    )
    postchecks: list[OnboardingCheckDraft] = Field(
        default_factory=list,
        max_length=20,
    )
    verification_attempts: int = Field(
        default=6,
        ge=1,
        le=30,
    )
    verification_delay_seconds: int = Field(
        default=5,
        ge=0,
        le=300,
    )


class OnboardingDagDraft(OnboardingStrictModel):
    dag_id: str = Field(
        default="",
        max_length=255,
    )
    exception_types: list[str] = Field(
        default_factory=list,
        max_length=50,
    )
    investigation_sop: str = Field(
        default="",
        max_length=50000,
    )


# ============================================================
# Existing targets
# ============================================================

class OnboardingExistingTargetDraft(OnboardingStrictModel):
    """Reference an existing registered SSH target."""

    mode: Literal["EXISTING"]
    target_id: str = Field(
        default="",
        max_length=128,
    )


class OnboardingExistingDatabaseTargetDraft(
    OnboardingStrictModel
):
    """Reference an existing registered database target."""

    mode: Literal["EXISTING_DATABASE"]
    database_target_id: str = Field(
        default="",
        max_length=128,
    )


# ============================================================
# New database target
# ============================================================

class OnboardingDatabaseTargetMetadataDraft(
    OnboardingStrictModel
):
    database_target_id: str = Field(
        default="",
        max_length=128,
    )
    display_name: str = Field(
        default="",
        max_length=255,
    )
    hostname: str = Field(
        default="",
        max_length=255,
    )
    database_port: int = Field(
        default=3306,
        ge=1,
        le=65535,
    )
    database_name: str = Field(
        default="",
        max_length=255,
    )

    # Onboarding only supports read-only diagnostic database
    # targets. This value cannot be changed by the LLM.
    read_only_required: Literal[True] = True

    # The activation service enables the target only after
    # successfully testing and saving its credentials.
    enabled: Literal[False] = False


class OnboardingDatabaseCredentialRequirementDraft(
    OnboardingStrictModel
):
    credential_name: str = Field(
        default="",
        max_length=150,
    )
    credential_type: Literal[
        "DATABASE_PASSWORD"
    ] = "DATABASE_PASSWORD"
    purpose: Literal[
        "DATABASE_READ_ONLY"
    ] = "DATABASE_READ_ONLY"
    username: str = Field(
        default="",
        max_length=255,
    )
    secret_required: Literal[True] = True


class OnboardingNewDatabaseTargetDraft(
    OnboardingStrictModel
):
    mode: Literal["NEW_DATABASE"]
    target: OnboardingDatabaseTargetMetadataDraft
    credential: OnboardingDatabaseCredentialRequirementDraft


# ============================================================
# New SSH target
# ============================================================

class OnboardingTargetMetadataDraft(OnboardingStrictModel):
    target_id: str = Field(
        default="",
        max_length=128,
    )
    display_name: str = Field(
        default="",
        max_length=255,
    )
    hostname: str = Field(
        default="",
        max_length=255,
    )
    ssh_port: int = Field(
        default=22,
        ge=1,
        le=65535,
    )
    ssh_host_key_policy: Literal[
        "DISCOVER_AND_PIN_ON_ACTIVATION"
    ] = "DISCOVER_AND_PIN_ON_ACTIVATION"

    # Activation changes this to enabled only after the SSH
    # connection and credentials have been validated.
    enabled: Literal[False] = False


class OnboardingCredentialRequirementDraft(
    OnboardingStrictModel
):
    credential_name: str = Field(
        default="",
        max_length=150,
    )
    credential_type: Literal[
        "SSH_PASSWORD"
    ] = "SSH_PASSWORD"
    purpose: Literal[
        "VERIFIER_READ_ONLY",
        "EXECUTOR_REMEDIATION",
    ]
    username: str = Field(
        default="",
        max_length=255,
    )
    secret_required: Literal[True] = True


class OnboardingCredentialPlanDraft(
    OnboardingStrictModel
):
    verifier: OnboardingCredentialRequirementDraft
    executor: Optional[
        OnboardingCredentialRequirementDraft
    ] = None


class OnboardingNewTargetDraft(OnboardingStrictModel):
    """New username/password SSH target."""

    mode: Literal["NEW"]
    target: OnboardingTargetMetadataDraft
    credential_plan: OnboardingCredentialPlanDraft


OnboardingTargetRegistrationDraft = Annotated[
    Union[
        OnboardingExistingTargetDraft,
        OnboardingExistingDatabaseTargetDraft,
        OnboardingNewTargetDraft,
        OnboardingNewDatabaseTargetDraft,
    ],
    Field(discriminator="mode"),
]


# ============================================================
# Legacy remediation-action draft
# ============================================================

class OnboardingRemediationActionDraft(
    OnboardingStrictModel
):
    """
    Transitional compatibility model.

    New onboarding activation must not create this action.
    Administrators must select an existing ACTIVE action using
    selected_action_id.
    """

    action_id: str = Field(
        default="",
        max_length=128,
    )
    component_id: str = Field(
        default="",
        max_length=255,
    )
    target_id: str = Field(
        default="",
        max_length=128,
    )
    display_name: str = Field(
        default="",
        max_length=255,
    )
    description: str = Field(
        default="",
        max_length=5000,
    )
    risk_level: Literal[
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
    ] = "MEDIUM"
    lifecycle_status: Literal["DRAFT"] = "DRAFT"
    implementation_version: str = Field(
        default="",
        max_length=64,
    )
    executor_type: Literal[
        "SSH_COMMAND"
    ] = "SSH_COMMAND"
    execution_spec: OnboardingExecutionSpecDraft
    verification_summary: str = Field(
        default="",
        max_length=5000,
    )
    rollback_summary: Optional[str] = Field(
        default=None,
        max_length=5000,
    )
    requires_approval: Literal[True] = True


# ============================================================
# Review and assistant schemas
# ============================================================

class OnboardingReviewTemplateDraft(
    OnboardingStrictModel
):
    summary: str = Field(
        default="",
        max_length=2000,
    )
    sop_review_points: list[str] = Field(
        default_factory=list,
        max_length=20,
    )
    action_review_points: list[str] = Field(
        default_factory=list,
        max_length=20,
    )
    activation_requirements: list[str] = Field(
        default_factory=list,
        max_length=20,
    )


OnboardingOperatingMode = Literal[
    "INVESTIGATE_ONLY",
    "APPROVAL_REQUIRED_ACTION",
]


class OnboardingBundleDraft(OnboardingStrictModel):
    managed_action: Optional[ManagedActionInput] = None
    schema_version: Literal[1] = 1
    lifecycle_status: Literal["DRAFT"] = "DRAFT"
    operating_mode: OnboardingOperatingMode = (
        "INVESTIGATE_ONLY"
    )
    dag: OnboardingDagDraft
    target_registration: OnboardingTargetRegistrationDraft

    # This points to an existing ACTIVE action in
    # remediation_action_catalog.
    selected_action_id: Optional[str] = Field(
        default=None,
        pattern=r"^[a-z0-9][a-z0-9_-]{2,127}$",
    )

    # Transitional compatibility only. New onboarding must
    # always keep this field null.
    remediation_action: Optional[
        OnboardingRemediationActionDraft
    ] = None

    review_template: OnboardingReviewTemplateDraft

    @model_validator(mode="after")
    def validate_managed_action_mode(self) -> "OnboardingBundleDraft":
        if self.managed_action is not None and (self.operating_mode != "APPROVAL_REQUIRED_ACTION" or self.selected_action_id != self.managed_action.action_id):
            raise ValueError("The action must match the approval-required draft")
        return self



class OnboardingConnectionMapping(OnboardingStrictModel):
    hostname: str = Field(min_length=1, max_length=255)
    port: int = Field(ge=1, le=65535)
    database_name: str = Field(default="", max_length=255)
    confirmed: bool = False


class OnboardingConfirmationQuestion(OnboardingStrictModel):
    kind: Literal["airflow_variable", "connection_mapping"]
    key: str = Field(min_length=1, max_length=255)
    prompt: str = Field(min_length=1, max_length=2000)
    evidence_ids: list[str] = Field(min_length=1, max_length=100)



class OnboardingLimitedCoverageAcknowledgement(OnboardingStrictModel):
    acknowledged: Literal[True]
    review_token: str = Field(pattern=r"^[a-f0-9]{64}$")
    reason: str = Field(min_length=1, max_length=1000)


class OnboardingStructuredInput(OnboardingStrictModel):
    """Typed administrator input that the LLM must copy, not infer."""
    extract_action_candidates: bool = False
    managed_action: Optional[ManagedActionInput] = None

    limited_coverage_acknowledgement: Optional[OnboardingLimitedCoverageAcknowledgement] = None


    external_script_policy: Literal["EXCLUDE", "REVIEW"] = "EXCLUDE"


    # Values are JSON text, e.g. 15, "host.example", or ["ops@example.com"].
    airflow_variable_values: dict[str, str] = Field(default_factory=dict, max_length=100)
    connection_mappings: dict[str, OnboardingConnectionMapping] = Field(default_factory=dict, max_length=100)


    # The pasted Python is inspected as text. It is never imported or run.
    dag_source_code: str = Field(default="", max_length=60000)
    investigation_read_only: bool = False

    dag_id: str = Field(
        default="",
        max_length=255,
    )
    exception_types: list[str] = Field(
        default_factory=list,
        max_length=50,
    )
    monitoring_description: str = Field(
        default="",
        max_length=5000,
    )
    operating_mode: OnboardingOperatingMode = (
        "INVESTIGATE_ONLY"
    )
    target_registration: OnboardingTargetRegistrationDraft
    investigation_logic: str = Field(
        default="",
        max_length=50000,
    )

    selected_action_id: Optional[str] = Field(
        default=None,
        pattern=r"^[a-z0-9][a-z0-9_-]{2,127}$",
    )

    # Transitional compatibility only.
    remediation_action: Optional[
        OnboardingRemediationActionDraft
    ] = None

    @model_validator(mode="after")
    def validate_dag_source_mode(self) -> "OnboardingStructuredInput":
        if self.dag_source_code.strip() and not self.investigation_read_only and not self.extract_action_candidates:
            raise ValueError("Confirm that Verifier investigations are read-only")
        if self.managed_action is not None:
            if self.operating_mode != "APPROVAL_REQUIRED_ACTION":
                raise ValueError("A new action requires approval-required execution mode")
            if self.selected_action_id is not None:
                raise ValueError("Choose a new action or an existing action")
        if self.dag_source_code.strip() and self.operating_mode == "INVESTIGATE_ONLY" and self.selected_action_id:
            raise ValueError("Investigate-only mode cannot select an action")
        return self


class OnboardingAssistantRequest(OnboardingStrictModel):
    message: str = Field(
        min_length=1,
        max_length=10000,
    )
    conversation: list[
        OnboardingConversationMessage
    ] = Field(
        default_factory=list,
        max_length=30,
    )
    current_draft: Optional[
        OnboardingBundleDraft
    ] = None
    structured_input: Optional[
        OnboardingStructuredInput
    ] = None


class OnboardingAssistantResponse(OnboardingStrictModel):
    action_extraction: dict[str, object] = Field(default_factory=dict)
    action_preview: dict[str, object] = Field(default_factory=dict)

    source_plan: dict[str, object] = Field(default_factory=dict)
    confirmation_questions: list[OnboardingConfirmationQuestion] = Field(default_factory=list, max_length=200)
    explanation_notes: list[dict[str, object]] = Field(default_factory=list, max_length=20)

    assistant_message: str = Field(
        min_length=1,
        max_length=10000,
    )
    ready_for_review: bool
    missing_fields: list[str] = Field(
        default_factory=list,
        max_length=100,
    )
    validation_issues: list[str] = Field(
        default_factory=list,
        max_length=100,
    )
    draft: OnboardingBundleDraft


# ============================================================
# Activation credentials
# ============================================================

class OnboardingSecretModel(BaseModel):
    """
    Input contract for activation secrets.

    Password whitespace is deliberately preserved because whitespace
    may be part of a valid password.
    """

    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        str_strip_whitespace=False,
    )


class OnboardingNoActivationCredentials(
    OnboardingSecretModel
):
    """Used when the selected target already exists."""

    credential_kind: Literal["NONE"] = "NONE"


class OnboardingSshActivationCredentials(
    OnboardingSecretModel
):
    credential_kind: Literal[
        "SSH_PASSWORDS"
    ] = "SSH_PASSWORDS"

    verifier_password: SecretStr = Field(
        min_length=1,
        max_length=4096,
    )

    executor_password: Optional[SecretStr] = Field(
        default=None,
        min_length=1,
        max_length=4096,
    )


class OnboardingDatabaseActivationCredentials(
    OnboardingSecretModel
):
    credential_kind: Literal[
        "DATABASE_PASSWORD"
    ] = "DATABASE_PASSWORD"

    password: SecretStr = Field(
        min_length=1,
        max_length=4096,
    )


OnboardingActivationCredentials = Annotated[
    Union[
        OnboardingNoActivationCredentials,
        OnboardingSshActivationCredentials,
        OnboardingDatabaseActivationCredentials,
    ],
    Field(discriminator="credential_kind"),
]


# ============================================================
# Activation request
# ============================================================

class OnboardingActivationRequest(
    OnboardingStrictModel
):
    """
    Administrator-reviewed onboarding bundle submitted for
    permanent activation.
    """
    update_existing_component: bool = False
    action_definition_confirmed: bool = False

    source_review: Optional[OnboardingStructuredInput] = None


    draft: OnboardingBundleDraft
    credentials: OnboardingActivationCredentials
    confirmation: Literal["ACTIVATE"]

    @model_validator(mode="after")
    def validate_activation_contract(
        self,
    ) -> "OnboardingActivationRequest":
        registration = self.draft.target_registration

        if isinstance(
            registration,
            (
                OnboardingExistingTargetDraft,
                OnboardingExistingDatabaseTargetDraft,
            ),
        ):
            expected_credential_kind = "NONE"

        elif isinstance(
            registration,
            OnboardingNewTargetDraft,
        ):
            expected_credential_kind = "SSH_PASSWORDS"

        else:
            expected_credential_kind = "DATABASE_PASSWORD"

        if (
            self.credentials.credential_kind
            != expected_credential_kind
        ):
            raise ValueError(
                "credentials.credential_kind does not match "
                "target_registration.mode"
            )

        # Administrators may only select existing actions.
        if self.draft.remediation_action is not None:
            raise ValueError(
                "Onboarding cannot create remediation actions; "
                "select an existing ACTIVE action using "
                "selected_action_id"
            )

        selected_action_id = self.draft.selected_action_id

        if (
            self.draft.operating_mode
            == "INVESTIGATE_ONLY"
        ):
            if selected_action_id is not None:
                raise ValueError(
                    "INVESTIGATE_ONLY onboarding cannot "
                    "select a remediation action"
                )

        elif selected_action_id is None:
            raise ValueError(
                "APPROVAL_REQUIRED_ACTION onboarding "
                "requires selected_action_id"
            )

        # The current remediation executor only supports
        # registered SSH actions.
        if isinstance(
            registration,
            (
                OnboardingExistingDatabaseTargetDraft,
                OnboardingNewDatabaseTargetDraft,
            ),
        ):
            if (
                self.draft.operating_mode
                != "INVESTIGATE_ONLY"
            ):
                raise ValueError(
                    "Database targets currently support "
                    "INVESTIGATE_ONLY onboarding"
                )

        # A new SSH target needs a separate executor password
        # if it will use an approval-required action.
        if (
            isinstance(
                registration,
                OnboardingNewTargetDraft,
            )
            and self.draft.operating_mode
            == "APPROVAL_REQUIRED_ACTION"
            and isinstance(
                self.credentials,
                OnboardingSshActivationCredentials,
            )
            and self.credentials.executor_password is None
        ):
            raise ValueError(
                "A new SSH target using an approved action "
                "requires an executor_password"
            )

        return self


# ============================================================
# Existing remediation-action catalog response
# ============================================================

class OnboardingActionOption(StrictModel):
    action_id: str
    component_id: str
    target_id: str
    display_name: str
    description: str
    risk_level: Literal[
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
    ]
    implementation_version: str
    requires_approval: bool


class OnboardingActionCatalogResponse(StrictModel):
    items: list[OnboardingActionOption] = Field(
        default_factory=list,
    )


# ============================================================
# Activation response
# ============================================================

class OnboardingActivationResponse(StrictModel):
    dag_id: str
    lifecycle_status: Literal["ACTIVE"] = "ACTIVE"
    operating_mode: OnboardingOperatingMode

    target_type: Literal[
        "SSH",
        "DATABASE",
    ]
    target_id: str

    target_created: bool
    credentials_created: bool

    selected_action_id: Optional[str] = None

    sop_content_hash: str = Field(
        pattern=r"^[a-f0-9]{64}$",
    )

    activated_by: str
    message: str
# RCA_ADMIN_EXECUTION_MODE_V1

# RCA_ADMIN_EXECUTION_MODE_V2
