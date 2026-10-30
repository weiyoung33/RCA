"""Contract fixture only; never copy this file over an application schema."""
SOURCE = '''
from typing import Literal, Optional
from pydantic import BaseModel, ConfigDict, Field, model_validator
class OnboardingStrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, str_strip_whitespace=True)
class Registration(OnboardingStrictModel):
    mode: Literal["EXISTING"]
    target_id: str
class Dag(OnboardingStrictModel):
    dag_id: str
    exception_types: list[str]
    investigation_sop: str
class Review(OnboardingStrictModel):
    summary: str
    sop_review_points: list[str]
    action_review_points: list[str]
    activation_requirements: list[str]
class OnboardingBundleDraft(OnboardingStrictModel):
    schema_version: Literal[1] = 1
    lifecycle_status: Literal["DRAFT"] = "DRAFT"
    operating_mode: Literal["INVESTIGATE_ONLY", "APPROVAL_REQUIRED_ACTION"]
    dag: Dag
    target_registration: Registration
    selected_action_id: Optional[str] = None
    remediation_action: Optional[dict] = None
    review_template: Review
class OnboardingStructuredInput(OnboardingStrictModel):
    dag_id: str = ""
    exception_types: list[str] = Field(default_factory=list)
    dag_source_code: str = ""
    airflow_variable_values: dict[str, str] = Field(default_factory=dict)
    investigation_read_only: bool = False
    operating_mode: str = "INVESTIGATE_ONLY"
    target_registration: Registration
    selected_action_id: Optional[str] = None
    remediation_action: Optional[dict] = None
    @model_validator(mode="after")
    def validate_dag_source_mode(self):
        if self.dag_source_code and self.operating_mode != "INVESTIGATE_ONLY":
            raise ValueError("source only")
        return self
class OnboardingAssistantRequest(OnboardingStrictModel):
    structured_input: Optional[OnboardingStructuredInput] = None
class OnboardingAssistantResponse(OnboardingStrictModel):
    assistant_message: str
    ready_for_review: bool
    missing_fields: list[str]
    validation_issues: list[str]
    source_plan: dict
    confirmation_questions: list
    explanation_notes: list
    draft: OnboardingBundleDraft
class OnboardingActivationRequest(OnboardingStrictModel):
    draft: OnboardingBundleDraft
    source_review: Optional[OnboardingStructuredInput] = None
    action_legacy_field: str = "unchanged"
'''
