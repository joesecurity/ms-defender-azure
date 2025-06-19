"""
constant File
"""

# pylint: disable=invalid-name

from collections import namedtuple
from dataclasses import dataclass, field
from enum import Enum
from json import loads
from os import environ


def str_to_bool(value: str) -> bool:
    """
    Convert string to bool type
    """
    return loads(value.strip().lower()) if isinstance(value, str) else bool(value)


AlertConfig = namedtuple(
    "AlertConfig",
    [
        "SEVERITIES",
        "STATUSES",
        "EVIDENCE_ENTITY_TYPES",
        "EVIDENCE_FILE_TYPE",
        "EVIDENCE_URL_TYPE",
        "MAX_ALERT_COUNT",
        "WINDOWS_DEFENDER_ATP",
        "WINDOWS_DEFENDER_AV",
        "SELECTED_DETECTION_SOURCES",
    ],
)

MachineActionConfig = namedtuple(
    "MachineActionConfig",
    ["JOB_TIMEOUT", "JOB_SLEEP", "MACHINE_TIMEOUT", "MACHINE_RETRY", "SLEEP"],
)


@dataclass
class GeneralConfig:
    """
    GeneralConfig
    """

    SELECTED_VERDICTS: list[str] = field(
        default_factory=lambda: ["suspicious", "malicious", "clean"]
    )


GENERAL_CONFIG = GeneralConfig()


@dataclass
class JoeConfig:
    """
    JoeSandbox Configuration
    """

    API_KEY: str
    ANALYSIS_JOB_TIMEOUT: int
    RESUBMIT: bool
    JOE_API_RETRIES: int
    JOE_API_TIMEOUT: int
    URL: str = "https://jbxcloud.joesecurity.org/api/"
    CONNECTOR_NAME: str = "MicrosoftDefenderForEndpointConnectorAzureFunction-Beta"
    API_KEY_TYPE: str = "Sandbox"
    SSL_VERIFY: bool = True
    ACCEPT_TAC: bool = True
    ANALYSIS_URL: str = "https://jbxcloud.joesecurity.org"
    RESUBMISSION_VERDICTS: list[str] = field(
        default_factory=lambda: ["malicious", "suspicious", "clean", "unknown"]
    )


JOE_CONFIG = JoeConfig(
    API_KEY=environ.get("JoeSandboxAPIKey", ""),
    ANALYSIS_JOB_TIMEOUT=int(environ.get("JoeSandboxAnalysisJobTimeout", 30)) * 60,
    RESUBMIT=str_to_bool(environ.get("JoeSandboxResubmit", "True")),
    JOE_API_RETRIES=int(environ.get("JoeSandboxAPIMaxRetry", 5)),
    JOE_API_TIMEOUT=int(environ.get("JoeSandboxAPIRetryTimeout", 5)) * 60,
)


@dataclass
class MachineActionStatus:
    """
    Machine Status
    """

    SUCCEEDED: str = "Succeeded"
    NOT_AVAILABLE: list[str] = field(default_factory=lambda: ["Pending", "InProgress"])
    FAIL: list[str] = field(default_factory=lambda: ["Cancelled", "TimeOut", "Failed"])


MACHINE_ACTION_STATUS = MachineActionStatus()


@dataclass
class APIConfig:
    """
    Microsoft API Configurations
    """

    APPLICATION_ID: str
    APPLICATION_SECRET: str
    CONNECTION_STRING: str
    ACCOUNT_KEY: str
    ACCOUNT_NAME: str
    DEFENDER_API_TIMEOUT: int
    DEFENDER_API_RETRY: int
    AUTH_URL: str
    RESOURCE_APPLICATION_ID_URI: str = "https://api.securitycenter.microsoft.com"
    URL: str = "https://api.securitycenter.microsoft.com"
    USER_AGENT: str = "MdePartner-JoeSecurity-JoeSecuritySandbox-AzureFunctionApp/4.4.1"
    CONTAINER_NAME: str = "joesecurity-defender-quarantine-files"


DEFENDER_API = APIConfig(
    APPLICATION_ID=environ.get("AzureClientID", ""),
    APPLICATION_SECRET=environ.get("AzureClientSecret", ""),
    CONNECTION_STRING=environ.get("AzureStorageConnectionString", ""),
    ACCOUNT_KEY=environ.get("AzureStorageAccountKey", ""),
    ACCOUNT_NAME=environ.get("StorageAccount", ""),
    DEFENDER_API_TIMEOUT=int(environ.get("DefenderApiRetryTimeout", 5)) * 60,
    DEFENDER_API_RETRY=int(environ.get("DefenderApiMaxRetry", 5)),
    AUTH_URL=f"https://login.microsoftonline.com/{environ.get('AzureTenantID', '')}/oauth2/token",
)


ALERT = AlertConfig(
    SEVERITIES=["Unspecified", "Informational", "Low", "Medium", "High"],
    STATUSES=["Unknown", "New", "InProgress", "Resolved"],
    EVIDENCE_ENTITY_TYPES=["File", "Url"],
    EVIDENCE_FILE_TYPE="File",
    EVIDENCE_URL_TYPE="Url",
    MAX_ALERT_COUNT=10000,
    WINDOWS_DEFENDER_ATP="WindowsDefenderAtp",
    WINDOWS_DEFENDER_AV="WindowsDefenderAv",
    SELECTED_DETECTION_SOURCES=["WindowsDefenderAtp", "WindowsDefenderAv"],
)

MACHINE_ACTION = MachineActionConfig(
    JOB_TIMEOUT=600,
    JOB_SLEEP=30,
    MACHINE_TIMEOUT=int(environ.get("MachineAvailabilityTimeout", 5)) * 60,
    MACHINE_RETRY=int(environ.get("MachineAvailabilityRetry", 10)),
    SLEEP=int(environ.get("MachineAvailabilityTimeout", 5))
    * 60
    // int(environ.get("MachineAvailabilityRetry", 10)),
)


class EnrichmentSectionTypes(Enum):
    """
    JoeSandbox section to enrich
    """

    CLASSIFICATIONS = "classifications"
    THREAT_NAMES = "threat_names"


class IngestionConfig(Enum):
    """
    Type of alert ingestion
    """

    EDR_BASED_INGESTION = True
    AV_BASED_INGESTION = True


class EDREnrichment(Enum):
    """
    EDR alert ingestion
    """

    ACTIVE = True
    SELECTED_SECTIONS = ["classifications", "threat_names", "vtis"]


class AVEnrichment(Enum):
    """
    Antivirus alert ingestion
    """

    ACTIVE = True
    SELECTED_SECTIONS = ["classifications", "threat_names"]


HELPER_SCRIPT_FILE_NAME = "SubmitEvidencesToJoeSandbox.ps1"

RETRY_STATUS_CODE = [500, 501, 502, 503, 504, 429]
AUTH_ERROR_STATUS_CODE = 401

