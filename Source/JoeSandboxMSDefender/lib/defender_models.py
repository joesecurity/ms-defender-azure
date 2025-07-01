"""
Models
"""

from base64 import b64encode
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class LiveResponse:
    """
    LiveResponse class for storing live response job details
    """

    index: int = 0
    has_error: bool = False
    is_finished: bool = False
    id: Any = None
    download_url: Any = None
    timeout_counter: int = 0


@dataclass
class Evidence:
    """
    Evidence class for storing evidence related information
    """

    sha256: str
    sha1: str
    file_name: str
    file_path: str
    alert_id: str
    machine_id: str
    detection_source: str
    url: str
    entity_type: str
    joe_analysis: list = field(default_factory=list)
    downloaded_file_data: Optional[bytes] = None
    live_response: LiveResponse = field(default_factory=LiveResponse)
    comments: set[str] = field(default_factory=set)
    submissions: list = field(default_factory=list)

    def __post_init__(self):
        self.absolute_path = self.file_path + "\\" + self.file_name
        self.alert_ids = {self.alert_id}
        self.machine_ids = {self.machine_id}

    def set_comments(self, comments):
        """
        Setting comment
        """
        for comment in comments:
            if "comment" in comment and comment["comment"] is not None:
                self.comments.add(
                    b64encode(comment["comment"].encode("utf-8")).decode("utf-8")
                )


@dataclass
class Machine:
    """
    Machine class for storing machine related information and evidences
    """

    id: str
    edr_evidences: dict = field(default_factory=dict)
    av_evidences: dict = field(default_factory=dict)
    run_script_live_response_finished: bool = False
    timeout_counter: int = 0

    def has_pending_edr_actions(self) -> bool:
        """
        Check if the machine has pending live response jobs
        :return bool: status of pending live response jobs
        """
        for evidence in self.edr_evidences.values():
            if (
                not evidence.live_response.is_finished
                and not evidence.live_response.has_error
            ):
                return True

        return False

    def get_successful_edr_evidences(self):
        """
        Fetch successful EDR Alert
        """
        return [
            evidence
            for evidence in self.edr_evidences.values()
            if evidence.live_response.download_url is not None
        ]
