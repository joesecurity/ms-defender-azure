"""
Microsoft Defender Class
"""

# pylint: disable=line-too-long
# pylint: disable=consider-using-f-string

from base64 import b64encode
from datetime import datetime, timedelta, timezone
from gzip import GzipFile
from io import BytesIO
from json import dumps
from os import path
from string import Template
from time import sleep
from typing import Union

import requests
from azure.storage.blob import ContainerSasPermissions, generate_container_sas
from requests import Response
from requests_toolbelt.multipart.encoder import MultipartEncoder

from ..const import (
    ALERT,
    AUTH_ERROR_STATUS_CODE,
    DEFENDER_API,
    HELPER_SCRIPT_FILE_NAME,
    JOE_CONFIG,
    MACHINE_ACTION,
    MACHINE_ACTION_STATUS,
    RETRY_STATUS_CODE,
)
from .defender_models import Evidence, LiveResponse


class MicrosoftDefender:
    """
    Wrapper class for Microsoft Defender for Endpoint API calls
    Import this class to retrieve alerts, evidences and start live response jobs
    """

    def __init__(self, log):
        """
        Initialize and authenticate the MicrosoftDefender instance,
        use MicrosoftDefenderConfig as configuration
        :param log: logger instance
        :return: void
        """
        self.access_token = None
        self.headers = None
        self.config = DEFENDER_API
        self.log = log

        self.authenticate()

    def authenticate(self):
        """
        Authenticate using Azure Active Directory application properties,
        and retrieves the access token
        :raise: Exception when credentials/application properties are not properly configured
        :return: void
        """

        body = {
            "resource": self.config.RESOURCE_APPLICATION_ID_URI,
            "client_id": self.config.APPLICATION_ID,
            "client_secret": self.config.APPLICATION_SECRET,
            "grant_type": "client_credentials",
        }
        try:
            response = self.retry_request(
                method="POST", url=self.config.AUTH_URL, data=body
            )
            data = response.json()
            self.access_token = data["access_token"]
            self.headers = {
                "Authorization": "Bearer %s" % self.access_token,
                "User-Agent": self.config.USER_AGENT,
                "Content-Type": "application/json",
            }
            self.log.info(
                "Successfully authenticated the Microsoft Defender for Endpoint API"
            )
        except Exception as err:
            self.log.error(err)
            raise

    def generate_sas_token(self) -> str:
        """
        Generating SAS Token
        :return: Sas Token
        """
        expiry_time = datetime.now(timezone.utc) + timedelta(hours=2)
        sas_token = generate_container_sas(
            account_name=DEFENDER_API.ACCOUNT_NAME,
            container_name=DEFENDER_API.CONTAINER_NAME,
            account_key=DEFENDER_API.ACCOUNT_KEY,
            permission=ContainerSasPermissions(write=True),
            expiry=expiry_time,
        )
        self.log.info(
            "Successfully generated temporary saas token for azure storage account container"
        )
        return sas_token

    def upload_ps_script_to_library(self) -> bool:
        """
        Upload powershell script to Defender library
        """
        request_url = self.config.URL + "/api/libraryfiles"
        sas_token = f"?{self.generate_sas_token()}"
        script_dir = path.dirname(__file__)
        with open(path.join(script_dir, HELPER_SCRIPT_FILE_NAME)) as script_file:
            script_content = script_file.read()
        script_content_temp = Template(script_content)
        updated_sas_token = script_content_temp.safe_substitute(SAS_TOKEN=sas_token)

        mp_encoder = MultipartEncoder(
            fields={
                "HasParameters": "true",
                "OverrideIfExists": "true",
                "Description": "description",
                "file": (HELPER_SCRIPT_FILE_NAME, updated_sas_token, "text/plain"),
            }
        )

        try:
            response = self.retry_request(
                method="POST",
                url=request_url,
                headers={**self.headers, **{"Content-Type": mp_encoder.content_type}},
                data=mp_encoder,
            )
            json_response = response.json()

            if response.ok:
                self.log.info(
                    "PS script successfully uploaded to the defender library files"
                )
                return True
            if "error" in json_response:
                self.log.error(
                    "Failed to upload PS script to the defender library files - Error: %s"
                    % (json_response["error"]["message"])
                )
        except Exception as err:
            self.log.error(
                "Failed to upload PS script to the defender library files - Error: %s"
                % err
            )

        return False

    def get_evidences(self, alert_id: str) -> dict:
        """
        Retrieve alerts and related evidence information from Microsoft Defender API.
        Returns a combined dictionary of file and URL evidence objects.
        """
        request_url = f"{self.config.URL}/api/alerts/{alert_id}"
        evidences: dict = {}

        try:
            response = self.retry_request(
                method="GET", url=request_url, headers=self.headers
            )
            alert_data = response.json()

            if not alert_data or "error" in alert_data:
                self.log.error(
                    "Failed to retrieve alert %s: %s",
                    alert_id,
                    alert_data.get("error", {}).get("message", "Empty response"),
                )
                return evidences

            if (
                alert_data.get("detectionSource")
                not in ALERT.SELECTED_DETECTION_SOURCES
            ):
                return evidences

            self.log.info(f"Successfully retrieved alert {alert_id}")

            for evidence in alert_data.get("evidence", []):
                entity_type = evidence.get("entityType")
                evidence_sha256 = evidence.get("sha256") or ""
                sha1 = evidence.get("sha1") or ""
                file_name = evidence.get("fileName") or ""
                file_path = evidence.get("filePath") or ""
                url = (evidence.get("url") or "").strip()

                if (
                    entity_type == ALERT.EVIDENCE_FILE_TYPE
                    and evidence_sha256
                    and evidence_sha256.lower() != "none"
                ):
                    key = evidence_sha256
                elif entity_type == ALERT.EVIDENCE_URL_TYPE and url:
                    key = url
                else:
                    continue

                evidence_obj = evidences.get(key) or Evidence(
                    sha256=evidence_sha256,
                    sha1=sha1,
                    file_name=file_name,
                    file_path=file_path,
                    alert_id=alert_data["id"],
                    machine_id=alert_data.get("machineId", ""),
                    detection_source=alert_data.get("detectionSource", ""),
                    url=url,
                    entity_type=entity_type,
                )
                evidence_obj.alert_ids.add(alert_data["id"])
                evidence_obj.machine_ids.add(alert_data.get("machineId"))
                evidence_obj.set_comments(alert_data.get("comments", []))
                evidences[key] = evidence_obj

            self.log.info("Alert %s - %d evidences found", alert_id, len(evidences))

        except Exception as err:
            self.log.error("Exception while retrieving alert %s: %s", alert_id, err)

        return evidences

    def get_machine_actions(self, machine_id: str) -> list | None:
        """
        Retrieve machine actions for given machine_id
        https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/get-machineactions-collection
        :param machine_id: Microsoft Defender for Endpoint ID for the machine
        :exception: when machine actions are not properly retrieved
        :return list or None: list of machine actions or None if there is an error
        """
        odata_query = "$filter=machineId+eq+'%s'" % machine_id
        request_url = self.config.URL + "/api/machineactions?" + odata_query
        try:
            response = self.retry_request(
                method="GET", url=request_url, headers=self.headers
            )
            json_response = response.json()
            if "error" in json_response:
                self.log.error(
                    "Failed to retrieve actions for machine %s - Error: %s"
                    % (machine_id, json_response["error"]["message"])
                )
                return None
            if "value" in json_response:
                return json_response["value"]
            self.log.error(
                "Failed to parse api response for machine %s - Error: value key not found in dict"
                % (machine_id)
            )
            return None
        except Exception as err:
            self.log.error(
                "Failed to retrieve machine actions for machine %s - Error: %s"
                % (machine_id, err)
            )
            return None

    def get_machine_action(self, live_response_id: str) -> dict | None:
        """
        Retrieve machine action detail with given live_response_id string
        https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/get-machineaction-object
        :param live_response_id: live response id
        :exception: when machine action is not properly retrieved
        :return dict or None: dict of machine action data or None if there is an error
        """
        request_url = self.config.URL + "/api/machineactions/%s" % live_response_id
        try:
            response = self.retry_request(
                method="GET", url=request_url, headers=self.headers
            )
            json_response = response.json()
            if "error" in json_response:
                self.log.error(
                    "Failed to retrieve machine action detail for %s - Error: %s"
                    % (live_response_id, json_response["error"]["message"])
                )
                return None
            return json_response
        except Exception as err:
            self.log.error(
                "Failed to retrieve machine action for %s - Error: %s"
                % (live_response_id, err)
            )
            return None

    def is_machine_available(self, machine_id: str) -> bool:
        """
        Check if the machine has no pending or processing machine action
        Because we can't make another machine action request when one of them pending
        :param machine_id: Microsoft Defender for Endpoint ID for the machine
        :return bool: machine availability status
        """
        machine_actions = self.get_machine_actions(machine_id)
        if machine_actions is not None:

            for action in machine_actions:
                if action["status"] in MACHINE_ACTION_STATUS.NOT_AVAILABLE:
                    self.log.warning(
                        "Machine %s is busy. Current action type is %s and status is %s"
                        % (machine_id, action["type"], action["status"])
                    )
                    return False
            self.log.info("Machine %s is available" % machine_id)
            return True
        return False

    def cancel_machine_action(self, live_response_id: str) -> None:
        """
        Cancel the machine action with given live_response object
        https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/cancel-machine-action
        :param live_response_id: live response instance
        :exception: when machine action is not properly cancel
        :return None
        """

        is_action_cancelled = False

        while not is_action_cancelled:
            request_url = (
                self.config.URL + "/api/machineactions/%s/cancel" % live_response_id
            )
            try:
                request_data = {
                    "Comment": "Machine action was cancelled by JoeSandbox Connector due to timeout"
                }
                response = self.retry_request(
                    method="POST",
                    url=request_url,
                    data=dumps(request_data),
                    headers=self.headers,
                )
                json_response = response.json()
                if "error" in json_response:
                    self.log.error(
                        "Failed to cancel machine action for %s - Error: %s"
                        % (live_response_id, json_response["error"])
                    )
                else:
                    if (
                        json_response["status"] == "Cancelled"
                        or json_response["status"] == "Failed"
                    ):
                        self.log.info(
                            "Cancelled live response action %s" % live_response_id
                        )
                        is_action_cancelled = True
            except Exception as err:
                self.log.error(
                    "Failed to cancel machine action for %s - Error: %s"
                    % (live_response_id, err)
                )

    def wait_run_script_live_response(self, live_response_id: str) -> tuple:
        """
        This function checks the live response execution
        :param live_response_id: Live response ID
        :return tuple: status and Machine Action response
        """
        timeout_counter = 0
        has_error = False
        is_finished = False

        self.log.info("Waiting live response job %s to finish" % live_response_id)
        while (
            MACHINE_ACTION.JOB_TIMEOUT / MACHINE_ACTION.JOB_SLEEP > timeout_counter
            and not has_error
            and not is_finished
        ):
            sleep(MACHINE_ACTION.JOB_SLEEP)
            machine_action = self.get_machine_action(live_response_id)
            if machine_action is not None:
                if machine_action["status"] == MACHINE_ACTION_STATUS.SUCCEEDED:
                    self.log.info("Live response job %s finished" % live_response_id)
                    is_finished = True
                elif machine_action["status"] in MACHINE_ACTION_STATUS.FAIL:
                    self.log.error(
                        "Live response job %s failed with error" % live_response_id
                    )
                    has_error = True
                else:
                    timeout_counter += 1
            else:
                has_error = True
        if MACHINE_ACTION.JOB_TIMEOUT / MACHINE_ACTION.JOB_SLEEP <= timeout_counter:
            error_message = (
                "Live response job timeout was hit (%s seconds)"
                % MACHINE_ACTION.JOB_TIMEOUT
            )
            self.log.error(
                "Live response job %s failed with error - Error: %s"
                % (live_response_id, error_message)
            )
            has_error = True
            self.cancel_machine_action(live_response_id)
            sleep(MACHINE_ACTION.JOB_SLEEP)

        if has_error:
            return False, machine_action

        return True, machine_action

    def wait_live_response(self, live_response: LiveResponse) -> LiveResponse:
        """
        Waiting live response machine action job to finish with configured timeout checks
        :param live_response: live_response object
        :return live_response: modified live_response object with status
        """
        self.log.info("Waiting live response job %s to finish" % live_response.id)
        while (
            MACHINE_ACTION.JOB_TIMEOUT / MACHINE_ACTION.JOB_SLEEP
            > live_response.timeout_counter
            and not live_response.has_error
            and not live_response.is_finished
        ):
            sleep(MACHINE_ACTION.JOB_SLEEP)
            machine_action = self.get_machine_action(live_response.id)
            if machine_action is not None:
                if machine_action["status"] == MACHINE_ACTION_STATUS.SUCCEEDED:
                    self.log.info("Live response job %s finished" % live_response.id)
                    live_response.is_finished = True
                elif machine_action["status"] in MACHINE_ACTION_STATUS.FAIL:
                    self.log.error(
                        "Live response job %s failed with error" % live_response.id
                    )
                    live_response.has_error = True
                else:
                    live_response.timeout_counter += 1
            else:
                live_response.has_error = True
        if (
            MACHINE_ACTION.JOB_TIMEOUT / MACHINE_ACTION.JOB_SLEEP
            <= live_response.timeout_counter
        ):
            error_message = (
                "Live response job timeout was hit (%s seconds)"
                % MACHINE_ACTION.JOB_TIMEOUT
            )
            self.log.error(
                "Live response job %s failed with error - Error: %s"
                % (live_response.id, error_message)
            )
            live_response.has_error = True
            self.cancel_machine_action(live_response.id)
            sleep(MACHINE_ACTION.JOB_SLEEP)

        return live_response

    def get_live_response_result(self, live_response: LiveResponse) -> LiveResponse:
        """
        Retrieve live response result and download url
        https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/get-live-response-result
        :param live_response: live_response object instance
        :exception: when live response result is not properly retrieved
        :return: dict of live response result or None if there is an error
        """
        request_url = (
            self.config.URL
            + "/api/machineactions/%s/GetLiveResponseResultDownloadLink(index=%s)"
            % (live_response.id, live_response.index)
        )
        try:
            response = self.retry_request(
                method="GET", url=request_url, headers=self.headers
            )
            json_response = response.json()
            if "error" in json_response:
                self.log.error(
                    "Failed to retrieve live response results for %s - Error: %s"
                    % (live_response.id, json_response["error"]["message"])
                )
                live_response.has_error = True
            else:
                if "value" in json_response:
                    live_response.download_url = json_response["value"]
                else:
                    self.log.error(
                        "Failed to retrieve live response results for"
                        " %s - Error: value key not found" % (live_response.id)
                    )
                    live_response.has_error = True
        except Exception as err:
            self.log.error(
                "Failed to retrieve live response results for %s - Error: %s"
                % (live_response.id, err)
            )
            live_response.has_error = True

        return live_response

    def run_edr_live_response(self, machines: list) -> list:
        """
        This function will execute EDR live response command
        :param machines: List of machine contains evidences
        """
        for machine in machines:
            if len(machine.edr_evidences) > 0:
                self.log.info(
                    "Waiting %d live response jobs to start for machine %s"
                    % (len(machine.edr_evidences), machine.id)
                )
                while (
                    MACHINE_ACTION.MACHINE_RETRY > machine.timeout_counter
                    and machine.has_pending_edr_actions()
                ):
                    if self.is_machine_available(machine.id):
                        for evidence in machine.edr_evidences.values():
                            if self.is_machine_available(machine.id):
                                # json request body for live response
                                live_response_command = {
                                    "Commands": [
                                        {
                                            "type": "GetFile",
                                            "params": [
                                                {
                                                    "key": "Path",
                                                    "value": evidence.absolute_path,
                                                }
                                            ],
                                        }
                                    ],
                                    "Comment": "JoeSandbox Connector File Acquisition Job for %s"
                                    % evidence.sha256,
                                }

                                self.log.info(
                                    "Trying to start live response job for"
                                    " evidence %s from machine %s"
                                    % (evidence.absolute_path, machine.id)
                                )
                                request_url = (
                                    self.config.URL
                                    + "/api/machines/%s/runliveresponse" % machine.id
                                )
                                try:
                                    response = self.retry_request(
                                        method="POST",
                                        url=request_url,
                                        data=dumps(live_response_command),
                                        headers=self.headers,
                                    )
                                    json_response = response.json()
                                    if "error" in json_response:
                                        self.log.error(
                                            "Live response error for machine %s"
                                            " for evidence %s - Error: %s"
                                            % (
                                                machine.id,
                                                evidence.sha256,
                                                json_response["error"]["message"],
                                            )
                                        )
                                        evidence.live_response.has_error = True
                                    else:
                                        try:
                                            sleep(5)
                                            json_response = self.get_machine_action(
                                                json_response["id"]
                                            )

                                            if json_response is not None:
                                                for command in json_response[
                                                    "commands"
                                                ]:
                                                    if (
                                                        command["command"]["type"]
                                                        == "GetFile"
                                                    ):
                                                        evidence.live_response.index = (
                                                            command["index"]
                                                        )
                                                        evidence.live_response.id = (
                                                            json_response["id"]
                                                        )
                                                self.log.info(
                                                    "Live response job %s for evidence %s started successfully"
                                                    % (
                                                        evidence.live_response.id,
                                                        evidence.sha256,
                                                    )
                                                )
                                                evidence.live_response = (
                                                    self.wait_live_response(
                                                        evidence.live_response
                                                    )
                                                )

                                                if evidence.live_response.is_finished:
                                                    evidence.live_response = (
                                                        self.get_live_response_result(
                                                            evidence.live_response
                                                        )
                                                    )
                                        except Exception as err:
                                            self.log.error(
                                                "Failed to parse api response for machine %s - Error: %s"
                                                % (machine.id, err)
                                            )
                                            evidence.live_response.has_error = True
                                except Exception as err:
                                    self.log.error(
                                        "Failed to create live response job for machine %s - Error: %s"
                                        % (machine.id, err)
                                    )
                                    evidence.live_response.has_error = True
                            else:
                                sleep(MACHINE_ACTION.SLEEP / 60)
                    else:
                        sleep(MACHINE_ACTION.SLEEP)
                        machine.timeout_counter += 1
                if machine.has_pending_edr_actions():
                    self.log.error(
                        "Machine %s was not available during the timeout (%s seconds)"
                        % (machine.id, MACHINE_ACTION.MACHINE_TIMEOUT)
                    )

        return machines

    def run_av_submission_script(self, machines: list, threat_name: str = "") -> list:
        """
        This function will execute AV live response command
        :param machines: List of machine contains evidences
        :param threat_name: Threat name from alert response
        """
        for machine in machines:
            file_counter = 0
            live_response_counter = 0
            if len(machine.av_evidences) > 0:
                self.log.info(
                    "Waiting run script live response job to start for machine %s"
                    % machine.id
                )
                file_names = []
                for evidence in machine.av_evidences.values():
                    file_names.append(evidence.sha256)

                while (
                    MACHINE_ACTION.MACHINE_RETRY > machine.timeout_counter
                    and MACHINE_ACTION.MACHINE_RETRY > live_response_counter
                    and not machine.run_script_live_response_finished
                ):
                    if self.is_machine_available(machine.id):
                        args_param = f"{threat_name},{self.config.ACCOUNT_NAME},{self.config.CONTAINER_NAME},{'joesecurity'.join(file_names)}"
                        live_response_command = {
                            "Commands": [
                                {
                                    "type": "RunScript",
                                    "params": [
                                        {
                                            "key": "ScriptName",
                                            "value": HELPER_SCRIPT_FILE_NAME,
                                        },
                                        {"key": "Args", "value": args_param},
                                    ],
                                }
                            ],
                            "Comment": "Live response job to submit evidences to JoeSandbox",
                        }
                        self.log.info(
                            "Trying to start run script live response job for machine %s"
                            % machine.id
                        )
                        request_url = (
                            self.config.URL
                            + "/api/machines/%s/runliveresponse" % machine.id
                        )
                        try:
                            response = self.retry_request(
                                method="POST",
                                url=request_url,
                                data=dumps(live_response_command),
                                headers=self.headers,
                            )
                            json_response = response.json()
                            if "error" in json_response:
                                self.log.error(
                                    "Run script live response error for machine %s - Error: %s"
                                    % (machine.id, json_response["error"]["message"])
                                )
                            else:
                                self.log.info(
                                    "Run script live response job successfully created for machine %s"
                                    % machine.id
                                )

                                if "id" in json_response:
                                    live_response_id = json_response["id"]
                                    (
                                        result,
                                        machine_action,
                                    ) = self.wait_run_script_live_response(
                                        live_response_id
                                    )
                                    if result:
                                        command = machine_action["commands"][0]
                                        if command["command"]["type"] == "RunScript":
                                            index = command["index"]
                                            res_id = machine_action["id"]
                                            request_url = f"{self.config.URL}/api/machineactions/{res_id}/GetLiveResponseResultDownloadLink(index={index})"
                                            response = self.retry_request(
                                                method="GET",
                                                url=request_url,
                                                headers=self.headers,
                                            )
                                            live_response_result = response.json()
                                            if "error" in live_response_result:
                                                self.log.error(
                                                    "Failed to retrieve live response results for %s - Error: %s"
                                                    % (
                                                        res_id,
                                                        live_response_result["error"][
                                                            "message"
                                                        ],
                                                    )
                                                )
                                            else:
                                                self.log.info(
                                                    "Checking if evidence restore or not"
                                                )
                                                if "value" in live_response_result:
                                                    download_url = live_response_result[
                                                        "value"
                                                    ]
                                                    content = self.retry_request(
                                                        method="GET",
                                                        url=download_url,
                                                        stream=True,
                                                    )
                                                    if content.ok:
                                                        log_msg = content.json().get(
                                                            "script_output"
                                                        )
                                                        if (
                                                            "QuarantinedFilesFound"
                                                            in log_msg
                                                        ):
                                                            self.log.info(
                                                                "Quarantine Files found"
                                                            )
                                                            if (
                                                                "NoMatchFound"
                                                                in log_msg
                                                            ):
                                                                self.log.info(
                                                                    "The evidence hash does"
                                                                    " not match the hash of any quarantined files."
                                                                    "Or defender block the quarantine file during"
                                                                    " hash calculation."
                                                                )
                                                            machine.run_script_live_response_finished = (
                                                                True
                                                            )
                                                        else:
                                                            if file_counter < 1:
                                                                file_counter += 1
                                                                self.log.info(
                                                                    f"No quarantined items for threat {threat_name} found waiting to get the file"
                                                                )
                                                                sleep(300)
                                                                continue
                                                            self.log.info(
                                                                "No Quarantine Files Found"
                                                            )
                                        machine.run_script_live_response_finished = True
                                        self.log.info(
                                            "Run script live response job successfully finished for machine %s"
                                            % machine.id
                                        )
                                    else:
                                        sleep(MACHINE_ACTION.SLEEP)
                                        live_response_counter += 1
                                        self.log.info(
                                            "Attempting %d Resubmit live response.."
                                            % (live_response_counter)
                                        )
                        except Exception as err:
                            self.log.error(
                                "Failed to create run script live response job for machine %s - Error: %s"
                                % (machine.id, err)
                            )
                            live_response_counter += 1
                    else:
                        # waiting the machine for pending live response jobs
                        sleep(MACHINE_ACTION.SLEEP)
                        # increment timeout_counter to check timeout in While loop
                        machine.timeout_counter += 1

                if MACHINE_ACTION.MACHINE_RETRY <= machine.timeout_counter:
                    self.log.error(
                        "Machine %s was not available during the timeout (%s seconds)"
                        % (machine.id, MACHINE_ACTION.MACHINE_TIMEOUT)
                    )
                if MACHINE_ACTION.MACHINE_RETRY <= live_response_counter:
                    self.log.error("Maximum number of live response retries exceeded")

        return machines

    def download_evidences(self, evidences: list) -> list:
        """
        Download and extract evidence files
        :param evidences: list of evidence objects
        :exception: when evidence file is not properly downloaded or extracted
        :return evidences: list of evidence objects with downloaded data in memory
        """

        # Initial list to store successfully downloaded evidences
        downloaded_evidences = []
        self.log.info("Downloading %d evidences" % len(evidences))

        for evidence in evidences:
            if evidence.live_response.download_url is not None:
                self.log.info("Downloading evidence %s" % evidence.sha256)

                try:
                    response = self.retry_request(
                        method="GET",
                        url=evidence.live_response.download_url,
                        stream=True,
                    )
                    if response.ok:
                        self.log.info(
                            "Evidence %s downloaded successfully. Response code: %d"
                            % (evidence.sha256, response.status_code)
                        )
                        compressed_data = BytesIO(response.content)
                        try:
                            with GzipFile(
                                fileobj=compressed_data, mode="rb"
                            ) as decompressed:
                                evidence.downloaded_file_data = decompressed.read()
                                self.log.info(
                                    "Evidence %s decompressed successfully"
                                    % evidence.sha256
                                )
                                downloaded_evidences.append(evidence)
                        except Exception as err:
                            self.log.error(
                                "Failed to decompress evidence %s - Error: %s"
                                % (evidence.sha256, err)
                            )
                    else:
                        self.log.error(
                            "Failed to download evidence %s - HTTP Status Code: %d"
                            % (evidence.sha256, response.status_code)
                        )
                except Exception as err:
                    self.log.error(
                        "Failed to download evidence %s - Error: %s"
                        % (evidence.sha256, err)
                    )

        return downloaded_evidences

    def enrich_alerts(self, evidence: Evidence, sample_data: dict) -> None:
        """
        Enrich alerts with JoeSandbox Analyzer submission metadata
        https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/update-alert
        :param evidence: evidence object
        :param sample_data: dict object which contains summary data about the sample
        :exception: when alert is not updated properly
        :return void:
        """
        comment = "Joe Sandbox Analysis:\n\n"
        comment += "Evidence SHA256:\n"
        comment += sample_data["sha256"] + "\n"
        comment += "Detection: %s\n" % sample_data["detection"].upper()
        comment += "Score: %d\n" % sample_data["score"]

        comment += "Classifications:\n"
        comment += sample_data["classification"] + "\n"

        comment += "Threat Names:\n"
        comment += sample_data["threatname"] + "\n"

        comment += (
            "Analysis Url: "
            + JOE_CONFIG.BASE_URL
            + "/analysis/%s\n" % sample_data["analysisid"]
        )

        if b64encode(comment.encode("utf-8")).decode("utf-8") not in evidence.comments:
            for alert_id in evidence.alert_ids:
                try:
                    request_data = {"comment": comment}
                    request_url = self.config.URL + "/api/alerts/%s" % alert_id
                    response = self.retry_request(
                        method="PATCH",
                        url=request_url,
                        data=dumps(request_data),
                        headers=self.headers,
                    )

                    if response.status_code != 200:
                        self.log.error(
                            "Failed to update alert %s - Error: %s"
                            % (alert_id, response.text)
                        )
                    else:
                        self.log.info(f"Successfully update alert {alert_id}")

                except Exception as err:
                    self.log.error(
                        "Failed to update alert %s - Error: %s" % (alert_id, err)
                    )

    def retry_request(
        self,
        method: str,
        url: str,
        retries: int = DEFENDER_API.DEFENDER_API_RETRY,
        backoff: int = DEFENDER_API.DEFENDER_API_TIMEOUT,
        param: Union[dict, None] = None,
        headers: Union[dict, None] = None,
        data: Union[dict, str, MultipartEncoder, None] = None,
        stream: Union[bool, None] = None,
    ) -> Response:
        """
        Retries the given API request in case of server errors or rate-limiting (HTTP 5xx or 429).

        :param method: HTTP method (GET, POST, etc.)
        :param url: URL to make the request to
        :param retries: Number of retry attempts
        :param backoff: backoff time in seconds
        :param headers: Headers to pass with the request
        :param param: Data to pass with the request (if applicable, e.g., for POST requests)
        :param data: Body
        :param stream
        :return: Response object from the request or None if it fails after retries
        """
        attempt = 0
        while attempt <= retries:
            try:
                response = requests.request(
                    method, url, params=param, headers=headers, data=data, stream=stream
                )
                response.raise_for_status()
                return response
            except requests.HTTPError as herr:
                if attempt < retries:
                    if response.status_code == AUTH_ERROR_STATUS_CODE:
                        self.authenticate()
                        continue
                    if response.status_code in RETRY_STATUS_CODE:
                        self.log.warning(
                            f"Attempt {attempt + 1}: Server error or too many requests. Retrying..."
                        )
                        sleep(backoff // retries)
                        attempt += 1
                        continue
                    json_response = response.json()
                    err_msg = json_response.get("error", {}).get("message", "")
                    self.log.error(f"Error In Defender API calling: {err_msg}")
                    raise Exception(
                        "An error occurred during MicrosoftDefender Retry Request"
                    ) from herr
                self.log.error(f"Request failed after {retries} retries. Error: {herr}")
                raise Exception(
                    "An error occurred during MicrosoftDefender Retry Request"
                ) from herr
            except requests.ConnectionError as cerr:
                if attempt < retries:
                    self.log.warning(
                        f"Attempt {attempt + 1}: Request Connection error or too many requests. Retrying..."
                    )
                    sleep(backoff // retries)
                    attempt += 1
                    continue
                raise Exception(
                    "An error occurred during MicrosoftDefender Retry Request"
                ) from cerr
            except Exception as err:
                raise Exception(
                    "An error occurred during MicrosoftDefender Retry Request"
                ) from err
        raise Exception("Failed to complete microsoft request after multiple retries.")
