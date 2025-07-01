"""
JoeSandbox API
"""

# pylint: disable=invalid-name
# pylint: disable=line-too-long
# pylint: disable=consider-using-f-string

from datetime import datetime
from io import BytesIO
from time import sleep
from typing import Any, Generator

from jbxapi import ConnectionError, InvalidApiKeyError, InvalidParameterError
from jbxapi import JoeSandbox as JoeAPI
from jbxapi import PermissionError, ServerOfflineError

from ..const import JOE_CONFIG
from .defender_models import Machine


class JoeSandbox:
    """
    Wrapper class for JoeSandboxRESTAPI modules and functions.
    Import this class to submit samples and retrieve reports.
    """

    def __init__(self, log):
        """
        Initialize, authenticate the JoeSandbox instance,
        use JoeSandboxConfig as configuration
        :param log: logger instance
        :return void
        """
        self.api = None
        self.log = log
        self.config = JOE_CONFIG

        self.authenticate()

    def authenticate(self):
        """
        Authenticate and verify the JoeSandbox REST API connection.
        :raises: Various exceptions if connection or config is invalid.
        """
        try:
            self.api = JoeAPI(
                apiurl=self.config.API_URL,
                apikey=self.config.API_KEY,
                verify_ssl=self.config.SSL_VERIFY,
                user_agent=self.config.CONNECTOR_NAME,
                accept_tac=self.config.ACCEPT_TAC,
                retries=self.config.JOE_API_RETRIES,
                timeout=self.config.JOE_API_TIMEOUT,
            )
            self.api.server_online()
            self.log.info(
                "Successfully authenticated and verified JoeSandbox %s API",
                self.config.API_KEY_TYPE,
            )
        except InvalidApiKeyError as inerr:
            self.log.error("Invalid API key for JoeSandbox: %s", inerr)
            raise
        except PermissionError as perr:
            self.log.error("The user does not have the required permissions: %s", perr)
            raise
        except ConnectionError as cerr:
            self.log.error("Failed to connect to JoeSandbox server: %s", cerr)
            raise
        except ServerOfflineError as serr:
            self.log.error("Joe Sandbox is offline: %s", serr)
            raise
        except Exception as err:
            self.log.error("Unexpected error during JoeSandbox authentication: %s", err)
            raise

    def get_analysis(self, query: str) -> list | None:
        """
        Fetch the analysis associated based on a given query (hash or url) from JoeSandbox.

        Args:
            query (str): The SHA-256 hash of the file or url for which the analysis
            is being requested.

        Returns:
            list or None: A list of analysis metadata matching the hash value, or None
            if no analysis is available or the operation fails.
        """
        try:
            response = self.api.analysis_search(query)
            if response:
                self.log.info("Analysis for %s retrieved from JoeSandbox", query)
                return response
        except InvalidParameterError as inperr:
            self.log.error("An API parameter is invalid.. Error: %s", inperr)
        except ConnectionError as cerr:
            self.log.error("Failed to connect to JoeSandbox server.. Error: %s", cerr)
        except Exception as err:
            self.log.error(
                "Unexpected error while retrieving analysis for %s: %s", query, err
            )

        return None

    def get_analysis_info(self, web_id: str) -> dict | None:
        """
        Fetch the analysis associated with a particular web_id from JoeSandbox.

        Args:
            web_id (str): The web id of the analysis.
        Returns:
            dict or None: A dictionary containing the analysis result if found, or None
            if no analysis is available or the operation fails.
        """
        try:
            response = self.api.analysis_info(web_id)
            if response:
                self.log.info("Analysis retrieved from JoeSandbox")
                return response
        except InvalidParameterError as inperr:
            self.log.error("An API parameter is invalid... Error: %s", inperr)
        except ConnectionError as cerr:
            self.log.error(
                "Failed to connect to JoeSandbox server while fetching analysis info.. Error: %s",
                cerr,
            )
        except Exception as err:
            self.log.error("Unexpected error while retrieving analysis: %s", err)

        return None

    def parse_analysis_data(self, analysis: list[dict] | dict | None) -> dict:
        """
        Extracts relevant metadata from a JoeSandbox analysis result.

        Args:
            analysis (list[dict] | dict | None): A list of analysis metadata dictionaries, or a single one.

        Returns:
            dict: A dictionary containing extracted metadata, or empty if detection is 'unknown' or input is invalid.
        """
        if not analysis:
            return {}
        if isinstance(analysis, list):
            analysis_data = max(analysis, key=lambda x: x.get("score", 0))
        elif isinstance(analysis, dict):
            analysis_data = analysis
        else:
            self.log.warning("Invalid analysis input type: %s", type(analysis))
            return {}

        if analysis_data.get("detection", "").lower() == "unknown":
            self.log.warning("Analysis detection is 'unknown'. Ignoring this analysis.")
            return {}

        keys_to_extract = [
            "webid",
            "detection",
            "threatname",
            "classification",
            "filename",
            "sha256",
            "score",
            "analysisid",
        ]

        return {
            key: analysis_data[key] for key in keys_to_extract if key in analysis_data
        }

    def get_av_submissions(self, machine: Machine, submissions: list) -> list:
        """
        Retrieve Antivirus submission
        :param machine: Machine object
        :param submissions: list of the submission
        :return list
        """
        if len(machine.av_evidences) > 0:
            if machine.run_script_live_response_finished:
                for evidence in machine.av_evidences.keys():
                    for submission in submissions:
                        submission["evidence"] = machine.av_evidences[evidence]
        return submissions

    def submit_files_to_joesandbox(
        self, submission_items: list, threat_name: str, source_type: str = "AV"
    ) -> list:
        """
        Function to submit files to JoeSandbox from AV or EDR alerts.

        Args:
            submission_items (list): List of file dicts (for AV) or evidence objects (for EDR).
            threat_name (str): Name of the threat.
            source_type (str): "AV" or "EDR" to determine the structure of input items and tagging.

        Returns:
            list: A list of dictionaries containing submission details.
        """
        tag = f"MSDefender-{source_type}-Alert"
        params = {"tags": [tag, threat_name]}
        submissions = []

        for obj in submission_items:
            try:
                if source_type == "AV":
                    for _, file in obj.items():
                        response = self.api.submit_sample(sample=file, params=params)
                        if response:
                            submissions.append(
                                {
                                    "submission_id": response["submission_id"],
                                    "type": "File",
                                }
                            )
                            self.log.debug("File %s submitted to JoeSandbox", file.name)
                elif source_type == "EDR":
                    file_obj = BytesIO(obj.downloaded_file_data)
                    file_obj.name = obj.file_name
                    response = self.api.submit_sample(sample=file_obj, params=params)
                    if response:
                        submissions.append(
                            {
                                "submission_id": response["submission_id"],
                                "evidence": obj,
                                "sha256": obj.sha256,
                                "type": "File",
                            }
                        )
                        self.log.debug("File %s submitted to JoeSandbox", file_obj.name)
            except PermissionError as perr:
                self.log.error("Insufficient permissions for this API key: %s", perr)
            except InvalidParameterError as inperr:
                self.log.error("Invalid parameter in submission: %s", inperr)
            except ConnectionError as cerr:
                self.log.error("Connection to JoeSandbox failed: %s", cerr)
            except Exception as err:
                self.log.error("Unexpected error during submission: %s", err)

        self.log.info("%d files submitted to JoeSandbox", len(submissions))
        return submissions

    def submit_url(self, evidences: dict, threat_name: str) -> list:
        """
        Function to submit urls to JoeSandbox from AV or EDR alerts.

        Args:
            evidences (list): List of evidence objects.
            threat_name (str): Name of the threat.

        Returns:
            list: A list of dictionaries containing submission details.
        """
        submissions = []
        params = {"tags": ["MSDefender-URL-Alert", threat_name]}
        for evidence in evidences.values():
            try:
                url = evidence.url
                response = self.api.submit_url(url=url, params=params)
                if response:
                    submissions.append(
                        {
                            "submission_id": response["submission_id"],
                            "evidence": evidence,
                            "sha256": evidence.sha256,
                            "type": "Url",
                        }
                    )
                    self.log.debug("URL %s submitted to JoeSandbox" % url)
            except PermissionError as perr:
                self.log.error(
                    "Insufficient permissions for this API key to submit urls: %s",
                    perr,
                )
            except InvalidParameterError as inperr:
                self.log.error(
                    "An API parameter is invalid under url submission. Error: %s",
                    inperr,
                )
            except ConnectionError as cerr:
                self.log.error(
                    "Failed to connect to JoeSandbox server while submitting urls. Error: %s",
                    cerr,
                )
            except Exception as err:
                self.log.error(err)
        return submissions

    def wait_submissions(
        self, submissions: list
    ) -> Generator[dict[str, Any], None, None]:
        """
        Waiting for submission to finish
        :param submissions: list of submission

        """
        submission_objects = [
            {
                "submission_id": submission["submission_id"],
                "timestamp": None,
                "error_count": 0,
                "evidence": submission["evidence"],
                "type": submission["type"],
            }
            for submission in submissions
        ]
        self.log.info("Waiting %d submission jobs to finish" % len(submission_objects))
        while len(submission_objects) > 0:
            sleep(JOE_CONFIG.ANALYSIS_JOB_TIMEOUT / 60)
            for submission_object in submission_objects:
                try:
                    response = self.api.submission_info(
                        submission_object["submission_id"]
                    )
                    if response["status"] == "finished":
                        submission_objects.remove(submission_object)
                        self.log.info(
                            "Submission job %s finished"
                            % submission_object["submission_id"]
                        )
                        yield {
                            "finished": True,
                            "response": response,
                            "submission": submission_object,
                            "analysis_id": response.get(
                                "most_relevant_analysis", {}
                            ).get("webid", ""),
                        }
                    elif submission_object["timestamp"] is None:
                        submission_object["timestamp"] = datetime.now()
                    elif (
                        datetime.now() - submission_object["timestamp"]
                    ).seconds >= JOE_CONFIG.ANALYSIS_JOB_TIMEOUT:
                        submission_objects.remove(submission_object)
                        self.log.error(
                            "Submission job %s exceeded the configured time threshold."
                            % submission_object["submission_id"]
                        )
                        yield {
                            "finished": False,
                            "response": response,
                            "submission": submission_object,
                        }
                except InvalidParameterError as inperr:
                    self.log.error(
                        "An API parameter is invalid while getting analysis info. Error: %s",
                        inperr,
                    )
                except Exception as err:
                    self.log.error(str(err))
                    if submission_object["error_count"] >= 5:
                        yield {
                            "finished": False,
                            "response": None,
                            "submission": submission_object,
                        }
                    else:
                        submission_object["error_count"] += 1

        self.log.info("Submission jobs finished")
