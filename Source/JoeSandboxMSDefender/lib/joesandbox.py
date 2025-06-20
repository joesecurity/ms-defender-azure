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

from jbxapi import JoeException, JoeSandbox as JoeAPI

from ..const import JOE_CONFIG
from .Models import Machine


class JoeSandbox:
    """
    Wrapper class for JoeSandboxRESTAPI modules and functions.
    Import this class to submit samples and retrieve reports.
    """

    def __init__(self, log):
        """
        Initialize, authenticate and healthcheck the JoeSandbox instance,
        use JoeSandboxConfig as configuration
        :param log: logger instance
        :return void
        """
        self.api = None
        self.log = log
        self.config = JOE_CONFIG

        self.authenticate()
        self.healthcheck()

    def healthcheck(self):
        """
        Healtcheck for JoeSandbox REST API, uses system_info endpoint
        :raise: When healtcheck error occured during the connection wih REST API
        :return: boolean status of JoeSandbox REST API
        """

        try:
            self.api.server_info()
            self.log.info("JoeSandbox Healthcheck is successfully.")
            return True
        except Exception as err:
            self.log.error("Healthcheck failed. Error: %s" % (err))
            raise

    def authenticate(self):
        """
        Authenticate the JoeSandbox REST API
        :raise: When API Key is not properly configured
        :return: void
        """
        try:
            self.api = JoeAPI(
                apiurl=self.config.URL,
                apikey=self.config.API_KEY,
                verify_ssl=self.config.SSL_VERIFY,
                user_agent=self.config.CONNECTOR_NAME,
                accept_tac=self.config.ACCEPT_TAC,
                retries=JOE_CONFIG.JOE_API_RETRIES,
                timeout=JOE_CONFIG.JOE_API_TIMEOUT,
            )
            self.log.info(
                "Successfully authenticated the JoeSandbox %s API"
                % self.config.API_KEY_TYPE
            )
        except Exception as err:
            self.log.error(err)
            raise

    def get_analysis(self, query: str) -> list | None:
        """
        Fetch the analysis associated with a particular SHA-256 hash from JoeSandbox.

        Args:
            query (str): The SHA-256 hash of the file or resource for which the analysis
            is being requested.

        Returns:
            dict or None: A dictionary containing the analysis result if found, or None
            if no analysis is available or the operation fails.
        """
        try:
            response = self.api.analysis_search(query)
            if response:
                self.log.info("Analysis for %s retrieved from JoeSandbox", query)
                return response
        except JoeException as jerr:
            self.log.error(
                "Analysis for %s couldn't be found in JoeSandbox database. Error: %s",
                query,
                jerr,
            )
        except Exception as err:
            self.log.error(
                "Unexpected error while retrieving analysis for %s: %s", query, err
            )

        return None

    def get_analysis_info(self, web_id: str) -> list | None:
        """
        Fetch the analysis associated with a particular SHA-256 hash from JoeSandbox.

        Args:
            web_id (str): The SHA-256 hash of the file or resource for which the analysis
            is being requested.

        Returns:
            dict or None: A dictionary containing the analysis result if found, or None
            if no analysis is available or the operation fails.
        """
        try:
            response = self.api.analysis_info(web_id)
            if response:
                self.log.info("Analysis retrieved from JoeSandbox")
                return response
        except JoeException as jerr:
            self.log.error(
                "Analysis couldn't be found in JoeSandbox database. Error: %s",
                jerr,
            )
        except Exception as err:
            self.log.error("Unexpected error while retrieving analysis: %s", err)

        return None

    def parse_sample_data(self, sample: list | dict | None) -> dict:
        """
        Parse and extract summary data about the sample with keys below
        :param sample: list object which contains raw data about the sample
        :return sample_data: dict objects which contains parsed data about the sample
        """
        sample_data = {}
        keys = [
            "webid",
            "detection",
            "threatname",
            "classification",
            "filename",
            "sha256",
            "score",
            "analysisid",
        ]
        if sample:
            if isinstance(sample, list):
                high_score_sample = max(sample, key=lambda x: x.get("score", 0))
            else:
                high_score_sample = sample
            for key in keys:
                if key in high_score_sample:
                    sample_data[key] = high_score_sample[key]
        return sample_data

    def submit_av_files(self, file_objects: list, threat_name: str) -> list:
        """
        Submit a list of antivirus files to an external service with associated parameters and logs the submission status.

        Arguments:
            file_objects (list[dict[str, IO]]): A list of dictionaries where each dictionary
                maps a file hash (string) to a file-like object.
            threat_name (str): A string representing the name of the detected threat. Can be None.

        Returns:
            list[dict[str, str]]: A list of dictionaries, each containing the submission ID of a
                successfully uploaded file.

        Raises:
            This function does not explicitly raise exceptions but captures and logs errors
            during file submission.

        """
        params = {"tags": ["MSDefender-AV-Alert", threat_name]}
        submissions = []
        for file_obj in file_objects:
            try:
                for _, file in file_obj.items():
                    response = self.api.submit_sample(sample=file, params=params)
                    if response:
                        submissions.append(
                            {"submission_id": response["submission_id"], "type": "File"}
                        )
                        self.log.debug("File %s submitted to JoeSandbox" % file.name)

            except Exception as err:
                self.log.error(err)
        return submissions

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

    def submit_edr_samples(self, evidences: list, threat_name: str) -> list:
        """
        Submit sample to JoeSandbox Sandbox to analyze
        :param evidences: list of evidences which downloaded from Microsoft Defender for Endpoint
        :param threat_name: Threat name
        :return submissions: dict object which contains submission_id and sample_id
        """
        params = {"tags": ["MSDefender-EDR-Alert", threat_name]}
        submissions = []

        for evidence in evidences:
            try:
                file_obj = BytesIO(evidence.download_file_path)
                file_obj.name = evidence.file_name
                response = self.api.submit_sample(sample=file_obj, params=params)
                if response:
                    submissions.append(
                        {
                            "submission_id": response["submission_id"],
                            "evidence": evidence,
                            "sha256": evidence.sha256,
                            "type": "File",
                        }
                    )
                    self.log.debug("File %s submitted to JoeSandbox" % file_obj.name)
            except Exception as err:
                self.log.error(err)

        self.log.info("%d files submitted to JoeSandbox" % len(submissions))
        return submissions

    def submit_url(self, evidences: dict, threat_name: str) -> list:
        """
        Submit URL to JoeSandbox
        :param evidences: URL to submit
        :param threat_name: Threat name
        :return list of submissions
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
                            "Submission job %d exceeded the configured time threshold."
                            % submission_object["submission_id"]
                        )
                        yield {
                            "finished": False,
                            "response": response,
                            "submission": submission_object,
                        }

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
