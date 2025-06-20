"""
Main file for azure function execution
"""

import logging as log
import traceback
from hashlib import sha256
from io import BytesIO
from json import dumps

import azure.functions as func
from azure.storage.blob import BlobServiceClient

from .const import (
    ALERT,
    DEFENDER_API,
    SELECTED_VERDICTS,
    JOE_CONFIG,
)
from .lib.joesandbox import JoeSandbox
from .lib.microsoft_defender import MicrosoftDefender
from .lib.defender_models import Evidence, Machine


def group_evidences_by_machines(evidences: dict) -> list:
    """
    Helper function to group evidences by machine
    :param evidences: dict of evidence objects
    :return machines: list of machine objects which contains related evidences
    """
    machines = {}
    for evidence in evidences.values():
        selected_machine_id = list(evidence.machine_ids)[0]

        if selected_machine_id not in machines:
            machines[selected_machine_id] = Machine(selected_machine_id)

        machine = machines[selected_machine_id]
        if evidence.detection_source == ALERT.WINDOWS_DEFENDER_AV:
            machine.av_evidences[evidence.sha256] = evidence
        else:
            machine.edr_evidences[evidence.sha256] = evidence

    return list(machines.values())


def update_evidence_machine_ids(machines: list) -> list:
    """
    Group Evidences By Machine
    :param machines:
    :return: List of Machines
    """
    evidences_by_machine: dict = {}

    for machine in machines:
        for evidence in machine.av_evidences.values():
            evidences_by_machine.setdefault(evidence.sha256, set()).add(machine.id)
            evidence.machine_ids = evidences_by_machine[evidence.sha256]
        for evidence in machine.edr_evidences.values():
            evidences_by_machine.setdefault(evidence.sha256, set()).add(machine.id)
            evidence.machine_ids = evidences_by_machine[evidence.sha256]

    return machines


def list_all_blob(machines: list) -> list:
    """
    List all file(blob) uploaded by powershell scripts during the AV alerts,
    returns list of file object and delete the blob from container.
    :param machines: Machine object
    """
    file_objects = []
    try:
        for machine in machines:
            if not machine.run_script_live_response_finished:
                continue

            blob_service_client = BlobServiceClient.from_connection_string(
                DEFENDER_API.CONNECTION_STRING
            )
            container_client = blob_service_client.get_container_client(
                DEFENDER_API.CONTAINER_NAME
            )
            blobs = container_client.list_blobs()

            for blob in blobs:
                blob_data = (
                    container_client.get_blob_client(blob.name)
                    .download_blob()
                    .readall()
                )
                sha256_hash = sha256(blob_data).hexdigest()
                file_obj = BytesIO(blob_data)
                file_obj.name = blob.name
                file_objects.append({sha256_hash: file_obj})
                container_client.delete_blob(blob.name)
        log.info("Retrieved %d files from Azure blob storage", len(file_objects))

    except Exception as ex:
        log.error("Error retrieving files from Azure blob storage: %s", ex)
    return file_objects


def run(
    alert: dict, threat_name: str, detection_source: str, threat_family: str
) -> None:
    """
    :param alert:
    :param threat_name:
    :param detection_source:
    :param threat_family:
    :return: None
    """
    ms_defender = MicrosoftDefender(log)
    joe_security = JoeSandbox(log)

    found_evidences, download_file_evidences, resubmit_file_evidences = {}, {}, {}
    download_url_evidences, resubmit_url_evidences = {}, {}
    submissions = []

    evidences = ms_defender.get_evidences(alert.get("id", ""))

    for key, evidence in evidences.items():
        sample = joe_security.get_analysis(key)
        if sample:
            metadata = joe_security.parse_sample_data(sample)
            if (
                JOE_CONFIG.RESUBMIT
                and metadata["detection"] in JOE_CONFIG.RESUBMISSION_VERDICTS
            ):
                log.info("Analysis results for %s exists in JoeSandbox.", key)
                log.info(
                    "Resubmit is set to true, %s will be resubmitted to JoeSandbox for analysis.",
                    key,
                )
                if evidence.entity_type == ALERT.EVIDENCE_FILE_TYPE:
                    resubmit_file_evidences[key] = evidence
                elif evidence.entity_type == ALERT.EVIDENCE_URL_TYPE:
                    resubmit_url_evidences[key] = evidence
            else:
                log.info("Analysis results for %s exists in JoeSandbox.", key)
                log.info(
                    "Resubmit is set to false,"
                    " %s will not be resubmitted to JoeSandbox for analysis.",
                    key,
                )
                evidence.joe_sample = sample
                found_evidences[key] = evidence
        else:
            log.info("Analysis results for %s does not exist in JoeSandbox.", key)
            log.info(
                "%s will be downloaded and submitted to JoeSandbox for analysis.", key
            )
            if evidence.entity_type == ALERT.EVIDENCE_FILE_TYPE:
                download_file_evidences[key] = evidence
            elif evidence.entity_type == ALERT.EVIDENCE_URL_TYPE:
                download_url_evidences[key] = evidence
    if found_evidences:
        log.info("%d evidences found on JoeSandbox", len(found_evidences))
    if not JOE_CONFIG.RESUBMIT:
        for evidence in found_evidences.values():
            sample_data = joe_security.parse_sample_data(evidence.joe_sample)
            if sample_data["detection"] in SELECTED_VERDICTS:
                enrich_alerts(ms_defender, evidence, sample_data)

    download_file_evidences.update(resubmit_file_evidences)
    download_url_evidences.update(resubmit_url_evidences)
    if download_file_evidences:
        log.info("Alert evidence type Files are being processed..")
        submissions.extend(
            process_file(
                download_file_evidences,
                detection_source,
                threat_name,
                ms_defender,
                joe_security,
                threat_family,
            )
        )
    if download_url_evidences:
        log.info("Alert evidence type URLs are being processed..")
        submissions.extend(
            process_url(download_url_evidences, joe_security, threat_family)
        )

    process_submissions(joe_security, ms_defender, submissions)


def process_file(
    download_evidences: dict,
    detection_source: str,
    threat_name: str,
    ms_defender: MicrosoftDefender,
    joe_security: JoeSandbox,
    threat_family: str,
) -> list:
    """
    Process the EDR and AV alert file
    :param download_evidences:  file to submit
    :param detection_source: Type of alert
    :param threat_name: Name of the threat
    :param ms_defender: MicrosoftDefender Object
    :param joe_security: JoeSandbox object
    :param threat_family: Threat Family
    """
    log.info(
        "In total %d file evidences need to be"
        " downloaded from defender and submitted to JoeSandbox.",
        len(download_evidences),
    )
    submissions_list = []

    machines = group_evidences_by_machines(download_evidences)
    machines = update_evidence_machine_ids(machines)
    log.info("evidences found on %d machines.", len(machines))

    if detection_source == ALERT.WINDOWS_DEFENDER_AV:
        if ms_defender.upload_ps_script_to_library():
            machines = ms_defender.run_av_submission_script(machines, threat_name)
            if machines:
                file_objects = list_all_blob(machines)
                if len(file_objects) > 0:
                    submissions = joe_security.submit_av_files(
                        file_objects, threat_family
                    )
                    submissions_list.extend(
                        joe_security.get_av_submissions(machines[0], submissions)
                    )
                else:
                    log.info("AV Alert: No file found to submit")

    if detection_source == ALERT.WINDOWS_DEFENDER_ATP:
        machines = ms_defender.run_edr_live_response(machines)
        successful_evidences = [
            evidence
            for machine in machines
            for evidence in machine.get_successful_edr_evidences()
        ]
        log.info(
            "%d File evidences successfully collected with live response.",
            len(successful_evidences),
        )

        downloaded_evidences = ms_defender.download_evidences(successful_evidences)
        if len(downloaded_evidences) > 0:
            log.info(
                "EDR Alert: In total %d evidence files downloaded successfully.",
                len(downloaded_evidences),
            )
            submissions_list.extend(
                joe_security.submit_edr_samples(downloaded_evidences, threat_family)
            )
        else:
            log.info("EDR Alert: No file found to submit")

    return submissions_list


def process_url(
    download_evidences: dict, joe_security: JoeSandbox, threat_family: str
) -> list:
    """
    Process URL
    :param download_evidences: URL evidence
    :param joe_security: JoeSandbox Object
    :param threat_family: Threat family
    :return list
    """
    log.info(
        "In total, %d URL evidences needs to be downloaded and submitted to JoeSandbox.",
        len(download_evidences),
    )
    url_submission = joe_security.submit_url(download_evidences, threat_family)
    return url_submission


def enrich_alerts(
    ms_defender: MicrosoftDefender, evidence: Evidence, sample_data: dict
) -> None:
    """
    :param ms_defender: Microsoft Object
    :param evidence: Evidences
    :param sample_data: Sample Data
    :return: None
    """
    ms_defender.enrich_alerts(evidence, sample_data)


def process_submissions(
    joe_security: JoeSandbox, ms_defender: MicrosoftDefender, submissions: list
) -> None:
    """
    :param joe_security: JoeSecurity Object
    :param ms_defender: Microsoft Object
    :param submissions: Child Sample ID
    :return: None
    """
    for result in joe_security.wait_submissions(submissions):
        submission = result["submission"]
        evidence = submission["evidence"]

        if result["finished"]:
            sample = joe_security.get_analysis_info(result["analysis_id"])
            sample_data = joe_security.parse_sample_data(sample)

            if sample_data["detection"] in SELECTED_VERDICTS:
                enrich_alerts(ms_defender, evidence, sample_data)


def main(req: func.HttpRequest) -> func.HttpResponse:
    """
    Main Function
    """
    log.info("Resource Requested: %s", func.HttpRequest)

    try:
        alert = req.params.get("alert", {}) or req.get_json().get("alert", {})
        threat_name = req.params.get("threat_name", "") or req.get_json().get(
            "threat_name", ""
        )
        threat_family = req.params.get("threat_family", "") or req.get_json().get(
            "threat_family", ""
        )
        detection_source = req.params.get("detection_source", "") or req.get_json().get(
            "detection_source", ""
        )

        if not alert:
            return func.HttpResponse(
                "Invalid Request. Missing 'alert' parameter.", status_code=400
            )

        log.info(
            "Processing Alert %s and threat_name %s.", alert.get("id"), threat_name
        )

        run(alert, threat_name, detection_source, threat_family)
        return func.HttpResponse(
            dumps({"message": "Successfully submitted and enriched alert"}),
            status_code=200,
        )

    except Exception as ex:
        error_msg = traceback.format_exc()
        log.error("Exception Occurred: %s", str(ex))
        log.error(error_msg)
        return func.HttpResponse("Internal Server Exception", status_code=500)
