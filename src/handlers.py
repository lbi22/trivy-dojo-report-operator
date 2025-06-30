import json
from io import BytesIO
import requests
from requests.exceptions import HTTPError, RequestException
import kopf
import copy

import settings

import prometheus_client as prometheus

prometheus.start_http_server(9090)
REQUEST_TIME = prometheus.Summary(
    "request_processing_seconds", "Time spent processing request"
)
PROMETHEUS_DISABLE_CREATED_SERIES = True
c = prometheus.Counter("defectdojo_requests_total", "Total DefectDojo Import/Re-import Requests", ["status"])

proxies = {
    "http": settings.HTTP_PROXY,
    "https": settings.HTTPS_PROXY,
} if settings.HTTP_PROXY or settings.HTTPS_PROXY else None


def check_allowed_reports(report: str):
    """
    Validates if the report type is in the allowed list defined in the function.
    Exits the program if the report type is not allowed.
    """
    allowed_reports: list[str] = [
        "configauditreports",
        "vulnerabilityreports",
        "exposedsecretreports",
        "infraassessmentreports",
        "rbacassessmentreports",
    ]

    if report not in allowed_reports:
        print(
            f"[ERROR] report {report} is not allowed. Allowed reports: {allowed_reports}"
        )
        exit(1)


@kopf.on.startup()
def configure(settings: kopf.OperatorSettings, **_):
    """
    Configure kopf operator settings on startup.
    """
    settings.watching.connect_timeout = 60
    settings.watching.server_timeout = 600
    settings.watching.client_timeout = 610

    settings.persistence.diffbase_storage = kopf.MultiDiffBaseStorage(
        [
            kopf.StatusDiffBaseStorage(field="status.diff-base"),
        ]
    )

def send_batch_to_dojo(logger, headers: dict, base_data: dict, report_body: dict, proxies: dict | None):
    """
    Sends a single batch of vulnerabilities to the DefectDojo reimport-scan API.

    This function takes a report body containing a subset of vulnerabilities
    and sends it to DefectDojo. It handles the HTTP request and error checking.

    """
    json_string: str = json.dumps(report_body)
    json_file: BytesIO = BytesIO(json_string.encode("utf-8"))
    report_file: dict = {"file": ("report.json", json_file)}

    try:
        response: requests.Response = requests.post(
            settings.DEFECT_DOJO_URL + "/api/v2/reimport-scan/",
            headers=headers,
            data=base_data,
            files=report_file,
            verify=True,
            proxies=proxies,
            timeout=120
        )
        response.raise_for_status()
        num_vulns = len(report_body.get('report', {}).get('vulnerabilities', []))
        logger.info(f"Successfully submitted a batch of {num_vulns} vulnerabilities.")
        logger.debug(f"DefectDojo response: {response.content}")
    except HTTPError as http_err:
        raise kopf.TemporaryError(
            f"HTTP error occurred on batch submission: {http_err} - {response.content}. Retrying...",
            delay=60,
        )
    except RequestException as req_err:
        raise kopf.TemporaryError(
            f"Request error occurred on batch submission: {req_err}. Retrying...",
            delay=60,
        )


labels: dict = {}
if settings.LABEL and settings.LABEL_VALUE:
    labels = {settings.LABEL: settings.LABEL_VALUE}
elif settings.LABEL:
    labels = {settings.LABEL: kopf.PRESENT}


for report in settings.REPORTS:
    # check if reports are allowed
    check_allowed_reports(report)

    @REQUEST_TIME.time()
    @kopf.on.create(report.lower() + ".aquasecurity.github.io", labels=labels)
    def send_to_dojo(body, meta, logger, **_):
        """
        Main handler that processes a report, splits it into batches if necessary,
        and sends them to DefectDojo.
        """
        kind = body.get('kind', 'UnknownKind')
        name = meta.get('name', 'UnknownName')
        logger.info(f"Working on {kind} {name}")

        vulnerabilities = body.get('report', {}).get('vulnerabilities', [])
        
        if not vulnerabilities:
            logger.info(f"Report {name} contains no vulnerabilities. Nothing to send.")
            return

        logger.info(f"Found {len(vulnerabilities)} total vulnerabilities. Processing in batches of {settings.DEFECT_DOJO_VULNERABILITY_BATCH_SIZE}.")

        _DEFECT_DOJO_ENGAGEMENT_NAME = eval(settings.DEFECT_DOJO_ENGAGEMENT_NAME) if settings.DEFECT_DOJO_EVAL_ENGAGEMENT_NAME else settings.DEFECT_DOJO_ENGAGEMENT_NAME
        _DEFECT_DOJO_PRODUCT_NAME = eval(settings.DEFECT_DOJO_PRODUCT_NAME) if settings.DEFECT_DOJO_EVAL_PRODUCT_NAME else settings.DEFECT_DOJO_PRODUCT_NAME
        _DEFECT_DOJO_PRODUCT_TYPE_NAME = eval(settings.DEFECT_DOJO_PRODUCT_TYPE_NAME) if settings.DEFECT_DOJO_EVAL_PRODUCT_TYPE_NAME else settings.DEFECT_DOJO_PRODUCT_TYPE_NAME
        _DEFECT_DOJO_SERVICE_NAME = eval(settings.DEFECT_DOJO_SERVICE_NAME) if settings.DEFECT_DOJO_EVAL_SERVICE_NAME else settings.DEFECT_DOJO_SERVICE_NAME
        _DEFECT_DOJO_ENV_NAME = eval(settings.DEFECT_DOJO_ENV_NAME) if settings.DEFECT_DOJO_EVAL_ENV_NAME else settings.DEFECT_DOJO_ENV_NAME
        _DEFECT_DOJO_TEST_TITLE = eval(settings.DEFECT_DOJO_TEST_TITLE) if settings.DEFECT_DOJO_EVAL_TEST_TITLE else settings.DEFECT_DOJO_TEST_TITLE

        headers: dict = {
            "Authorization": "Token " + settings.DEFECT_DOJO_API_KEY,
            "Accept": "application/json",
        }

        data: dict = {
            "active": settings.DEFECT_DOJO_ACTIVE,
            "verified": settings.DEFECT_DOJO_VERIFIED,
            "close_old_findings": settings.DEFECT_DOJO_CLOSE_OLD_FINDINGS,
            "close_old_findings_product_scope": settings.DEFECT_DOJO_CLOSE_OLD_FINDINGS_PRODUCT_SCOPE,
            "push_to_jira": settings.DEFECT_DOJO_PUSH_TO_JIRA,
            "minimum_severity": settings.DEFECT_DOJO_MINIMUM_SEVERITY,
            "auto_create_context": settings.DEFECT_DOJO_AUTO_CREATE_CONTEXT,
            "deduplication_on_engagement": settings.DEFECT_DOJO_DEDUPLICATION_ON_ENGAGEMENT,
            "scan_type": "Trivy Scan",
            "engagement_name": _DEFECT_DOJO_ENGAGEMENT_NAME,
            "product_name": _DEFECT_DOJO_PRODUCT_NAME,
            "product_type_name": _DEFECT_DOJO_PRODUCT_TYPE_NAME,
            "service": _DEFECT_DOJO_SERVICE_NAME,
            "environment": _DEFECT_DOJO_ENV_NAME,
            "test_title": _DEFECT_DOJO_TEST_TITLE,
            "do_not_reactivate": settings.DEFECT_DOJO_DO_NOT_REACTIVATE,
        }

        logger.debug(f"Base data for DefectDojo: {data}")

        batch_size = settings.DEFECT_DOJO_VULNERABILITY_BATCH_SIZE
        total_batches = (len(vulnerabilities) + batch_size - 1) // batch_size
        
        for i in range(0, len(vulnerabilities), batch_size):
            current_batch_vulns = vulnerabilities[i:i + batch_size]
            batch_report_body = copy.deepcopy(body)
            batch_report_body['report']['vulnerabilities'] = current_batch_vulns

            logger.info(f"Submitting batch {i//batch_size + 1}/{total_batches}...")

            try:
                send_batch_to_dojo(logger, headers, data, batch_report_body, proxies)
                c.labels("success").inc()
            except kopf.TemporaryError as e:
                c.labels("failed").inc()
                raise e
            except Exception as e:
                c.labels("failed").inc()
                raise kopf.TemporaryError(f"An unexpected error occurred during batch processing: {e}", delay=60)
        
        logger.info(f"Finished processing all {total_batches} batches for {kind} {name}")
