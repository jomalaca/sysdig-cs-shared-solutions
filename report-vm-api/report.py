#!/usr/bin/env python

import requests
import argparse
import json
import datetime
import pandas
import os
import time
import logging
from operator import itemgetter
import urllib.parse

# store script start time
startTime = time.time()
scansCount = 0

# regions dictionary
api_endpoints = {
    "au1": {
        "old": "app.au1.sysdig.com",
        "new": "api.au1.sysdig.com",
    },
    "eu1": {
        "old": "eu1.app.sysdig.com",
        "new": "api.eu1.sysdig.com",
    },
    "in1": {
        "old": "app.in1.sysdig.com",
        "new": "api.in1.sysdig.com",
    },
    "me2": {
        "old": "app.me2.sysdig.com",
        "new": "api.me2.sysdig.com",
    },
    "us1": {
        "old": "secure.sysdig.com",
        "new": "api.us1.sysdig.com",
    },
    "us2": {
        "old": "us2.app.sysdig.com",
        "new": "api.us2.sysdig.com",
    },
    "us3": {
        "old": "app.us3.sysdig.com",
        "new": "api.us3.sysdig.com",
    },
    "us4": {
        "old": "app.us4.sysdig.com",
        "new": "api.us4.sysdig.com",
    }
}

# Setup logger
LOG = logging.getLogger(__name__)

# define a Handler which writes INFO messages or higher to the sys.stderr
console = logging.StreamHandler()
# set a format which is simpler for console use
console.setLevel(logging.INFO)
# tell the handler to use this format
console.setFormatter(logging.Formatter('%(asctime)s %(levelname)s: %(message)s'))

# add the handler to the main logger
LOG.addHandler(console)

# Define custom exceptions
class UnexpectedHTTPResponse(Exception):
    """Used when recieving an unexpected HTTP response"""

SEVERITY = {
    "Critical": 2,
    "High": 3,
    "Medium": 5,
    "Low": 6,
    "Negligible": 7
}

class TokenAuth(requests.auth.AuthBase):
    def __init__(self, token):
        self.token = token
    def __call__(self, request):
        request.headers['Authorization'] = f'Bearer {self.token}'
        return request

def generate_csv(report):
    df = pandas.DataFrame(report)
    return df.to_csv(index=False)

def generate_report(sysdigRegion, auth, headers, hasFix, isExploitable, dateFrom, severity, image, reportType, baseImage):
    neededSeverities = get_severities_list(severity)
    reportReturn = []
    global scansCount
    # Get the pipeline scan results
    LOG.info(f"Retrieving the list of pipeline scan results...")
    results = get_results(sysdigRegion=sysdigRegion, auth=auth, headers=headers, dateFrom=dateFrom, severity=severity, image=image, reportType=reportType)
    resultsCount = len(results)
    scansCount = resultsCount

    # get kubernetes workload labels
    if reportType == "runtime":
        kubernetesWorkloadLabels = get_kubernetes_workload_labels(sysdigRegion=sysdigRegion, auth=auth, headers=headers)

    # Output amount of uniq image scans
    LOG.info(f"Found {resultsCount} unique image scan results.")

    counter = 0

    for result in results:
        counter += 1

        scope = result.get('scope', {}) 
        workload_type = scope.get('kubernetes.workload.type')
        workload_name = scope.get('kubernetes.workload.name')
        namespace_name = scope.get('kubernetes.namespace.name')
        cluster_name = scope.get('kubernetes.cluster.name')

        # find kubernetes workload labels
        if reportType == "runtime":
            key_value_pairs_to_match = {"type": workload_type, "name": workload_name, "namespaceName": namespace_name, "clusterName": cluster_name}
            matching_dicts = [item for item in kubernetesWorkloadLabels if all(item.get(key) == value for key, value in key_value_pairs_to_match.items())]

        if counter % 100 == 0:
            LOG.info(f"Processing image scan {counter} of {resultsCount}.")
        resultData = get_result(sysdigRegion=sysdigRegion, auth=auth, headers=headers, resultId=result['resultId'])

        # collect base image information
        if baseImage:
            # Extract unique pull strings
            unique_pullstrings = set()
            baseImagesData = []

            for base_image in resultData["baseImages"]:
                # baseImage_type = resultData['baseImages'][base_image]
                # print(baseImage_type)
                pullstrings = resultData['baseImages'][base_image].get("pullStrings", [])
                unique_pullstrings.update(pullstrings)
                # print(pullstrings)
            for pullstring in unique_pullstrings:
                baseImageReturn = {}
                for baseImageReportType in ["registry","pipeline","runtime"]:
                    dateFrom =((datetime.datetime.utcnow() - datetime.timedelta(days=90)) if baseImageReportType == "pipeline" else None)
                    baseImages = get_results(sysdigRegion=sysdigRegion, auth=auth, headers=headers, dateFrom=dateFrom, severity=severity, image=pullstring, reportType=baseImageReportType)
                    if baseImages:
                        baseImageData = get_result(sysdigRegion=sysdigRegion, auth=auth, headers=headers, resultId=baseImages[0]['resultId'])
                        baseImageReturn['imageId'] = baseImageData['metadata']['imageId']
                        baseImageReturn['digest'] = baseImageData['metadata']['digest']
                        baseImageReturn['imagePullString'] = baseImageData['metadata']['pullString']
                        baseImageReturn['createdAt'] = baseImageData['metadata']['createdAt']
                        break
                if baseImageReturn:
                    baseImagesData.append(baseImageReturn)

        # Continue if image has no packages
        if 'packages' not in resultData.keys():
            LOG.info(f"Image: {resultData['metadata']['pullString']} has no packages...skipping...")
            continue

        for packageId in resultData['packages']:
            if resultData['packages'][packageId].get('vulnerabilitiesRefs'):
                for vulnId in resultData['packages'][packageId].get('vulnerabilitiesRefs'):
                    if isExploitable and not resultData['vulnerabilities'][vulnId]['exploitable']:
                        continue
                    if hasFix:
                        if not ('fixVersion' in resultData['vulnerabilities'][vulnId]):
                            continue
                    if neededSeverities and resultData['vulnerabilities'][vulnId]['severity'].lower() not in neededSeverities:
                        continue
                    itemReturn = {}
                    itemReturn['imageId'] = resultData['metadata']['imageId']
                    itemReturn['imageLabels'] = (resultData['metadata']['labels'] if 'labels' in resultData['metadata'] else {})
                    if reportType == "runtime":
                        itemReturn['kubernetesScope'] = (result['scope'] if 'scope' in result else {})
                        itemReturn['kubernetesLabels'] = (matching_dicts[0]['labels'] if matching_dicts and 'labels' in matching_dicts[0] else {})
                    itemReturn['imagePullString'] = resultData['metadata']['pullString']
                    itemReturn['osName'] = resultData['metadata']['baseOs']
                    itemReturn['createdAt'] = resultData['metadata']['createdAt']
                    itemReturn['vulnCvssScore'] = resultData['vulnerabilities'][vulnId]['cvssScore']['score']
                    itemReturn['vulnCvssVersion'] = resultData['vulnerabilities'][vulnId]['cvssScore']['version']
                    itemReturn['vulnDisclosureDate'] = resultData['vulnerabilities'][vulnId]['disclosureDate']
                    itemReturn['vulnExploitable'] = resultData['vulnerabilities'][vulnId]['exploitable']
                    itemReturn['vulnFixAvailable'] = ("true" if 'fixVersion' in resultData['vulnerabilities'][vulnId] else "false")
                    itemReturn['vulnFixVersion'] = (resultData['vulnerabilities'][vulnId]['fixVersion'] if 'fixVersion' in resultData['vulnerabilities'][vulnId] else "")
                    itemReturn['vulnName'] = resultData['vulnerabilities'][vulnId]['name']
                    itemReturn['vulnSeverity'] = resultData['vulnerabilities'][vulnId]['severity']
                    itemReturn['vulnCvssVector'] = resultData['vulnerabilities'][vulnId]['cvssScore']['vector']
                    itemReturn['packageName'] = resultData['packages'][packageId]['name']
                    itemReturn['packagePath'] = resultData['packages'][packageId]['path']
                    itemReturn['packageSuggestedFix'] = (resultData['vulnerabilities'][vulnId]['fixedInVersion'] if 'fixedInVersion' in resultData['vulnerabilities'][vulnId] else "")
                    itemReturn['packageType'] = resultData['packages'][packageId]['type']
                    itemReturn['packageVersion'] = resultData['packages'][packageId]['version']
                    if baseImage:
                        # itemReturn['baseImageId'] = baseImagesData
                        # print(baseImagesData)
                        # print(len(baseImagesData))
                        if baseImagesData:
                            itemReturn['baseImageId'] = baseImagesData[0]['imageId']
                            itemReturn['baseImagePullString'] = baseImagesData[0]['imagePullString']
                            itemReturn['baseImageCreatedAt'] = baseImagesData[0]['createdAt']
                    reportReturn.append(itemReturn)
    return reportReturn

def get_results(sysdigRegion, auth, headers, dateFrom, severity, image, reportType):
    severities = get_severities_list(severity)
    cursor = ""
    params = {
        "limit": "100",
    }
    if image:
        params["filter"] = f'freeText in ("{image}")'
    resultsReturn = []
    results = []
    imageIDs = []

    while True:
        queryResults = json.loads(get_data_from_http_request(f"https://{api_endpoints[sysdigRegion]['new']}/secure/vulnerability/v1/{reportType}-results", auth=auth, headers=headers, params=params))
        cursor = (queryResults['page']['next'] if 'next' in queryResults['page'] else None)
        params.update({"cursor": cursor})
        resultsReturn.extend(queryResults['data'])
        if cursor == None:
            break

    if reportType == "pipeline":
        # Sort results to have latest scan first.
        resultsReturn = sorted(resultsReturn, key=itemgetter('createdAt'), reverse=True)

        for result in resultsReturn:
            try:
                # Try parsing with microseconds first
                created_at = datetime.datetime.strptime(result['createdAt'], "%Y-%m-%dT%H:%M:%S.%fZ")
            except ValueError:
                # If that fails, try without microseconds
                created_at = datetime.datetime.strptime(result['createdAt'], "%Y-%m-%dT%H:%M:%SZ")

            if created_at > dateFrom:
                if result['imageId'] not in imageIDs and check_severities(vulnBySeverity=result['vulnTotalBySeverity'],neededSeverities=severities):
                    imageIDs.append(result['imageId'])
                    results.append(result)

    elif reportType == "runtime":
        for result in resultsReturn:
            if "asset.type" in result['scope'] and result['scope']['asset.type'] == "workload" and check_severities(vulnBySeverity=result['vulnTotalBySeverity'],neededSeverities=severities):
                results.append(result)

    elif reportType == "registry":
        for result in resultsReturn:
            if check_severities(vulnBySeverity=result['vulnTotalBySeverity'],neededSeverities=severities):
                results.append(result)

    return results

def get_result(sysdigRegion, auth, headers, resultId):
    return json.loads(get_data_from_http_request(f"https://{api_endpoints[sysdigRegion]['new']}/secure/vulnerability/v1/results/{resultId}", auth=auth, headers=headers))

def get_kubernetes_workload_labels(sysdigRegion, auth, headers):
    try:
        while True:
            LOG.debug(f"Getting kubernetes workload labels from graphql endpoint...")
            response = requests.post(f"https://{api_endpoints[sysdigRegion]['old']}/api/graph/v1/graphql", auth=auth, headers=headers, data = '{"query":"{kubeWorkloads {name type clusterName namespaceName labels{name}}}"}')
            LOG.debug(f"Response status: {response.status_code}")
            if response.status_code == 200:
                break

            elif response.status_code in [429,504]:
                LOG.debug(f"Response data: {response.content}")
                LOG.debug(f"Response code {response.status_code}. Sleeping 60 seconds...")
                time.sleep(60)
                LOG.debug(f"Retrying request...")
            else:
                raise UnexpectedHTTPResponse(
                    f"Unexpected HTTP response status: {response.status_code}"
                )
        output = []
        for result in json.loads(response.content)['data']['kubeWorkloads']:
            labels = {}
            for label in result['labels']:
                key, value = label['name'].split(': ')
                labels[key] = value
            result['type'] = result['type'].lower()
            result['labels'] = labels
            output.append(result)
        return output
    except Exception as e:
        LOG.critical(e)
        LOG.critical(f"Error while requesting url: {api_endpoints[sysdigRegion]['new']}")
        raise SystemExit(-1)

def get_severities_list(severity):
    severities = []
    if severity == None:
        return severity
    else:
        severity_number = SEVERITY[severity]
        for severity in SEVERITY.items():
            if severity[1] <= severity_number:
                severities.append(severity[0].lower())
        return severities

def check_severities(vulnBySeverity,neededSeverities):
    if neededSeverities == None:
        return True
    vulnWithRequestedSeverity = 0
    for severity in vulnBySeverity.items():
        if severity[0] in neededSeverities:
            vulnWithRequestedSeverity = vulnWithRequestedSeverity + severity[1]
    if vulnWithRequestedSeverity >= 0:
        return True
    else:
        return False

def get_data_from_http_request(url,auth,headers,params=None):
    try:
        while True:
            LOG.debug(f"Sending http request to: {url}")
            params=(urllib.parse.urlencode(params, safe='():/') if params else None)
            response = requests.get(url=url, auth=auth, headers=headers, params=params)
            LOG.debug(f"Response status: {response.status_code}")
            if response.status_code == 200:
                break

            elif response.status_code in [429,504]:
                LOG.debug(f"Response data: {response.content}")
                LOG.debug(f"Response code {response.status_code}. Sleeping 60 seconds...")
                time.sleep(60)
                LOG.debug(f"Retrying request...")
            else:
                raise UnexpectedHTTPResponse(
                    f"Unexpected HTTP response status: {response.status_code}"
                )
        return response.content
    except Exception as e:
        LOG.critical(e)
        LOG.critical(f"Error while requesting url: {url}")
        raise SystemExit(-1)

def main():
    parser = argparse.ArgumentParser(description="Generate pipeline scanner report", epilog="Please set environment variable SECURE_API_TOKEN with valid Sysdig Secure API token to be able to run script.")
    parser.add_argument("--sysdig-region", dest="sysdigRegion", type=str, choices=['au1','eu1','in1','me2','us1','us2','us3','us4'], help="Sysdig Secure Region", required=True)
    parser.add_argument("--days-back", dest="daysBack", metavar="N", type=int, help="Amount of days to search back. (default: %(default)s)", required=False, default="7")
    parser.add_argument("--severity", dest="severity", type=str, choices=['Critical', 'High', 'Medium', 'Low', 'Negligible'], help="Get packages with severity higher or equal to specified.", required=False)
    parser.add_argument("--fix-available", dest="fixAvailable", help="Get packages with fixes available only.", required=False, action='store_true')
    parser.add_argument("--exploit-available", dest="exploitAvailable", help="Get packages with exploit available only.", required=False, action='store_true')
    parser.add_argument("--output-format", dest="outputFormat", type=str, choices=['json', 'csv'], help="Specify output format for report. (default: %(default)s)", required=False, default="json")
    parser.add_argument("--type", dest="reportType", type=str, choices=['runtime', 'pipeline'], help="Specify type of the report. (default: %(default)s)", required=False, default="pipeline")
    parser.add_argument("--log-level", dest="logLevel", type=str, choices=['INFO', 'DEBUG'], help="Set log level. If DEBUG level set logs are stored in report.log file in the same folder where script is executed.", default="INFO", required=False)
    parser.add_argument("--image", dest="image", type=str, help="Get results for specific image only. Partial or full match can be used.", required=False)
    parser.add_argument("--include-base-image", dest="baseImage", help="Include information about base image if available.", required=False, action='store_true')
    args = parser.parse_args()
    sysdigToken = (os.environ.get('SECURE_API_TOKEN') if 'SECURE_API_TOKEN' in os.environ else exit(parser.print_help()))
    sysdigRegion = args.sysdigRegion
    reportType = args.reportType
    dateFrom =((datetime.datetime.utcnow() - datetime.timedelta(days=args.daysBack)) if reportType == "pipeline" else None)
    severity = args.severity
    hasFix = args.fixAvailable
    isExploitable = args.exploitAvailable
    outputFormat = args.outputFormat
    logLevel = args.logLevel
    image = args.image
    baseImage = args.baseImage
    headers = {
        "Content-Type": "application/json",
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate, br"
    }
    auth = TokenAuth(sysdigToken)

    if logLevel == "DEBUG":
        logging.basicConfig(
            level=logging.DEBUG,
            format="%(asctime)s.%(msecs)03d %(levelname)s - %(funcName)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
            filename="report.log",
            filemode = 'w',
        )
    else:
        LOG.setLevel(logging.INFO)

    report = generate_report(sysdigRegion=sysdigRegion, auth=auth, headers=headers, dateFrom=dateFrom, hasFix=hasFix, isExploitable=isExploitable, severity=severity, image=image, reportType=reportType, baseImage=baseImage)

    if outputFormat == "json":
        print(json.dumps(report))
    else:
        csv = generate_csv(report)
        print(csv)

    LOG.info(f"It took {time.strftime('%Hh %Mm %Ss', time.gmtime(round(time.time() - startTime)))} to generate report with {len(report)} vulnerabilities entries for {scansCount} scanned images.")

if __name__ == '__main__':
    main()