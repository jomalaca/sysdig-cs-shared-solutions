# Generating pipeline or runtime scan results report by using API

## Purpose ##

Many customers are looking for the script examples to generate custom VM report. This script have examples of leveraging both Runtime and Pipeline VM APIs.

### Usage ###

To utilize this script it is recommended to operate within a Python Virtual Environment. Included in the package
is a `pipenv` definition. To set up `pipenv` visit https://pipenv.pypa.io/en/latest/.

Running the script takes multiple arguments all available via the included `--help` function.

```
usage: report.py [-h] --sysdig-region {au1,eu1,in1,me2,us1,us2,us3,us4} [--days-back N] [--severity {Critical,High,Medium,Low,Negligible}]
                 [--fix-available] [--exploit-available] [--output-format {json,csv}] [--type {runtime,pipeline}] [--log-level {INFO,DEBUG}]
                 [--image IMAGE] [--include-base-image]

Generate pipeline scanner report

options:
  -h, --help            show this help message and exit
  --sysdig-region {au1,eu1,in1,me2,us1,us2,us3,us4}
                        Sysdig Secure Region
  --days-back N         Amount of days to search back. (default: 7)
  --severity {Critical,High,Medium,Low,Negligible}
                        Get packages with severity higher or equal to specified.
  --fix-available       Get packages with fixes available only.
  --exploit-available   Get packages with exploit available only.
  --output-format {json,csv}
                        Specify output format for report. (default: json)
  --type {runtime,pipeline}
                        Specify type of the report. (default: pipeline)
  --log-level {INFO,DEBUG}
                        Set log level. If DEBUG level set logs are stored in report.log file in the same folder where script is executed.
  --image IMAGE         Get results for specific image only. Partial or full match can be used.
  --include-base-image  Include information about base image if available.

Please set environment variable SECURE_API_TOKEN with valid Sysdig Secure API token to be able to run script.
```

Script can generate report in JSON or CSV formats. Please see below for examples.

CSV:
```
./report.py --sysdig-region us2 --severity Critical --type runtime --include-base-image --image quay.io/maratsal/make-some-noise:v2 --output-format csv
2025-01-31 18:49:44,841 INFO: Retrieving the list of pipeline scan results...
2025-01-31 18:49:45,729 INFO: Found 1 unique image scan results.
imageId,imageLabels,kubernetesScope,kubernetesLabels,imagePullString,osName,scanTime,vulnCvssScore,vulnCvssVersion,vulnDisclosureDate,vulnExploitable,vulnFixAvailable,vulnFixVersion,vulnName,vulnSeverity,vulnCvssVector,packageName,packagePath,packageSuggestedFix,packageType,packageVersion,baseImages
sha256:3689c2f73a9777d95697d7887d1a8793636993fc65a3eb14973a3138e14bbf16,{'maintainer': 'NGINX Docker Maintainers <docker-maint@nginx.com>'},"{'asset.type': 'workload', 'kubernetes.cluster.name': 'CLUSTER_NAME', 'kubernetes.namespace.name': 'nginx-log4j', 'kubernetes.pod.container.name': 'sysevent', 'kubernetes.workload.name': 'nginx-log4j', 'kubernetes.workload.type': 'deployment', 'workload.name': 'nginx-log4j', 'workload.orchestrator': 'kubernetes'}",{'app': 'nginx-log4j'},quay.io/maratsal/make-some-noise:v2,debian 11.5,2024-06-28T12:38:39.901812426Z,10.0,3.1,2021-11-30,True,true,v2.15.0,CVE-2021-44228,critical,CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H,org.apache.logging.log4j:log4j-core,/apache-log4j-2.14.1-bin/log4j-core-2.14.1.jar,,,2.14.1,[]
sha256:3689c2f73a9777d95697d7887d1a8793636993fc65a3eb14973a3138e14bbf16,{'maintainer': 'NGINX Docker Maintainers <docker-maint@nginx.com>'},"{'asset.type': 'workload', 'kubernetes.cluster.name': 'CLUSTER_NAME', 'kubernetes.namespace.name': 'nginx-log4j', 'kubernetes.pod.container.name': 'sysevent', 'kubernetes.workload.name': 'nginx-log4j', 'kubernetes.workload.type': 'deployment', 'workload.name': 'nginx-log4j', 'workload.orchestrator': 'kubernetes'}",{'app': 'nginx-log4j'},quay.io/maratsal/make-some-noise:v2,debian 11.5,2024-06-28T12:38:39.901812426Z,9.0,3.1,2021-11-30,True,true,v2.16.0,CVE-2021-45046,critical,CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H,org.apache.logging.log4j:log4j-core,/apache-log4j-2.14.1-bin/log4j-core-2.14.1.jar,,,2.14.1,[]
sha256:3689c2f73a9777d95697d7887d1a8793636993fc65a3eb14973a3138e14bbf16,{'maintainer': 'NGINX Docker Maintainers <docker-maint@nginx.com>'},"{'asset.type': 'workload', 'kubernetes.cluster.name': 'CLUSTER_NAME', 'kubernetes.namespace.name': 'nginx-log4j', 'kubernetes.pod.container.name': 'sysevent', 'kubernetes.workload.name': 'nginx-log4j', 'kubernetes.workload.type': 'deployment', 'workload.name': 'nginx-log4j', 'workload.orchestrator': 'kubernetes'}",{'app': 'nginx-log4j'},quay.io/maratsal/make-some-noise:v2,debian 11.5,2024-06-28T12:38:39.901812426Z,9.1,3.1,2024-06-26,False,true,1.18.3-6+deb11u5,CVE-2024-37371,critical,CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H,libgssapi-krb5-2,/var/lib/dpkg/status,,,1.18.3-6+deb11u2,[]
...
2025-01-31 18:49:46,406 INFO: It took 00h 00m 02s to generate report with 26 vulnerabilities entries for 1 scanned images.
```

JSON:
```
./report.py --sysdig-region us2 --severity Critical --type runtime --include-base-image --image quay.io/maratsal/make-some-noise:v2 | jq
2025-01-31 18:51:37,709 INFO: Retrieving the list of pipeline scan results...
2025-01-31 18:51:38,485 INFO: Found 1 unique image scan results.
[
  {
    "imageId": "sha256:3689c2f73a9777d95697d7887d1a8793636993fc65a3eb14973a3138e14bbf16",
    "imageLabels": {
      "maintainer": "NGINX Docker Maintainers <docker-maint@nginx.com>"
    },
    "kubernetesScope": {
      "asset.type": "workload",
      "kubernetes.cluster.name": "CLUSTER_NAME",
      "kubernetes.namespace.name": "nginx-log4j",
      "kubernetes.pod.container.name": "sysevent",
      "kubernetes.workload.name": "nginx-log4j",
      "kubernetes.workload.type": "deployment",
      "workload.name": "nginx-log4j",
      "workload.orchestrator": "kubernetes"
    },
    "kubernetesLabels": {
      "app": "nginx-log4j"
    },
    "imagePullString": "quay.io/maratsal/make-some-noise:v2",
    "osName": "debian 11.5",
    "scanTime": "2024-06-28T12:38:39.901812426Z",
    "vulnCvssScore": 9,
    "vulnCvssVersion": "3.1",
    "vulnDisclosureDate": "2021-11-30",
    "vulnExploitable": true,
    "vulnFixAvailable": "true",
    "vulnFixVersion": "v2.16.0",
    "vulnName": "CVE-2021-45046",
    "vulnSeverity": "critical",
    "vulnCvssVector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "packageName": "org.apache.logging.log4j:log4j-core",
    "packagePath": "/apache-log4j-2.14.1-bin/log4j-core-2.14.1.jar",
    "packageSuggestedFix": "",
    "packageType": "",
    "packageVersion": "2.14.1",
    "baseImages": []
  },
...
]
```
