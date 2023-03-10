#!/usr/bin/env python3

from datetime import datetime
import json
import sys


def make_ref_rule_dict(item: dict) -> dict:
    """
    Convert SARIF to Threadfix
    """
    rule = item["rule"]

    severity = rule.get("security_severity_level", rule["severity"])

    try:
        cwe_start = "external/cwe/cwe-"
        # next will raise StopIteration if no tags match the filter
        cwe = next(filter(lambda x: x.startswith(cwe_start), rule["tags"]))
        rule_type = cwe.replace(cwe_start, "")
        mapping_type = "CWE"
    except StopIteration:
        rule_type = rule["id"]
        mapping_type = "TOOL_VENDOR"

    return {
        "id": rule["id"],
        "shortDescription": rule["description"],
        "fullDescription": rule["description"],  # To revisit
        "type": rule_type,
        "mapping_type": mapping_type,
        "severity": severity.capitalize(),
        "nativeSeverity": severity.capitalize(),
    }


def assemble_findings_for_run(item: dict, repo: str) -> dict:
    ref_rule_dict = make_ref_rule_dict(item)

    # mapping dict
    mapping_dict = {
        "value": ref_rule_dict["type"],
        "primary": True,
        "mappingType": ref_rule_dict["mapping_type"],
    }
    if ref_rule_dict["mapping_type"] != "CWE":
        mapping_dict["vendorOtherType"] = "CodeQLRuleDB"

    # dataflow dict
    start_file = item["instances_url"]

    dataflow_dict = {
        "file": start_file,
        "lineNumber": item["most_recent_instance"]["location"]["start_line"],
        "columnNumber": item["most_recent_instance"]["location"][
            "start_column"
        ],
        "text": "",
    }

    static_details_dict = {
        "dataFlow": [dataflow_dict],
        "parameter": "",
        "file": start_file,
    }

    return {
        "nativeId": f"{repo}-{str(item['number'])}",
        "severity": ref_rule_dict["severity"],
        "nativeSeverity": ref_rule_dict["nativeSeverity"],
        "mappings": [mapping_dict],
        "summary": ref_rule_dict["shortDescription"],
        "description": ref_rule_dict["shortDescription"],
        "staticDetails": static_details_dict,
    }


if len(sys.argv) != 4:
    print(f"usage: {sys.argv[0]} <input_file> <output_file> <repo>")
    sys.exit(1)

infile = sys.argv[1]
outfile = sys.argv[2]
repository = sys.argv[3]

print("Input file will be: " + infile)
print("Output file will be: " + outfile)

with open(infile, "r") as read_file:
    sarif_data = json.load(read_file)

findings = [
    assemble_findings_for_run(item, repository) for item in sarif_data
]

now = datetime.strftime(datetime.now(), "%Y-%m-%dT%H:%M:%SZ")
output = {
    "collectionType": "SAST",
    "source": "GitHub Advanced Security",
    "created": now,
    "exported": now,
    "updated": now,
    "findings": findings,
}

with open(outfile, "w", encoding='utf8') as write_file:
#    # do we want compact json?
#    json.dump(output, write_file, separators=(",", ":"))
    # or pretty json?
    json.dump(output, write_file, indent=2)
    write_file.close()
