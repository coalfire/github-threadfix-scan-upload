#!/usr/local/bin/python3

import datetime
import json
import sys


# Converts SARIF to Threadfix
def make_ref_rule_dict(item):
    ret_val = {}
    current_rule = {}
    cwe_start = 'external/cwe/cwe-'

    current_rule['id'] = item['rule']['id']
    current_rule['shortDescription'] = item['rule']['description']
    current_rule['fullDescription'] = item['rule']['description']  # To revisit

    # Severities
    if 'security_severity_level' in item['rule']:
        current_rule['nativeSeverity'] = item['rule']['security_severity_level'].capitalize()
        current_rule['severity'] = item['rule']['security_severity_level'].capitalize()
    else:
        current_rule['nativeSeverity'] = item['rule']['severity'].capitalize()
        current_rule['severity'] = item['rule']['severity'].capitalize()

    vuln_type = item['rule']['id']
    current_rule['isCwe'] = False
    for tag in item['rule']['tags']:
        if str(tag).startswith(cwe_start):
            vuln_type = str(tag)[len(cwe_start):len(str(tag))]
            current_rule['isCwe'] = True
    current_rule['type'] = vuln_type

    ret_val[item['rule']['id']] = current_rule

    return (ret_val)


def assemble_findings_for_run(finding_list, item, repo):
    ref_rule_dict = make_ref_rule_dict(item)
    finding_dict = {}

    finding_dict['nativeId'] = repo + '-' + str(item['number'])

    first_key = list(ref_rule_dict.keys())[0]

    finding_dict['severity'] = ref_rule_dict[first_key]['severity']
    finding_dict['nativeSeverity'] = ref_rule_dict[first_key]['nativeSeverity']

    # If the rule had a CWE, add that mapping
    if ref_rule_dict[first_key]['isCwe'] == True:
        mapping_dict = {}
        mapping_dict['mappingType'] = 'CWE'
        mapping_dict['value'] = ref_rule_dict[first_key]['type']
        mapping_dict['primary'] = True
        mapping_list = []
        mapping_list.append(mapping_dict)
        finding_dict['mappings'] = mapping_list
    else:
        mapping_dict = {}
        mapping_dict['mappingType'] = 'TOOL_VENDOR'
        mapping_dict['value'] = ref_rule_dict[first_key]['type']
        mapping_dict['primary'] = True
        mapping_dict['vendorOtherType'] = 'CodeQLRuleDB'
        mapping_list = []
        mapping_list.append(mapping_dict)
        finding_dict['mappings'] = mapping_list

    finding_dict['summary'] = ref_rule_dict[first_key]['shortDescription']
    finding_dict['description'] = ref_rule_dict[first_key]['shortDescription']

    #     # Make the dataflow
    dataflow_dict = {}
    start_file = item['instances_url']
    dataflow_dict['file'] = start_file
    dataflow_dict['lineNumber'] = item['most_recent_instance']['location']['start_line']
    dataflow_dict['columnNumber'] = item['most_recent_instance']['location']['start_column']
    dataflow_dict['text'] = ''

    static_details_dict = {}

    dataflow_list = []
    dataflow_list.append(dataflow_dict)
    static_details_dict['dataFlow'] = dataflow_list
    static_details_dict['parameter'] = ''
    static_details_dict['file'] = start_file

    # #     # Add the static details to the finding
    finding_dict['staticDetails'] = static_details_dict

    # #     # Finally add the whole finding
    finding_list.append(finding_dict)


if len(sys.argv) < 3:
    print("usage: sarif_to_threadfix.py <input_file> <output_file>")
    exit(1)

infile = sys.argv[1]
outfile = sys.argv[2]
repo = sys.argv[3]

print("Input file will be: " + infile)
print("Output file will be: " + outfile)

sarif_data = {}
with open(infile, "r") as read_file:
    sarif_data = json.load(read_file)

output = {}

# Metadata
output['collectionType'] = 'SAST'
output['source'] = 'GitHub Advanced Security'

# Handle timestamp
created_date_string = datetime.datetime.strftime(datetime.datetime.now(), '%Y-%m-%dT%H:%M:%SZ')
output['created'] = str(created_date_string)
output['exported'] = str(created_date_string)
output['updated'] = str(created_date_string)
# Now build the finding list


finding_list = []

for item in sarif_data:
    assemble_findings_for_run(finding_list, item, repo)

output['findings'] = finding_list

# Write the output file

with open(outfile, "w") as write_file:
    json.dump(output, write_file)
    write_file.close()
