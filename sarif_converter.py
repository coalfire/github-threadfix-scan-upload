#!/usr/local/bin/python3

import datetime
import json
import random
import string
import sys

## This converts SARIF to threadfix
def make_ref_rule_dict(item):
    ret_val = { }
    current_rule = { }
    cwe_start = 'external/cwe/cwe-'


    current_rule['id'] = item['rule']['id']
    current_rule['shortDescription'] = item['rule']['description']
    current_rule['fullDescription'] = item['rule']['description'] ## To revisit
    current_rule['nativeSeverity'] = item['rule']['security_severity_level'].capitalize()
    current_rule['severity'] = item['rule']['security_severity_level'].capitalize()
    

    vuln_type = item['rule']['id']
    current_rule['isCwe'] = False
    for tag in item['rule']['tags']:
         if str(tag).startswith(cwe_start):
             vuln_type = str(tag)[len(cwe_start):len(str(tag))]
             current_rule['isCwe'] = True
    current_rule['type'] = vuln_type

    
    ret_val[item['rule']['id']] = current_rule

    return (ret_val)

def assemble_findings_for_run(finding_list, item):
    
    ref_rule_dict = make_ref_rule_dict(item)
    finding_dict = { }

    #     # Create a random findingId because CodeQL doesn't track unique IDs across tool executions
    #     # TODO - May be able to use some of the fingerprint stuff to fill this in better
    letters = string.ascii_letters
    finding_id = ''.join(random.choice(letters) for i in range(256))
    finding_dict['nativeId'] = finding_id
    
    first_key = list(ref_rule_dict.keys())[0]

    finding_dict['severity'] = ref_rule_dict[first_key]['severity']
    finding_dict['nativeSeverity'] = ref_rule_dict[first_key]['nativeSeverity']


    # #     # If the rule had a CWE, add that mapping, otherwise map as a CodeQL mapping
    # #     # TODO - Expand handling for tools other than CodeQL
    if ref_rule_dict[first_key]['isCwe'] == True:
        mapping_dict = { }
        mapping_dict['mappingType'] = 'CWE'
        mapping_dict['value'] = ref_rule_dict[first_key]['type']
        mapping_dict['primary'] = True
        mapping_list = [ ]
        mapping_list.append(mapping_dict)
        finding_dict['mappings'] = mapping_list
    else:
        mapping_dict = { }
        mapping_dict['mappingType'] = 'TOOL_VENDOR'
        mapping_dict['value'] = ref_rule_dict[first_key]['type']
        mapping_dict['primary'] = True
        mapping_dict['vendorOtherType'] = 'CodeQLRuleDB'
        mapping_list = [ ]
        mapping_list.append(mapping_dict)
        finding_dict['mappings'] = mapping_list
        
    finding_dict['summary'] = ref_rule_dict[first_key]['shortDescription']
    finding_dict['description'] = ref_rule_dict[first_key]['shortDescription']

    #     # Make the dataflow
    #     # TODO - Track the actual dataflow - not just the first entry
    dataflow_dict = { }
    start_file = item['instances_url']
    dataflow_dict['file'] = start_file
    dataflow_dict['lineNumber'] = item['most_recent_instance']['location']['start_line']
    dataflow_dict['columnNumber'] = item['most_recent_instance']['location']['start_column']
    dataflow_dict['text'] = ''


    static_details_dict = { }

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

print ("Input file will be: " + infile)
print ("Output file will be: " + outfile)

sarif_data = { }
with open(infile, "r") as read_file:
    sarif_data = json.load(read_file)

output = { }

# Get the basics out of the way
output['collectionType'] = 'SAST'
# TOFIX - Determine how we want to do this - do we want to detect the value from the SARIF tools or stuff it in as a command-line argument?
output['source'] = 'CodeQL'


# Handle timestamp stuff
# SARIF doesn't appear to have timestamps, so we will just use the time of conversion. Not perfect - but what can you do?

created_date_string = datetime.datetime.strftime(datetime.datetime.now(), '%Y-%m-%dT%H:%M:%SZ')
output['created'] = str(created_date_string)
output['exported'] = str(created_date_string)
output['updated'] = str(created_date_string)
# Now build the finding list




# For every "run" and every "tool" element in the file, create new findings to add to the list. This assumes - as you really can't with
# SARIF - that all the "tool" driver values will be the same and that the runs are equal.


## -----Beginning---
finding_list = [ ]

for item in sarif_data:
    assemble_findings_for_run(finding_list, item)


output['findings'] = finding_list

# Write the output file

with open(outfile, "w") as write_file:
    json.dump(output, write_file)
    write_file.close()
