import json

# TODO: Pickup paths from settings file / Environment variables / User Inputs
INPUT_NVD_JSON_PATH = u'/Users/sidhshar/Downloads/cve_jsons/nvdcve-1.0-2016.json'
OUTPUT_JSON_PATH = u'/Users/sidhshar/Downloads/cve_jsons/nvdcve-mod.json'

def read_nvd_json(nvdfile):
    with open(nvdfile) as json_file:
        # TODO: Exception handling
        return json.load(json_file)

def write_jsonfile(data, outputfile):
    with open(outputfile, 'w') as outfile:
        # TODO: Exception handling
        json.dump(data, outfile)

def run():
    jsondata = read_nvd_json(INPUT_NVD_JSON_PATH)

    cve_list = jsondata['CVE_Items']

    trimmed_data = {}

    for cve in cve_list:
        if cve['impact'].has_key('baseMetricV3'):
            cve_id = cve['cve']['CVE_data_meta']['ID']
            trimmed_data[cve_id] = cve['impact']['baseMetricV3']

    write_jsonfile(trimmed_data, OUTPUT_JSON_PATH)

if __name__ == "__main__":
    run()
