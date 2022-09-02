import os
import time
import csv
from requests_toolbelt.multipart.encoder import MultipartEncoder
import subprocess
import common
import json
import requests
import pandas as pd
import socket


def check_MobSF_server_status(server_ip, server_port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex((server_ip, int(server_port)))
    is_server_running = False
    if result == 0:
        is_server_running = True

    sock.close()

    return is_server_running


def start_MobSF_server(MobSF_base_path,server_ip, server_port, os_env):
    is_server_running = check_MobSF_server_status(server_ip,server_port)
    if not is_server_running:
        current_path = os.getcwd()
        os.chdir(MobSF_base_path)

        if os_env == "Windows":
            subprocess.call('start run.bat '+server_ip+":"+server_port, shell=True)

        elif os_env == "Linux":
            subprocess.call('gnome-terminal -- ./run.sh ' + server_ip + ":" + server_port, shell=True)

        os.chdir(current_path)
        time.sleep(10)


def generate_MobSF_scanned_app_details():
    if not os.path.exists('MobSF_Scanned_App_Details.csv'):
        scanner_app_details_csv = open('MobSF_Scanned_App_Details.csv', 'w', newline='')
        writer = csv.writer(scanner_app_details_csv)
        writer.writerow(['app_name', 'app_hash'])
        scanner_app_details_csv.close()


def upload_apk(apk_file, api_key, server):
    common.msg_print("Uploading file...")
    multipart_data = MultipartEncoder(fields={'file': (apk_file, open(apk_file, 'rb'), 'application/octet-stream')})
    headers = {'Content-Type': multipart_data.content_type, 'Authorization': api_key}
    response = requests.post(server + '/api/v1/upload', data=multipart_data, headers=headers)
    common.msg_print("File uploaded!")
    return response.text


def scan_apk(upload_response, api_key, server):
    common.msg_print("Scanning file...")
    post_dict = json.loads(upload_response)
    headers = {'Authorization': api_key}
    response = requests.post(server + '/api/v1/scan', data=post_dict, headers=headers)
    common.msg_print("File scanned!")
    return response.text


# This is for delete a scanned file
def delete_scanned_results(scan_hash, api_key, server):
    common.msg_print("Removing scan...")
    headers = {'Authorization': api_key}
    data = {"hash": scan_hash}
    response = requests.post(server + '/api/v1/delete_scan', data=data, headers=headers)
    common.msg_print("Scan removed!")
    return response.text


# This is for bulk removal
def get_all_scans(server,api_key):
    all_hash=[]
    headers = {'Authorization': api_key}
    response = requests.get(server + '/api/v1/scans',  headers=headers)

    json_object = json.loads(response.text)

    contents = json_object["content"]

    for x in range(len(contents)):
        scan_hash = contents[x]["MD5"]
        delete_scanned_results(scan_hash,api_key, server)

    if len(contents) == 10:
        common.msg_print("moving to next page")
        get_all_scans(server,api_key)




def write_scanned_app_details(app_name, app_hash):
    common.msg_print("Writing data to CSV file...")
    scanned_app_details_file = open('MobSF_Scanned_App_Details.csv', 'a', newline='')
    scanned_app_details_file_writer = csv.writer(scanned_app_details_file)
    scanned_app_details_file_writer.writerow([app_name, app_hash])
    scanned_app_details_file.close()
    common.msg_print("Data writing completed!")


def get_source_code(app_name, app_hash, source_file, api_key, server):
    headers = {'Authorization': api_key}
    data = {"hash": app_hash, "type": "apk", "file": source_file}
    response = requests.post(server + '/api/v1/view_source', data=data, headers=headers)
    json_object = json.loads(response.text)

    source_code = json_object["data"]

    java_file = open(app_name + ".java", "wb")
    java_file.write(source_code.encode("utf-8"))
    java_file.close()

    lines = []
    with open(app_name + ".java") as file_in:
        for line in file_in:
            lines.append(line)

    source_code_df = pd.DataFrame(lines, columns=['code'])
    os.remove(app_name + ".java")

    return source_code_df


def get_vulnerability_data_json(app_hash, api_key, server):
    common.msg_print("Generating JSON report...")
    headers = {'Authorization': api_key}
    data = {"hash": app_hash}
    response = requests.post(server + '/api/v1/report_json', data=data, headers=headers)
    common.msg_print("JSON Report generated!")
    return response


def generate_vulnerable_dataset(api_key, server, app_name, app_hash, vulnerability_json_response):
    vulnerability_dataset = []

    try:
        common.msg_print("Generating vulnerability dataset...")
        code_analysis_json_obj = json.loads(str(vulnerability_json_response))["code_analysis"]
        # Iterating through each issue
        for each_android_issue in code_analysis_json_obj:
            try:
                for each_files in code_analysis_json_obj[each_android_issue]["files"]:
                    try:
                        filepath = str(each_files)
                        code_lines_str_list = str(
                            code_analysis_json_obj[each_android_issue]["files"][each_files]).split(",")
                        code_lines = list(map(int, code_lines_str_list))

                        for i in range(len(code_lines)):
                            code_lines[i] = code_lines[i] - 1

                        all_code_lines = get_source_code(app_name, app_hash, filepath, api_key, server)

                        for index, row in all_code_lines.iterrows():
                            vulnerability_status = 0
                            if index in code_lines:
                                vulnerability_status = 1

                            code = str(row[0]).strip()
                            attr_id = ""
                            attr_description = ""
                            attr_type = ""
                            attr_pattern = ""
                            attr_severity = ""
                            attr_input_case = ""
                            attr_cvss = ""
                            attr_cwe_id = ""
                            attr_cwe_desc = ""
                            attr_owasp_mobile = ""
                            attr_masvs = ""
                            attr_ref = ""

                            if vulnerability_status == 1:

                                metadata = code_analysis_json_obj[each_android_issue]["metadata"]
                                try:
                                    attr_id = str(metadata["id"])
                                except:
                                    attr_id = ""

                                try:
                                    attr_description = str(metadata["description"])
                                except:
                                    attr_description = ""

                                try:
                                    attr_type = str(metadata["type"])
                                except:
                                    attr_type = ""
                                try:
                                    attr_pattern = str(metadata["pattern"])
                                except:
                                    attr_pattern = ""
                                try:
                                    attr_severity = str(metadata["severity"])
                                except:
                                    attr_severity = ""
                                try:
                                    attr_input_case = str(metadata["input_case"])
                                except:
                                    attr_input_case = ""
                                try:
                                    attr_cvss = str(metadata["cvss"])
                                except:
                                    attr_cvss = ""
                                try:
                                    attr_cwe = str(metadata["cwe"])
                                except:
                                    attr_cwe = ""
                                try:
                                    attr_cwe = str(metadata["cwe"])
                                except:
                                    attr_cwe = ""
                                try:
                                    attr_cwe = str(metadata["cwe"])
                                    attr_cwe_split = attr_cwe.split(": ")
                                    attr_cwe_id = attr_cwe_split[0]
                                    attr_cwe_desc = attr_cwe[len(attr_cwe_id) + 1:]
                                except:
                                    attr_cwe = ""
                                    attr_cwe_id = ""
                                    attr_cwe_desc = ""
                                try:
                                    attr_owasp_mobile = str(metadata["owasp-mobile"])
                                except:
                                    attr_owasp_mobile = ""
                                try:
                                    attr_masvs = str(metadata["masvs"])
                                except:
                                    attr_masvs = ""
                                try:
                                    attr_ref = str(metadata["ref"])
                                except:
                                    attr_ref = ""

                            csv_data_row = [attr_id, attr_description, attr_type, attr_pattern, code, attr_severity,
                                            attr_input_case, attr_cvss, attr_cwe_id, attr_cwe_desc,
                                            attr_owasp_mobile, attr_masvs, attr_ref, vulnerability_status]

                            vulnerability_dataset.append(csv_data_row)

                    except Exception as ef:
                        print(str(ef) + " : in file : " + each_files)
                        continue

            except Exception as ei:
                print(str(ei) + " : for android issue : " + each_android_issue)
                continue

    except Exception as ej:
        print(str(ej) + " : for json file : " + app_name + ".json")

    if os.path.exists("MobSF_Unprocessed_Dataset.csv"):
        header = ['ID', 'Description', 'Type', 'Pattern', 'Code', 'Severity', 'Input Case', 'CVSS', 'CWE_ID',
                  'CWE_Desc',
                  'OWASP_Mobile', 'OWSAP_MASVS', 'Reference', 'Vulnerability_status']
        vulnerability_dataframe = pd.DataFrame(vulnerability_dataset, columns=header)

        vulnerability_dataframe.drop_duplicates(subset=['Code', 'CWE_ID'], inplace=True)

        vulnerability_dataframe.to_csv("MobSF_Unprocessed_Dataset.csv", mode='a', index=False, header=False,
                                       encoding='utf-8')

    else:
        # data frame to csv
        header = ['ID', 'Description', 'Type', 'Pattern', 'Code', 'Severity', 'Input Case', 'CVSS', 'CWE_ID',
                  'CWE_Desc', 'OWASP_Mobile', 'OWSAP_MASVS', 'Reference', 'Vulnerability_status']
        vulnerability_dataframe = pd.DataFrame(vulnerability_dataset, columns=header)

        vulnerability_dataframe.drop_duplicates(subset=['Code', 'CWE_ID'], inplace=True)

        vulnerability_dataframe.to_csv('MobSF_Unprocessed_Dataset.csv', sep=',', encoding='utf-8', index=False)

    common.msg_print("Vulnerability dataset generated!")


def execute_MobSF_process(apk_location_folder, api_key, server, file):
    # Reading scanned apps details
    scanned_apps = pd.read_csv('MobSF_Scanned_App_Details.csv')

    try:

        if file in scanned_apps.app_name.values:
            common.msg_print("This file has already been scanned!")
        else:
            upload_response = upload_apk(apk_location_folder + "/" + file + "/" + file + ".apk", api_key, server)

            # Retrieving required information from upload response
            json_response = json.loads(upload_response)
            app_hash = json_response['hash']
            app_name = json_response['file_name']
            app_name = app_name[:len(app_name) - 4]

            scan_apk(upload_response, api_key, server)
            write_scanned_app_details(app_name, app_hash)
            vulnerability_json_response = get_vulnerability_data_json(app_hash, api_key, server)

            generate_vulnerable_dataset(api_key, server, app_name, app_hash, vulnerability_json_response.text)

            delete_scanned_results(app_hash, api_key, server)

    except Exception as e:
        common.msg_print("Unexpected Error :" + str(e))