import csv
import os
import shutil
import pandas as pd
import subprocess
import json
from datetime import datetime
import common


def create_Qark_scanned_app_details_csv():
    scanner_app_details_csv = open('Qark_Scanned_App_Details.csv', 'w', newline='')
    writer = csv.writer(scanner_app_details_csv)
    writer.writerow(['app_name'])
    scanner_app_details_csv.close()


def create_Qark_intial_scan_csv():
    scanner_app_details_csv = open('Qark_Initial_Scans.csv', 'w', newline='')
    writer = csv.writer(scanner_app_details_csv)
    writer.writerow(
        ['app_name', 'category', 'Severity', 'Description', 'name', 'line_number', 'file_object', 'apk_exploit_dict'])
    scanner_app_details_csv.close()


def generate_Qark_scanned_app_details():
    if not os.path.exists('Qark_Scanned_App_Details.csv'):
        create_Qark_scanned_app_details_csv()

    if not os.path.exists('Qark_Initial_Scans.csv'):
        create_Qark_intial_scan_csv()

    if not os.path.exists("Qark_partial_datasets"):
        os.mkdir("Qark_partial_datasets")


def clear_qark_temp_files():

    if os.path.exists("Qark_Reversed"):
        shutil.rmtree("Qark_Reversed")

    if os.path.exists("Qark_Initial_Scans.csv"):
        os.remove("Qark_Initial_Scans.csv")

    if os.path.exists("Qark_Analysis_CWE_mapped.csv"):
        os.remove("Qark_Analysis_CWE_mapped.csv")

    if os.path.exists("classes-error.zip"):
        os.remove("classes-error.zip")


def write_Qark_scanned_app_details(app_name):
    common.msg_print("Writing data to CSV file...")
    scanned_app_details_file = open('Qark_Scanned_App_Details.csv', 'a', newline='')
    scanned_app_details_file_writer = csv.writer(scanned_app_details_file)
    scanned_app_details_file_writer.writerow([app_name])
    scanned_app_details_file.close()
    common.msg_print("Data writing completed!")


def start_qark_scan(app_name, apk_location_folder, os_env):
    common.msg_print("Scanning file...")
    apk_param = apk_location_folder + "/" + app_name + "/" + app_name + ".apk"
    build_path_param =""

    if os_env == "Windows":
        build_path_param = "Qark_Reversed/" + app_name
    elif os_env == "Linux":
        build_path_param = str(os.getcwd()) + "/Qark_Reversed/" + app_name

    # command = "qark_execute.bat " + apk_param + " " + build_path_param
    command = "qark --apk " + apk_param + " --build-path " + build_path_param + " --report-type json"

    if os_env == "Windows":
        subprocess.call(command, creationflags=subprocess.CREATE_NEW_CONSOLE)
    elif os_env == "Linux":
        subprocess.call(command, shell=True)

    common.msg_print("File scanned!")


def write_to_csv(data_row):
    scanned_App_Details_file = open('Qark_Initial_Scans.csv', 'a', newline='')
    scanned_App_Details_file_writer = csv.writer(scanned_App_Details_file)
    scanned_App_Details_file_writer.writerow(data_row)
    scanned_App_Details_file.close()


def get_report_details(app_name, qark_report_path, os_env):
    common.msg_print("Generating report...")
    report_file = open(qark_report_path + "/report.json")
    report_data = json.load(report_file)

    for issue in report_data:
        app_name = app_name
        issue_category = issue['category']
        issue_severity = issue['severity']
        issue_description = issue['description']
        issue_name = issue['name']
        issue_line_number = str(issue['line_number']).replace(",", "_")
        issue_file_object = issue['file_object']
        issue_apk_exploit_dict = str(issue['apk_exploit_dict']).replace(",", "_")
        issue_csv_row = [app_name, issue_category, issue_severity, issue_description, issue_name, issue_line_number,
                         issue_file_object, issue_apk_exploit_dict]

        try:
            if os_env == "Windows":
                file_path_only_split = issue_file_object.split("\\")
                if file_path_only_split[1] == app_name:
                    write_to_csv(issue_csv_row)
            elif os_env == "Linux":
                file_path_only_split = issue_file_object.split("/" + app_name + "/")
                if len(file_path_only_split) > 1:
                    write_to_csv(issue_csv_row)

        except:
            continue

    report_file.close()
    write_Qark_scanned_app_details(app_name)
    common.msg_print("Report generated!")


def get_cwe_detail(name, name_Qark_dictionary, cwe_ID_Qark_dictionary, cwe_Desc_Qark_dictionary):
    key_list = list(name_Qark_dictionary.keys())
    val_list = list(name_Qark_dictionary.values())
    position = val_list.index(name)
    return str(cwe_ID_Qark_dictionary.get(position)), str(cwe_Desc_Qark_dictionary.get(position))


def map_Qark_issue_with_CWE():
    common.msg_print("Mapping vulnerabilities with CWEs...")
    df_data = pd.read_csv("Qark_Initial_Scans.csv")
    df_data.set_index('name')

    cwe_mapping = [
        ['broadcast', 'Dynamic broadcast receiver found', 'CWE-925',
         'Improper Verification of Intent by Broadcast Receiver'],
        ['broadcast', 'Send Broadcast Receiver Permission', 'CWE-925',
         'Improper Verification of Intent by Broadcast Receiver'],
        ['broadcast', 'Broadcast sent without receiverPermission', 'CWE-925',
         'Improper Verification of Intent by Broadcast Receiver'],
        ['broadcast', 'Broadcast sent with receiverPermission with minimum SDK under 21', 'CWE-927',
         'Use of Implicit Intent for Sensitive Communication'],
        ['broadcast', 'Broadcast sent with receiverPermission', 'CWE-927',
         'Use of Implicit Intent for Sensitive Communication'],
        ['broadcast', 'Broadcast sent as specific user without receiverPermission', 'CWE-925',
         'Improper Verification of Intent by Broadcast'],
        ['broadcast', 'Broadcast sent as specific user with receiverPermission with minimum SDK under 21', 'CWE-927',
         'Use of Implicit Intent for Sensitive Communication'],
        ['broadcast', 'Broadcast sent as specific user with receiverPermission', 'CWE-927',
         'Use of Implicit Intent for Sensitive Communication'],
        ['broadcast', 'Ordered broadcast sent with receiverPermission with minimum SDK under 21', 'CWE-927',
         'Use of Implicit Intent for Sensitive Communication'],
        ['broadcast', 'Ordered broadcast sent with receiverPermission', 'CWE-927',
         'Use of Implicit Intent for Sensitive Communication'],
        ['broadcast', 'Sticky broadcast sent', 'CWE-927', 'Use of Implicit Intent for Sensitive Communication'],
        ['cert', 'Certification Validation', 'CWE-295', 'Improper Certificate Validation'],
        ['cert', 'Empty certificate method', 'CWE-299', 'Improper Check for Certificate Revocation'],
        ['cert', 'Empty (return) certificate method', 'CWE-299', 'Improper Check for Certificate Revocation'],
        ['cert', 'Unsafe implementation of onReceivedSslError', 'CWE-599', 'Missing Validation of OpenSSL Certificate'],
        ['cert', 'Hostname Verifier', 'CWE-297', 'Improper Validation of Certificate with Host Mismatch'],
        ['cert', 'Allow all hostname verifier used', 'CWE-297',
         'Improper Validation of Certificate with Host Mismatch'],
        ['cert', 'setHostnameVerifier set to ALLOW_ALL', 'CWE-297',
         'Improper Validation of Certificate with Host Mismatch'],
        ['crpto', 'ECB Cipher Usage', 'CWE-327', 'Use of a Broken or Risky Cryptographic Algorithm'],
        ['crpto', 'Encryption keys are packaged with the application', 'CWE-798', 'Use of Hard-coded Credentials'],
        ['crpto', 'RSA Cipher Usage', 'CWE-780', 'Use of RSA Algorithm without OAEP'],
        ['crpto', 'Random number generator is seeded with SecureSeed', 'CWE-337',
         'Predictable Seed in Pseudo-Random Number Generator (PRNG)'],
        ['file', 'Logging found', 'CWE-532', 'Insertion of Sensitive Information into Log File'],
        ['file', 'Potential API Key found', 'CWE-200', 'Exposure of Sensitive Information to an Unauthorized Actor'],
        ['file', 'External storage used', 'CWE-921', 'Storage of Sensitive Data in a Mechanism without Access Control'],
        ['file', 'File Permissions', 'CWE-276', 'Incorrect Default Permissions'],
        ['file', 'World readable file', 'CWE-276', 'Incorrect Default Permissions'],
        ['file', 'World writeable file', 'CWE-276', 'Incorrect Default Permissions'],
        ['file', 'Hardcoded HTTP url found', 'CWE-312', 'Cleartext Storage of Sensitive Information'],
        ['file', 'Insecure functions found', 'CWE-676', 'Use of Potentially Dangerous Function'],
        ['file', 'Phone number or IMEI detected', 'CWE-200',
         'Exposure of Sensitive Information to an Unauthorized Actor'],
        ['generic', 'Potientially vulnerable check permission function called', 'CWE-732',
         'Incorrect Permission Assignment for Critical Resource'],
        ['generic', 'Potential task hijacking', 'CWE-732', 'Incorrect Permission Assignment for Critical Resource'],
        ['intent', 'Empty pending intent found', 'CWE-927', 'Use of Implicit Intent for Sensitive Communication'],
        ['manifest', 'Backup is allowed in manifest', 'CWE-530',
         'Exposure of Backup File to an Unauthorized Control Sphere'],
        ['manifest', 'android:path tag used', 'CWE-926', 'Improper Export of Android Application Components'],
        ['manifest', 'Potential API Key found', 'CWE-200',
         'Exposure of Sensitive Information to an Unauthorized Actor'],
        ['manifest', 'Custom permissions are enabled in the manifest', 'CWE-926',
         'Improper Export of Android Application Components'],
        ['manifest', 'Manifest is manually set to debug', 'CWE-489', 'Active Debug Code'],
        ['manifest', 'Exported tags', 'CWE-926', 'Improper Export of Android Application Components'],
        ['manifest', 'Tap Jacking possible', 'CWE-1021', 'Improper Restriction of Rendered UI Layers or Frames'],
        ['manifest', 'launchMode=singleTask found', 'CWE-926', 'Improper Export of Android Application Components'],
        ['manifest', "android:allowTaskReparenting='true' found", 'CWE-926',
         'Improper Export of Android Application Components'],
        ['webview', 'Webview uses addJavascriptInterface pre-API 17', 'CWE-939',
         'Improper Authorization in Handler for Custom URL Scheme'],
        ['webview', 'Javascript enabled in Webview', 'CWE-939',
         'Improper Authorization in Handler for Custom URL Scheme'],
        ['webview', 'BaseURL set for Webview', 'CWE-939', 'Improper Authorization in Handler for Custom URL Scheme'],
        ['webview', 'Remote debugging enabled in Webview', 'CWE-749', 'Exposed Dangerous Method or Function'],
        ['webview', 'Webview enables content access', 'CWE-749', 'Exposed Dangerous Method or Function'],
        ['webview', 'Webview enables file access', 'CWE-749', 'Exposed Dangerous Method or Function'],
        ['webview', 'Webview enables universal access for JavaScript', 'CWE-939',
         'Improper Authorization in Handler for Custom URL Scheme'],
        ['webview', 'Webview enables DOM Storage', 'CWE-79',
         "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"]
    ]

    df_cwe_mapping = pd.DataFrame(cwe_mapping, columns=['Category', 'name', 'CWE_ID', 'CWE_Desc'])
    df_cwe_mapping = df_cwe_mapping[['name', 'CWE_ID', 'CWE_Desc']]
    df_cwe_mapping.set_index('name')

    cwe_Qark_dictionary = df_cwe_mapping.to_dict('dict')
    name_Qark_dictionary = cwe_Qark_dictionary.get("name")
    cwe_ID_Qark_dictionary = cwe_Qark_dictionary.get("CWE_ID")
    cwe_Desc_Qark_dictionary = cwe_Qark_dictionary.get("CWE_Desc")

    for index, item in cwe_Qark_dictionary.get('name').items():
        name = item
        CWE_ID, CWE_desc = get_cwe_detail(item, name_Qark_dictionary, cwe_ID_Qark_dictionary, cwe_Desc_Qark_dictionary)
        df_data.loc[df_data.name == name, "CWE_ID"] = CWE_ID
        df_data.loc[df_data.name == name, "CWE_Desc"] = CWE_desc

    df_data.columns = ['app_name', 'category', 'Severity', 'Description', 'qark_name', 'line_number', 'file_object',
                       'apk_exploit_dict', 'CWE_ID', 'CWE_Desc']

    if os.path.exists("Qark_Analysis_CWE_mapped.csv"):
        df_data.to_csv("Qark_Analysis_CWE_mapped.csv", mode='a', header=False)
    else:
        df_data.to_csv("Qark_Analysis_CWE_mapped.csv")

    common.msg_print("Mapped vulnerabilities with CWEs!")


def read_source_file(file_path):
    file_df = pd.read_csv(file_path, names=['code_line'], sep="\t", skip_blank_lines=False).fillna("")
    return file_df


def generate_dataset(start, end, df_data):
    vulnerability_dataset = []
    print(str(datetime.now()) + " : " + "Processing lines.", end="")
    for i in range(start, end):
        print(".", end="")
        row = df_data.iloc[i]
        try:
            app_name = row.app_name
            category = row.category
            severity = row.Severity
            qark_name = row.qark_name
            line_number = int(str(row.line_number).split("_")[0][1:])
            file_object = row.file_object
            apk_exploit_dict = row.apk_exploit_dict
            CWE_ID = row.CWE_ID
            CWE_Desc = row.CWE_Desc
            try:

                source_file = read_source_file(file_object)
                file_type = str(file_object).split(".")[1].lower()
                if file_type not in ['java', 'kt', 'xml', 'txt']:
                    continue

                for j, file_row in source_file.iterrows():
                    code_line = file_row.code_line.strip()
                    if j == line_number - 1:
                        vulnerability_status = 1

                        csv_data_row = [app_name, category, severity, qark_name, code_line, CWE_ID, CWE_Desc,
                                        vulnerability_status]
                    else:
                        vulnerability_status = 0
                        csv_data_row = [app_name, "", "", "", code_line, "", "", vulnerability_status]

                    vulnerability_dataset.append(csv_data_row)
            except Exception as e:
                # print(e)
                continue
        except Exception as ef:
            # print(ef)
            continue

    header = ['app_name', 'category', 'Severity', 'qark_name', 'Code', 'CWE_ID', 'CWE_Desc', 'Vulnerability_status']
    vulnerability_dataframe = pd.DataFrame(vulnerability_dataset, columns=header)

    vulnerability_dataframe.drop_duplicates(subset=['Code', 'CWE_ID'], inplace=True)

    vulnerability_dataframe.to_csv('Qark_partial_datasets/Unprocessed_Dataset_' + str(start) + '_' + str(end) + '.csv',
                                   sep=',', encoding='utf-8', index=False)
    print("\n" + str(datetime.now()) + " : " + "Lines processed!")


def execute_generation_process(df_data):
    dataset_length = len(df_data)
    increment = 2500

    common.msg_print("Qark - Unprocessed dataset generating...")
    for i in range(0, dataset_length, increment):
        start = i
        end = i + increment
        if end > dataset_length:
            end = dataset_length

        common.msg_print("Partial dataset generating : " + str(start) + "_" + str(end))
        generate_dataset(start, end, df_data)
        common.msg_print("Partial dataset generated : " + str(start) + "_" + str(end))

    common.msg_print("Qark - Unprocessed dataset generated!")


def combine_dfs():
    df_all = pd.DataFrame()
    files = os.listdir('Qark_partial_datasets')

    for file in files:
        data_csv = 'Qark_partial_datasets' + "/" + file
        df_current = pd.read_csv(data_csv).fillna("")
        df_all = pd.concat([df_all, df_current], ignore_index=True)

    df_all.drop_duplicates(subset=['Code', 'CWE_ID'], inplace=True)

    if os.path.exists("Qark_Unprocessed_Dataset.csv"):
        df_all.to_csv("Qark_Unprocessed_Dataset.csv", mode='a', index=False, header=False, encoding='utf-8')

    else:
        df_all.to_csv("Qark_Unprocessed_Dataset.csv", encoding='utf-8', index=False)

    if os.path.exists("Qark_partial_datasets"):
        shutil.rmtree("Qark_partial_datasets")

def generate_vulnerable_dataset_Qark():
    if os.path.exists("Qark_Analysis_CWE_mapped.csv"):
        df_data = pd.read_csv("Qark_Analysis_CWE_mapped.csv")
        df_data.set_index('app_name')
        execute_generation_process(df_data)
