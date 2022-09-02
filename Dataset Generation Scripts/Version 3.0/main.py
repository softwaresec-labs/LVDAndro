import os
import platform

import pandas as pd
import mobsf_api_key_retriver as mobsf_api_key
import mobsf_unprocessed_dataset_generation as mobsf
import qark_unprocessed_dataset_generation as qark
import processed_dataset_generation as pro_data_gen
import common
import configparser


def perform_analysis():
    read_config = configparser.ConfigParser()
    read_config.read("settings.ini")

    apk_location_folder = read_config.get("Common", "APK_LOCATION_FOLDER")

    MobSF_BASE_PATH = read_config.get("MobSF", "MobSF_BASE_PATH")
    server_ip = read_config.get("MobSF", "MobSF_SERVER_IP")
    server_port = read_config.get("MobSF", "MobSF_SERVER_PORT")
    server = "http://" + server_ip + ":" + server_port

    qark_report_path = read_config.get("Qark", "Qark_REPORT_PATH")

    os_env = platform.system()


    common.msg_print("Starting analysis...")
    mobsf.start_MobSF_server(MobSF_BASE_PATH, server_ip, server_port,os_env)
    mobsf.generate_MobSF_scanned_app_details()
    api_key = mobsf_api_key.get_api_key(server)
    qark.generate_Qark_scanned_app_details()

    files = os.listdir(apk_location_folder)
    is_file_to_be_scanned_qark = False
    for file in files:
        common.msg_print("----------Application Name : " + file + ".apk----------")
        common.msg_print("Starting MobSF analysis...")
        mobsf.execute_MobSF_process(apk_location_folder, api_key, server, file)
        common.msg_print("MobSF analysis completed!")

        common.msg_print("Starting QARK analysis...")
        try:
            scanned_apps = pd.read_csv('Qark_Scanned_App_Details.csv')
            if file in scanned_apps.app_name.values:
                common.msg_print("This file has already been scanned!")
            else:
                is_file_to_be_scanned_qark = True
                qark.start_qark_scan(file, apk_location_folder, os_env)

                qark.get_report_details(file, qark_report_path,os_env)
                qark.map_Qark_issue_with_CWE()
                qark.create_Qark_intial_scan_csv()

        except Exception as e:
            common.msg_print("Unexpected Error :" + str(e))
            continue

        common.msg_print("Qark analysis completed!")

    if is_file_to_be_scanned_qark:
        qark.generate_vulnerable_dataset_Qark()
        qark.combine_dfs()

    qark.clear_qark_temp_files()

    common.msg_print("Analysis completed!")


def generate_processed_datasets():
    common.msg_print("Starting MobSF processed dataset generation...")
    pro_data_gen.generate_processed_dataset("MobSF")
    common.msg_print("MobSF processed dataset generated!")

    common.msg_print("Starting Qark processed dataset generation...")
    pro_data_gen.generate_processed_dataset("Qark")
    common.msg_print("Qark processed dataset generated!")

    common.msg_print("Starting LVDAndro final dataset generation...")
    pro_data_gen.generate_combined_processed_dataset()
    common.msg_print("LVDAndro final dataset generated!")


def main():
    perform_analysis()
    generate_processed_datasets()

if __name__ == '__main__':
    main()




