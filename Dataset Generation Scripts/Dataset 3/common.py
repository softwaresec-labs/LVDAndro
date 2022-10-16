from datetime import datetime
import configparser


def msg_print(print_str):
    print(str(datetime.now()) + " : " + print_str)

def ini_file_writer():
    write_config = configparser.ConfigParser()

    write_config.add_section("Common")
    write_config.set("Common", "APK_LOCATION_FOLDER", "/home/janaka/Downloads/APKs")

    write_config.add_section("MobSF")
    write_config.set("MobSF", "MobSF_BASE_PATH", "/home/janaka/Mobile-Security-Framework-MobSF")
    write_config.set("MobSF", "MobSF_SERVER_IP", "127.0.0.1")
    write_config.set("MobSF", "MobSF_SERVER_PORT", "8000")

    write_config.add_section("Qark")
    write_config.set("Qark", "Qark_REPORT_PATH", "/home/janaka/.local/lib/python3.8/site-packages/qark/report")

    cfgfile = open("settings.ini", 'w')
    write_config.write(cfgfile)
    cfgfile.close()
