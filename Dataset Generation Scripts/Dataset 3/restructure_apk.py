import os

path = "/home/janaka/Downloads/APKs/apks"


def list_files():

    dir_list = os.listdir(path)

    file_counter = 82
    for apk_file in dir_list:
        old_name = path+"/"+apk_file
        new_file_name = "app"+str(file_counter)
        os.mkdir(path+"/"+new_file_name)
        new_name = path+"/"+new_file_name+"/"+new_file_name+".apk"
        os.rename(old_name, new_name)

        file_counter = file_counter+1


if __name__ == '__main__':
    list_files()



