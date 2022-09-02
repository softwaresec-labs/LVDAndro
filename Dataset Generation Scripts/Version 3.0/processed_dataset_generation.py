import pandas as pd
import re


def preprocess_comments_and_strings(code_line):
    processed_code_line = code_line

    encryption_hashing_pattern = "AES|aes|SHA-1|sha-1|SHA1|sha1|MD5|md5"
    ip_pattern = "\w*([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\w*"
    string_pattern = "\"[\w|\s|$|&|+|,|:|;|=|?|@|#|_|/|\-|\.|!|`|~|%|\^|\*|\(|\)|\'\\[|\]\{|\}]*\""

    # Checking for encryption related strings
    find_encryption = re.search(encryption_hashing_pattern, processed_code_line)

    # Checking for IP related strings
    find_ip = re.search(ip_pattern, processed_code_line)

    if (find_encryption is None) & (find_ip is None):
        # replacing all strings with dummy string
        processed_code_line = re.sub(string_pattern, "\"user_str\"", processed_code_line)

    # replacing comments with dummy comment
    # comment_pattern = "//.*|/\\*(?s:.*?)\\*/|(\"(?:(?<!\\\\)(?:\\\\\\\\)*\\\\\"|[^\r\n\"])*\")"
    comment_pattern = "//.*|/\\*(?s:.*?)\\*/|/\\*(.)*|(.)*\\*/"
    processed_code_line = re.sub(comment_pattern, "//user_comment", processed_code_line)

    return processed_code_line


def generate_processed_dataset(scanner):
    unprocessed_csv = scanner+"_Unprocessed_Dataset.csv"
    processed_csv = unprocessed_csv.replace("Unprocessed", "Processed")

    unprocessed_dataset_df = pd.read_csv(unprocessed_csv).fillna("")

    unprocessed_dataset_df.drop_duplicates(subset=['Code', 'CWE_ID'], inplace=True)
    comments_and_strings_processed_codes = []

    if scanner == "MobSF":
        for code in unprocessed_dataset_df.Code:
            processed_code = preprocess_comments_and_strings(code)
            comments_and_strings_processed_codes.append(processed_code)

        # comments_and_strings_processed_codes_series = pd.Series(comments_and_strings_processed_codes)

    elif scanner == "Qark":
        for code in unprocessed_dataset_df.Code:
            if len(code) > 150:
                processed_code = "user_str"
            else:
                processed_code = preprocess_comments_and_strings(code)

            comments_and_strings_processed_codes.append(processed_code)

    unprocessed_dataset_df["processed_code"] = comments_and_strings_processed_codes
    processed_df = unprocessed_dataset_df

    processed_df.drop_duplicates(subset=['processed_code', 'CWE_ID'], inplace=True)

    processed_df.to_csv(processed_csv, sep=',', encoding='utf-8', index=False)


def generate_combined_processed_dataset():
    MobSF_processed_df = pd.read_csv("MobSF_Processed_Dataset.csv", low_memory=False).fillna("")
    Qark_processed_df = pd.read_csv("Qark_Processed_Dataset.csv", low_memory=False).fillna("")

    del MobSF_processed_df['ID']
    del Qark_processed_df['app_name']

    combined_processed_df = pd.concat([MobSF_processed_df, Qark_processed_df], ignore_index=True).fillna("")
    combined_processed_df = combined_processed_df.drop_duplicates(subset=['processed_code', 'CWE_ID'], keep='first')

    combined_processed_df.reset_index(inplace=True)
    combined_processed_df = combined_processed_df.rename(columns={'index': 'index'})

    combined_processed_df.to_csv("LVDAndro_Processed_Dataset.csv", index=False)

