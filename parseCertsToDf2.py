import csv
import functools
import itertools
import os
import sys
import time

import msgpack
import pandas as pd
import numpy as np
from multiprocessing import Pool, Manager
import tqdm


column_names = [
    "names",
    "serial_number",
    "subject_common_name",
    "subject_country",
    "subject_locality",
    "subject_province",
    "subject_organization",
    "subject_num_fields",
    "apple_ever_valid",
    "microsoft_ever_valid",
    "nss_ever_valid",
    "validation_level",
    "length_seconds",
    "not_after",
    "not_before",
    "crl_distribution_points",
    "dns_names",
    "key_algorithm_name",
    "version",
    "signature_algorithm_name",
    "issuer_dn",
    "issuer_common_name",
    "authority_info_access",
    "certificate_policies",
    "basic_constraints",
    "key_usage_present",
    "key_usage_value",
    #"key_usage",
    "extended_key_usage_present",
    #"extended_key_usage",
    "signed_certificate_timestamp",
    "authority_key_id",
    "critical",
    "in_tranco",
    "in_phish",
    "ocsp_urls",
    "notice_numbers"
]


def concat():
    res = list()
    # packer = msgpack.Packer()
    # packer.pack_array_header(10 ** 6)

    for p in os.scandir("bigQueryOutputs"):
        if p.name.endswith(".mp"):
            with open(p.path, 'rb') as fp:
                rows = msgpack.load(fp)
                res.extend(rows)
            # for r in rows:
            #     packer.pack(r)
    with open(f"allrows.mp", 'wb') as fp_out:
        msgpack.dump(res, fp_out)


def write_csv(data):
    with open('example.csv', 'a') as outfile:
        writer = csv.writer(outfile)
        writer.writerow(data)


def len_greater_than_0(key, row):
    if row[key] is None or len(row[key]) == 0:
        return False
    else:
        return True


def return_value_if_present(key, key2, row):
    if row[key] is None or len(row[key][key2]) == 0:
        return ""
    else:
        return row[key][key2][0]


def return_key_usage_value_if_present(key, key2, row):
    if row[key] is None:
        return -1
    else:
        return row[key][key2]

def num_non_empty_subject_fields(key, row):
    if row[key] is None or len(row[key]) == 0:
        return 0
    counter = 0
    for field in row[key]:
        if len(row[key][field]) > 0:
            counter += 1
    return counter


def get_notice_numbers(key, row):
    if row[key] is None or len(row[key]) == 0:
        return -1
    if row[key][0]["user_notice"] is None or len(row[key][0]["user_notice"]) == 0:
        return -1
    if row[key][0]["user_notice"][0]["notice_reference"] is None or len(row[key][0]["user_notice"][0]["notice_reference"]) == 0:
        return -1
    if row[key][0]["user_notice"][0]["notice_reference"]["notice_numbers"] is None:
        return -1
    return row[key][0]["user_notice"][0]["notice_reference"]["notice_numbers"]




def key_switch(key, row, row_dict):
    # if key == "crl_distribution_points":
    #     row_dict[key] = len_greater_than_0("crl_distribution_points", row)
    # elif key == "issuer_dn":
    #     row_dict[key] = len_greater_than_0("issuer_dn", row)
    if key == "issuer":
        row_dict["issuer_common_name"] = return_value_if_present(key, "common_name", row)
        # vantar eiginlega organization líka en var ekki með í fyrsta run-i
        row_dict["issuer_org"] = return_value_if_present(key, "organization", row)
    elif key == "subject":
        row_dict["subject_common_name"] = return_value_if_present(key, "common_name", row)
        row_dict["subject_country"] = return_value_if_present(key, "country", row)
        row_dict["subject_locality"] = return_value_if_present(key, "locality", row)
        row_dict["subject_province"] = return_value_if_present(key, "province", row)
        row_dict["subject_organization"] = return_value_if_present(key, "organization", row)
        row_dict["subject_num_fields"] = num_non_empty_subject_fields(key, row)
    elif key == "authority_info_access":
        is_present = len_greater_than_0(key, row)
        row_dict[key] = is_present
        if is_present:
            row_dict["ocsp_urls"] = len_greater_than_0("ocsp_urls", row["authority_info_access"])
        else:
            row_dict["ocsp_urls"] = False
    elif key == "certificate_policies":
        row_dict["notice_numbers"] = get_notice_numbers(key, row)
        row_dict[key] = len_greater_than_0(key, row)
    elif key == "basic_constraints":
        row_dict[key] = len_greater_than_0(key, row)
    elif key == "key_usage":
        if len_greater_than_0(key, row):
            row_dict["key_usage_present"] = True
            row_dict["key_usage_value"] = row[key]["value"]
        else:
            row_dict["key_usage_present"] = False
            row_dict["key_usage_value"] = None
    elif key == "extended_key_usage":
        row_dict[key] = len_greater_than_0(key, row)
    elif key == "signed_certificate_timestamp":
        row_dict[key] = len_greater_than_0(key, row)
    elif key == "authority_key_id":
        row_dict[key] = len_greater_than_0(key, row)
    else:
        row_dict[key] = row[key]


def clean_block_list():
    phish = pd.read_csv(filepath_or_buffer='/home/mha/PycharmProjects/thesis/bigQueryCode/phishtank.csv', sep=',',
                        header=0)
    phish['verification_time'] = pd.to_datetime(phish['verification_time'])
    phish = phish[phish['verification_time'].dt.year == 2023]
    phish[['protocol', 'urlNoProto']] = phish['url'].str.split('://', expand=True, n=1)
    phish = phish.drop(phish[phish.protocol == "http"].index)
    phish.reset_index(inplace=True)
    phish[['fullDomain', 'path']] = phish['urlNoProto'].str.split('/', expand=True, n=1)
    phish = phish.drop(phish[phish['fullDomain'].str.endswith('google.com')].index)
    phish = phish.drop(phish[phish['fullDomain'].str.endswith('amazonaws.com')].index)
    phish = phish.drop(phish[phish['fullDomain'].str.endswith('godaddysites.com')].index)
    phish = phish.drop(phish[phish['fullDomain'].str.endswith('weeblysite.com')].index)
    phish = phish.drop(phish[phish['fullDomain'].str.endswith('mybluehost.me')].index)
    phish = phish.drop(phish[phish['fullDomain'].str.endswith('inmotionhosting.com')].index)
    phish = phish.drop(phish[phish['fullDomain'].str.endswith('firebaseapp.com')].index)
    phish = phish.drop(phish[phish['fullDomain'].str.endswith('googleapis.com')].index)
    phish = phish.drop(phish[phish['fullDomain'].str.endswith('azurefd.net')].index)
    phish.reset_index(inplace=True)
    phish['fullDomain'] = phish['fullDomain'].str.replace('www.', '')
    return phish


def top_tranco():
    tranco_raw = pd.read_csv(filepath_or_buffer='/home/mha/PycharmProjects/thesis/bigQueryCode/tranco.csv', sep=',',
                             header=0)
    return tranco_raw.drop(tranco_raw[tranco_raw['rank'] > 20000].index)


def create_phish_set():
    block_list = clean_block_list()
    s = block_list['fullDomain'].unique()

    keep_domains = dict()
    for domain in s:
        add_keep_domain(domain, keep_domains)
    return keep_domains



def create_tranco_set():
    tranco = top_tranco()
    s = set(tranco['domain'].unique())

    keep_domains = dict()
    for domain in s:
        add_keep_domain(domain, keep_domains)
    return keep_domains


def add_keep_domain(domain: str, keep_domains: dict):
    reversed_parts = reversed(domain.split('.'))
    domain_node = keep_domains
    for part in reversed_parts:
        try:
            domain_node = domain_node[part]
        except KeyError:
            n_domain_node = dict()
            domain_node[part] = n_domain_node
            domain_node = n_domain_node

    domain_node["."] = domain


def is_in_keep_domains(domain: str, keep_domains: dict):
    reversed_parts = reversed(domain.split('.'))
    domain_node = keep_domains
    for part in reversed_parts:
        try:
            domain_node = domain_node[part]
        except KeyError:
            if part == '*':
                for domain, subdomains in domain_node.items():
                    if domain == '.':
                        continue
                    if '.' in subdomains:
                        return True
            return False

    return '.' in domain_node


class Filter:
    def __init__(self, keep_names):
        self.keep_names = keep_names
        # add_keep_domain("OpenWrt", self.keep_names)
        # add_keep_domain("foo.ifjllc.com", self.keep_names)

    def __call__(self, names):
        for name in names:
            # for name in row["f"][1]["v"]:
            # if name['v'] in self.keep_names:
            return is_in_keep_domains(name, self.keep_names)


PHISH_FILTER = Filter(create_phish_set())
TRANCO_FILTER = Filter(create_tranco_set())

def deduce_phish(key, row):
    return PHISH_FILTER(row[key])


def deduce_tranco(key, row):
    return TRANCO_FILTER(row[key])


def get_ocsp_urls_present(key, row):
    is_present = len_greater_than_0(key, row)
    if is_present:
        return len_greater_than_0("ocsp_urls", row["authority_info_access"])
    else:
        return False


COL_VALUE_GETTERS = dict(
    issuer_common_name=functools.partial(return_value_if_present, "issuer", "common_name"),
    issuer_organization=functools.partial(return_value_if_present, "issuer", "organization"),
    key_usage_present=functools.partial(len_greater_than_0, "key_usage"),
    names= lambda row: str(row["names"]),
    serial_number= lambda row: row["serial_number"],
    subject_common_name=functools.partial(return_value_if_present, "subject", "common_name"),
    subject_country=functools.partial(return_value_if_present, "subject", "country"),
    subject_locality=functools.partial(return_value_if_present, "subject", "locality"),
    subject_province=functools.partial(return_value_if_present, "subject", "province"),
    subject_organization=functools.partial(return_value_if_present, "subject", "organization"),
    subject_num_fields=functools.partial(num_non_empty_subject_fields, "subject"),
    apple_ever_valid=lambda row: row["apple_ever_valid"],
    microsoft_ever_valid=lambda row: row["microsoft_ever_valid"],
    nss_ever_valid=lambda row: row["nss_ever_valid"],
    validation_level=lambda row: row["validation_level"],
    length_seconds=lambda row: row["length_seconds"],
    not_after=lambda row: row["not_after"],
    not_before=lambda row: row["not_before"],
    crl_dist_point_present=functools.partial(len_greater_than_0,"crl_distribution_points"),
    dns_names=lambda row: str(row["dns_names"]),
    key_algorithm_name=lambda row: row["key_algorithm_name"],
    version=lambda row: row["version"],
    signature_algorithm_name=lambda row: row["signature_algorithm_name"],
    issuer_dn=lambda row: row["issuer_dn"],
    authority_info_access=functools.partial(len_greater_than_0, "authority_info_access"),
    certificate_policies=functools.partial(len_greater_than_0, "certificate_policies"),
    basic_constraints=functools.partial(len_greater_than_0, "basic_constraints"),
    key_usage_value=functools.partial(return_key_usage_value_if_present, "key_usage", "value"),
    extended_key_usage_present=functools.partial(len_greater_than_0, "extended_key_usage"),
    signed_certificate_timestamps=functools.partial(len_greater_than_0, "signed_certificate_timestamps"),
    authority_key_id=functools.partial(len_greater_than_0, "authority_key_id"),
    in_tranco=functools.partial(deduce_tranco, "names"),
    in_phish=functools.partial(deduce_phish, "names"),
    ocsp_urls=functools.partial(get_ocsp_urls_present, "authority_info_access"),
    notice_numbers=functools.partial(get_notice_numbers, "certificate_policies"),
)

# def convert_to_df(phish_keep_names: dict,
#                   tranco_keep_names: dict,
#                   # block_size: int,
#                   file_number,
#                   block_number: int,
#                   rows: list):
#     try:
#         start_time = time.time()
#         block_size = len(rows)
#         if os.path.exists(f"parsedCerts2/certificateDF_{file_number}_{block_number}_{block_size}_DONE"):
#             print(f"Nothing to do for block {block_number} and file {file_number}")
#             return
#         df = pd.DataFrame(columns=column_names)
#         build_row = dict.fromkeys(column_names)
#         filt_phish = Filter(phish_keep_names)
#         filt_tranco = Filter(tranco_keep_names)
#         for row in rows:
#             for key, value in row.items():
#                 key_switch(key, row, build_row)
#
#             build_row["in_tranco"] = filt_tranco(row["names"])
#             build_row["in_phish"] = filt_phish(row["names"])
#             df.loc[len(df)] = build_row
#
#             # df.append(build_row, ignore_index=True)
#             build_row.clear()
#             build_row = dict.fromkeys(column_names)
#
#         df.to_pickle(f"parsedCerts2/certificateDF_{file_number}_{block_number}_{block_size}.pkl")
#         with open(f"parsedCerts2/certificateDF_{file_number}_{block_number}_{block_size}_DONE", 'w') as fp:
#             fp.write("DONE")
#         print(f"block {block_number} "+"--- %s seconds ---" % (time.time() - start_time))
#     except Exception as e:
#         print(f"Unhandled Error in block {block_number} "+ e)
#         return

strDtype = pd.StringDtype()
def convert_to_df2(phish_keep_names: dict, tranco_keep_names: dict, file_number, unpacker):
    try:
        start_time = time.time()
        if os.path.exists(f"parsedCerts2/certificateDF_{file_number}DONE"):
            print(f"Nothing to do for block {file_number}")
            return

        n = unpacker.read_array_header()
        shape = (n,)
        # prealloc_data = {
        #     "issuer_common_name": pd.Series([None] * n, dtype="string"),
        #     "key_usage_present": pd.Series(np.ndarray(shape, dtype=np.dtype("?"))),
        #     "names": pd.Series([None] * n, dtype="string"),
        #     "serial_number": pd.Series([None] * n, dtype="string"),
        #     "subject_common_name": pd.Series([None] * n, dtype="string"),
        #     "subject_country": pd.Series([None] * n, dtype="string"),
        #     "subject_locality": pd.Series([None] * n, dtype="string"),
        #     "subject_province": pd.Series([None] * n, dtype="string"),
        #     "subject_organization": pd.Series([None] * n, dtype="string"),
        #     "subject_num_fields": pd.Series(np.ndarray(shape, dtype=np.dtype("i"))),
        #     "apple_ever_valid": pd.Series(np.ndarray(shape, dtype=np.dtype("?"))),
        #     "microsoft_ever_valid": pd.Series(np.ndarray(shape, dtype=np.dtype("?"))),
        #     "nss_ever_valid": pd.Series(np.ndarray(shape, dtype=np.dtype("?"))),
        #     "validation_level": pd.Series([None] * n, dtype="string"),
        #     "length_seconds": pd.Series(np.ndarray(shape, dtype=np.dtype("i"))),
        #     "not_after": pd.Series(np.ndarray(shape, dtype=np.dtype("f"))),
        #     "not_before": pd.Series(np.ndarray(shape, dtype=np.dtype("f"))),
        #     "crl_dist_point_present": pd.Series(np.ndarray(shape, dtype=np.dtype("?"))),
        #     "dns_names": pd.Series([None] * n, dtype="string"),
        #     "key_algorithm_name": pd.Series([None] * n, dtype="string"),
        #     "version": pd.Series(np.ndarray(shape, dtype=np.dtype("i"))),
        #     "signature_algorithm_name": pd.Series([None] * n, dtype="string"),
        #     "issuer_dn": pd.Series([None] * n, dtype="string"),
        #     "authority_info_access": pd.Series(np.ndarray(shape, dtype=np.dtype("?"))),
        #     "certificate_policies": pd.Series(np.ndarray(shape, dtype=np.dtype("?"))),
        #     "basic_constraints": pd.Series(np.ndarray(shape, dtype=np.dtype("?"))),
        #     "key_usage_value": pd.Series(np.ndarray(shape, dtype=np.dtype("i"))),
        #     "extended_key_usage_present": pd.Series(np.ndarray(shape, dtype=np.dtype("?"))),
        #     "signed_certificate_timestamps": pd.Series(np.ndarray(shape, dtype=np.dtype("?"))),
        #     "authority_key_id": pd.Series(np.ndarray(shape, dtype=np.dtype("?"))),
        #     "in_tranco": pd.Series(np.ndarray(shape, dtype=np.dtype("?"))),
        #     "in_phish": pd.Series(np.ndarray(shape, dtype=np.dtype("?"))),
        #     "ocsp_urls": pd.Series(np.ndarray(shape, dtype=np.dtype("?"))),
        #     "notice_numbers": pd.Series(np.ndarray(shape, dtype=np.dtype("i"))),
        # }

        # df = pd.DataFrame(prealloc_data)
        df = pd.DataFrame(columns=column_names)

        build_row = dict.fromkeys(column_names)
        filt_phish = Filter(phish_keep_names)
        filt_tranco = Filter(tranco_keep_names)
        row_added_count = 0
        chunk_number = 0
        start_chunk = time.time()
        for i in range(n):
            try:
                row = unpacker.unpack()
            except:
                df.to_pickle(f"parsedCerts2/certificateDF_{file_number}.pkl")
                return

            start = time.time()
            # build_row = [COL_VALUE_GETTERS[key](row) for key in prealloc_data.keys()]

            for key, value in row.items():
                key_switch(key, row, build_row)

            build_row["in_tranco"] = filt_tranco(row["names"])
            build_row["in_phish"] = filt_phish(row["names"])
            # df.loc[row_added_count] = build_row

            df = df.append(build_row, ignore_index=True)
            build_row.clear()
            build_row = dict.fromkeys(column_names)
            if row_added_count % 5_000 == 0:
                print(f"{row_added_count} rows added in %s seconds" % (time.time() - start_chunk))
                df.to_pickle(f"parsedCerts2/certificateDF_{file_number}_{chunk_number}.pkl")
                df = pd.DataFrame(columns=column_names)
                chunk_number += 1
                start_chunk = time.time()
            row_added_count += 1
            # print(f"Time for {len(row)} rows %s seconds" %(time.time() - start))

        # df.to_pickle(f"parsedCerts2/certificateDF_{file_number}.pkl")
        with open(f"parsedCerts2/certificateDF_{file_number}_DONE", 'w') as fp:
            fp.write("DONE")
        print(f"file {file_number} " + "--- %s seconds ---" % (time.time() - start_time))
    except Exception as e:
        print(f"Unhandled Error in file {file_number} " + e)
        df.to_pickle(f"parsedCerts2/certificateDF_{file_number}.pkl")
        return


def main():
    block_size = int(sys.argv[1])
    total_blocks = int(sys.argv[2])
    n_workers = int(sys.argv[3])
    # block_numbers = list(range(0, total_blocks))
    # block_numbers_left = [i for i in block_numbers if not os.path.exists(f"parsedCerts/certificateDF_{i}_{block_size}_DONE")]


    with open("/home/mha/PycharmProjects/thesis/joinedMsgPacks/merged2.mp", 'rb') as fp:
        unpacker = msgpack.Unpacker(fp)
        counter = 0
        file_number = 1
        convert_to_df2(create_phish_set(), create_tranco_set(), file_number, unpacker)
        # for unpacked in unpacker:
        #     if len(unpacked) > 0:
        #         convert_to_df(create_phish_set(), create_tranco_set(), file_number, counter, unpacked)
        #         counter += 1
            # Process each unpacked object individually
    # with open("/home/mha/PycharmProjects/thesis/joinedMsgPacks/combined_1.mp", 'rb') as fp:
    #     rows = msgpack.load(fp)
    #
    # iter_rows = [rows[i:i+block_size] for i in range(0, len(rows), block_size)]
    # dict_rows = list()
    # for counter, row in enumerate(iter_rows):
    #     dict_rows.append([counter, row])
    # # start_time = time.time()
    # counter = 0
    # for chunk in dict_rows:
    #     # ATHATH PHISH OG TRANCO ER SWAPPAÐ !!!!!!!!!!!!!!!!!
    #     convert_to_df(create_phish_set(), create_tranco_set(), len(chunk[1]), 1, chunk)
    #     print(f"Done with chunk {counter}")
    #     counter += 1


if __name__ == '__main__':
    #start_time = time.time()
    main()
    # print("--- %s seconds ---" % (time.time() - start_time))
    # df = pd.read_pickle("parsedCerts/certificateDF_55_20000.pkl")
    # print(df)

