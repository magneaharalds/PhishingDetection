import csv
import functools
import itertools
import os
import sys
import time

import msgpack
import pandas as pd
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


def return_value_if_present(key, row, value):
    if row[key] is None or len(row[key][value]) == 0:
        return ""
    else:
        return row[key][value][0]


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
        row_dict["issuer_common_name"] = return_value_if_present(key, row, "common_name")
        # vantar eiginlega organization líka en var ekki með í fyrsta run-i
        row_dict["issuer_org"] = return_value_if_present(key, row, "organization")
    elif key == "subject":
        row_dict["subject_common_name"] = return_value_if_present(key, row, "common_name")
        row_dict["subject_country"] = return_value_if_present(key, row, "country")
        row_dict["subject_locality"] = return_value_if_present(key, row, "locality")
        row_dict["subject_province"] = return_value_if_present(key, row, "province")
        row_dict["subject_organization"] = return_value_if_present(key, row, "organization")
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




def convert_to_df(phish_keep_names: dict,
                  tranco_keep_names: dict,
                  block_size: int,
                  #block_number: int,
                  rows: list):
    try:
        start_time = time.time()
        block_number = rows[0]
        if os.path.exists(f"parsedCerts2/certificateDF_{block_number}_{block_size}_DONE"):
            print(f"Nothing to do for block {block_number}")
            return
        df = pd.DataFrame(columns=column_names)
        build_row = dict.fromkeys(column_names)
        filt_phish = Filter(phish_keep_names)
        filt_tranco = Filter(tranco_keep_names)
        for row in rows[1]:
            for key, value in row.items():
                key_switch(key, row, build_row)

            build_row["in_tranco"] = filt_tranco(row["names"])
            build_row["in_phish"] = filt_phish(row["names"])
            df.loc[len(df)] = build_row

            # df.append(build_row, ignore_index=True)
            build_row.clear()
            build_row = dict.fromkeys(column_names)

        df.to_pickle(f"parsedCerts2/certificateDF_{block_number}_{block_size}.pkl")
        with open(f"parsedCerts2/certificateDF_{block_number}_{block_size}_DONE", 'w') as fp:
            fp.write("DONE")
        print(f"block {block_number} "+"--- %s seconds ---" % (time.time() - start_time))
    except Exception as e:
        print(f"Unhandled Error in block {block_number}", exc_info=e)
        return


def main():
    block_size = int(sys.argv[1])
    total_blocks = int(sys.argv[2])
    n_workers = int(sys.argv[3])
    # block_numbers = list(range(0, total_blocks))
    # block_numbers_left = [i for i in block_numbers if not os.path.exists(f"parsedCerts/certificateDF_{i}_{block_size}_DONE")]


    with open("joined_msgpack.mp", 'rb') as fp:
        rows = msgpack.load(fp)

    iter_rows = [rows[i:i+block_size] for i in range(0, len(rows), block_size)]
    dict_rows = list()
    for counter, row in enumerate(iter_rows):
        dict_rows.append([counter, row])
    # start_time = time.time()
    counter = 0
    for chunk in dict_rows:
        # ATHATH PHISH OG TRANCO ER SWAPPAÐ !!!!!!!!!!!!!!!!!
        convert_to_df(create_phish_set(), create_tranco_set(), len(chunk[1]), chunk)
        print(f"Done with chunk {counter}")
        counter += 1
    # f = functools.partial(convert_to_df, create_tranco_set(), create_phish_set(), block_size)
    # with tqdm.tqdm(total=len(dict_rows)) as pbar:
    #     # pbar.update(len(block_numbers) - len(iter_rows))
    #     with Pool(n_workers) as p:
    #         for _ in p.map(f, dict_rows):
    #             pbar.update(1)
    # print("--- %s seconds ---" % (time.time() - start_time))


if __name__ == '__main__':
    #start_time = time.time()
    main()
    # print("--- %s seconds ---" % (time.time() - start_time))
    # df = pd.read_pickle("parsedCerts/certificateDF_55_20000.pkl")
    # print(df)

