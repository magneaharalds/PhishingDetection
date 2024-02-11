import math
import os

import numpy as np
import pandas as pd
import random
import re
import time
import datetime
import ipaddress
import idna


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


def create_phish_set():
    block_list = clean_block_list()
    s = block_list['fullDomain'].unique()

    keep_domains = dict()
    for domain in s:
        add_keep_domain(domain, keep_domains)
    return keep_domains


def top_tranco():
    tranco_raw = pd.read_csv(filepath_or_buffer='/home/mha/PycharmProjects/thesis/bigQueryCode/tranco.csv', sep=',',
                             header=0)
    return tranco_raw.drop(tranco_raw[tranco_raw['rank'] > 20000].index)


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

    def __call__(self, names):
        for name in names:
            return is_in_keep_domains(name, self.keep_names)



def concat_pickle():
    df_final = pd.DataFrame(columns=column_names)
    for p in os.scandir("parsedCerts2"):
        if p.name.endswith(".pkl"):
            df = pd.read_pickle(p)
            df_final = df_final.append(df, ignore_index=True)

    df_final.to_pickle("certPrufa.pkl")




feature_names = [
    "validation_level",
    "apple_ever_valid",
    "nss_ever_valid",
    "microsoft_ever_valid",
    "subject_has_country",
    "subject_has_province", # vantar
    "subject_has_locality",
    "subject_has_common_name",
    "subject_only_cn",
    "num_subject_rdn",
    "subject_len",
    "length_seconds",
    "notice_numbers", # vantar
    "ocsp_urls", # vantar
    "crl_dist_point_present"
    "num_san_dns_names",
    "unique_tlds",
    "pub_key_algorithm",
    #"len_pub_key_algorithm", # vantar alveg held ég
    "version",
    "signature_algorithm_name",
    "len_serial_number",
    "len_issuer_dn",
    "issuer_has_common_name",
    "issuer_org",
    "subject_is_empty",
    "has_any_extensions", # vantar
    "serial_number_conforms" # vantar
    "valid_timestamps",
    "lcs_sans",
    "lcs_sans_normed",
    "sans_cdn", # hvernig á að reikna þetta?
    # 35-36
    "authority_info_access",
    # 37-38
    "certificate_policies",
    # 39-40
    "basic_constraints",
    "key_usage_present",
    "key_usage_value",
    # 45-46
    "extended_key_usage_present",
    # 49-50
    "signed_certificate_timestamp",
    #47-48
    "authority_key_id",
    "in_tranco",
    "in_phish"
]


def count_unique_tlds(sans):
    unique_tlds = set()
    for domain in sans:
        unique_tlds.add(domain.split('.')[-1])
    return len(unique_tlds)


def find_lcs(arr):
    # Determine size of the array
    n = len(arr)
    if n == 0:
        return ""
    # Take first word from array
    # as reference
    s = arr[0]
    l = len(s)

    res = ""

    for i in range(l):
        for j in range(i + 1, l + 1):

            # generating all possible substrings
            # of our reference string arr[0] i.e s
            stem = s[i:j]
            k = 1
            for k in range(1, n):

                # Check if the generated stem is
                # common to all words
                if stem not in arr[k]:
                    break

            # If current substring is present in
            # all strings and its length is greater
            # than current result
            if (k + 1 == n and len(res) < len(stem)):
                res = stem

    return res


def find_longest_substring(row):
    lcs = row["lcs_sans"]
    if len(row["dns_names"]) == 0:
        return 0
    longest_substring = sorted(row["dns_names"], key=len, reverse=True)[0]
    return lcs / len(longest_substring)


def check_crl(row):
    try:
        row["crl_distribution_points"]
        return True
    except KeyError:
        return False


def build_features(data):
    # 5
    data["subject_has_country"] = data.apply(lambda row: (len(row['subject_country']) > 0), axis = 1)
    # 7
    data["subject_has_locality"] = data.apply(lambda row: (len(row["subject_locality"]) > 0), axis = 1)
    # 6
    data["subject_has_province"] = data.apply(lambda row: (len(row["subject_province"]) > 0), axis =1)
    # 9
    data["subject_has_common_name"] = data.apply(lambda row: (len(row["subject_common_name"]) > 0), axis = 1)
    # 10
    data["subject_only_cn"] = data.apply(lambda row: row["subject_has_common_name"] and (not row["subject_has_country"] and not row["subject_has_locality"]), axis = 1)
    # 11
    # data["num_subject_rdn"] = data.apply()
    # 12
    data["subject_len"] = data.apply(lambda row: len(row["subject_country"]) + len(row["subject_locality"]) + len(row["subject_common_name"]) + len(row["subject_organization"]), axis = 1)
    # 17
    data["num_san_dns_names"] = data.apply(lambda row:  len(row["dns_names"]), axis = 1)
    # 18
    data["unique_san_tlds"] = data.apply(lambda row: count_unique_tlds(row["dns_names"]), axis = 1)
    # 19
    data["pub_key_algorithm"] = data["key_algorithm_name"]
    # 20
    data["pub_key_algorithm"] = data.apply(lambda row: len(row["key_algorithm_name"]), axis = 1)
    # 24
    data["len_serial_number"] = data.apply(lambda row: len(row["serial_number"]), axis = 1)
    # 26
    data["len_issuer_dn"] = data.apply(lambda row: len(row["issuer_dn"]), axis = 1)
    # 27
    data["issuer_has_common_name"] = data.apply(lambda row: (len(row["issuer_common_name"]) > 0), axis = 1)
    # 28
    data["subject_is_empty"] = data.apply(lambda row: (len(row["subject_country"]) + len(row["subject_locality"]) + len(row["subject_common_name"]) + len(row["subject_organization"])) == 0, axis = 1)

    # 31
    # data["valid_timestamps"] = data.apply(lambda row: row["not_before"] > row["not_after"], axis = 1)
    # 32
    data["lcs_sans"] = data.apply(lambda row: len(find_lcs(row["dns_names"])), axis = 1)
    # 33
    data["lcs_sans_normed"] = data.apply(lambda row: find_longest_substring(row), axis = 1)
    # 16
    data["crl_dist_point_present"] = data.apply(lambda row: check_crl(row), axis = 1)
    # return data


MY_SUSPICIOUS_KEYWORDS =['pfs',
 'cfi',
 'flare',
 'eth',
 'aragon',
 'r2',
 'domain',
 'crazy',
 'beat',
 'worker',
 'new',
 'express',
 'adobe',
 'ba',
 'storage',
 'fy',
 'nft',
 'page',
 'wave',
 'webcindario',
 'wix',
 'square',
 'best',
 'practice',
 'usps',
 'start',
 'tinyurl',
 'blogspot',
 'portfolio',
 'help',
 'form',
 'code',
 'bit',
 'flow',
 'weebl',
 'login',
 'keep',
 'url',
 'gateway',
 'baf',
 'al',
 'ver',
 'office',
 'id',
 'cel',
 'ap',
 'mardo',
 'box']



SUSPICIOUS_KEYWORDS = [
    "activity",
    "alert",
    "purchase",
    "office",
    "online",
    "recover",
    "authentication",
    "safe",
    "authorize",
    "secure",
    "bill",
    "client",
    "support",
    "unlock",
    "wallet",
    "form",
    "log-in",
    "live",
    "manage",
    "veriﬁcation",
    "webscr",
    "authenticate",
    "credential",
    "security",
    "service",
    "transaction",
    "update",
    "account",
    "login",
    "password",
    "signin",
    "sign-in",
    "verify",
    "invoice",
    "conﬁrm",
    "customer",
    "appleid",
    "outlook",
    "icloud",
    "office365",
    "iforgot",
    "microsoft",
    "itunes",
    "windows",
    "apple",
    "protonmail",
    "localbitcoin",
    "bitstamp",
    "bittrex",
    "google",
    "outlook",
    "yahoo",
    "yandex",
    "blockchain",
    "bitﬂyer",
    "coinbase",
    "hitbtc",
    "lakebtc",
    "bitﬁnex",
    "bitconnect",
    "coinsbank",
    "tutanota",
    "hotmail",
    "gmail",
    "facebook",
    "moneygram",
    "tumblr",
    "westernunion",
    "reddit",
    "bankofamerica",
    "aliexpress",
    "youtube",
    "wellsfargo",
    "paypal",
    "twitter",
    "linkedin",
    "citigroup",
    "instagram",
    "santander",
    "ﬂickr",
    "morganstanley",
    "whatsapp",
    "barclays",
    "hsbc",
    "scottrade",
    "ameritrade",
    "merilledge",
    "bank",
    "overstock",
    "aliexpress",
    "leboncoin",
    "amazon",
    "skype",
    "github",
    "netflix"
]

# Sótt 24th december https://www.spamhaus.org/statistics/tlds/
SUSPICIOUS_TLDs = [
    ".cn",
    ".ml",
    ".ga",
    ".live",
    ".gq",
    ".degree",
    ".top",
    ".cf",
    ".men",
    ".market",
    # frá cybercrime information center 2020
    ".tk",
    ".buzz",
    ".xyz",
    ".top",
    ".ga",
    ".info",
    ".cf",
    ".gq",
    ".icu",
    ".wang",
    ".net",
    ".online",
    ".host",
    ".org",
    ".us",
    # frá https://interisle.net/PhishingLandscape2022.pdf yearly TLD phishing score
    ".support",
    ".bar",
    ".shop",
    ".work",
    ".casa",
    ".finance",
    ".sbs",
    ".fyi",
]


def read_iana_tlds(file_path):
    lines_list = []
    with open(file_path, 'r') as file:
        for line in file:
            lines_list.append(line.strip())
    return lines_list


IANA_TLDs = [string.lower() for string in read_iana_tlds("tlds_iana.txt")]



def shannon_entropy(data):
    probabilities = [float(data.count(c)) / len(data) for c in set(data)]
    entropy = - sum(p * math.log(p) / math.log(2.0) for p in probabilities)
    return entropy


def is_ip_address(ip_str):
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


def is_international_domain(domain):
    try:
        decoded_domain = idna.decode(domain)
        return decoded_domain != domain
    except idna.IDNAError:
        return False


def digit_fraction(input_string):
    input_string = input_string.replace(".", "")
    digit_count = sum(1 for char in input_string if char.isdigit())
    return digit_count / len(input_string)


def vowel_fraction(input_string):
    vowels = 'aeiouyAEIOUY'  # Define the vowels you want to consider
    input_string = input_string.replace(".", "")
    vowel_count = sum(1 for char in input_string if char in vowels)
    return vowel_count / len(input_string)


def has_digit_subdomain(domain):
    parts = domain.split('.')
    for part in parts:
        if part.isdigit():
            return True
    return False


def mean_subdomain_length(domain):
    parts = domain.split('.')
    subdomains = parts[:-2]  # Exclude the TLD and second-level domain

    # Calculate the length of each subdomain
    subdomain_lengths = [len(sub) for sub in subdomains]

    if subdomain_lengths:  # Check if there are subdomains
        mean_length = sum(subdomain_lengths) / len(subdomain_lengths)
        return mean_length
    else:
        return 0


def has_single_char_subdomain(domain):
    parts = domain.split('.')
    subdomains = parts[:-2]  # Exclude the TLD and second-level domain

    for sub in subdomains:
        if len(sub) == 1:
            return True
    return False


def character_diversity(domain):
    unique_chars = set(domain.replace('.', ''))
    num_unique_chars = len(unique_chars)
    num_total_chars = len(domain.replace('.', ''))  # Exclude dots from counting

    if num_total_chars > 0:
        diversity_ratio = num_unique_chars / num_total_chars
        return diversity_ratio
    else:
        return 0


def has_wildcard_domain(sans):
    for domain in sans:
        if domain[0] == '*':
            return True
    return False


def is_wildcard_match(row):
    domain = row["domain"]
    wildcard_match = False
    exact_match = False
    for san in row["dns_names"]:
        if domain == san:
            exact_match = True
            continue
        elif san.startswith("*.") and domain.endswith(san[2:]):
            wildcard_match = True
    if exact_match == False and wildcard_match == True:
        return True
    else:
        return False


def find_tld_in_subdomains(domain):
    domain_notld = domain.rsplit(".", 1)[0]
    parts = domain_notld.split(".")
    for part in parts:
        if any(keyword == part for keyword in IANA_TLDs) == True:
            return True
    return False




def build_domain_features(data):
    # 59
    data["domain_len"] = data.apply(lambda row: len(row["domain"]), axis=1)
    # 61
    data["sus_keyword"] = data["domain"].apply(lambda x: any(keyword in x for keyword in MY_SUSPICIOUS_KEYWORDS))
    # 62
    data["sus_tld"] = data["domain"].apply(lambda x: any(keyword == "." + x.rsplit(".", 1)[1] for keyword in SUSPICIOUS_TLDs))
    # 63
    data["shannon_entropy"] = data["domain"].apply(shannon_entropy)
    # 64
    data["num_dashes"] = data["domain"].apply(lambda x: x.count('-'))
    # 65
    data["num_tokens"] = data["domain"].apply(lambda x: x.replace("-", ".").count('.')+1)
    # 66/67
    data["num_parts"] = data["domain"].apply(lambda x: x.count('.')+1)
    # 69
    data["token_is_tld"] = data["domain"].apply(find_tld_in_subdomains)
    # 71
    data["frac_special_char"] = data["domain"].apply(lambda x: sum(1 for char in x.replace(".", "") if char in set("-")) / len(x.replace(".", "")))
    # 72
    data["is_ip"] = data["domain"].apply(is_ip_address)
    # 73
    data["is_international"] = data["domain"].apply(is_international_domain)
    # 74
    data["frac_vowels"] = data["domain"].apply(vowel_fraction)
    # 75
    data["frac_digits"] = data["domain"].apply(digit_fraction)
    # 77
    data["has_digit_only_subdomain"] = data["domain"].apply(has_digit_subdomain)
    # 78
    data["mean_len_subdomains"] = data["domain"].apply(mean_subdomain_length)
    # 80
    data["valid_tld_iana"] = data["domain"].apply(lambda x: any(keyword in "." + x.rsplit(".", 1)[1] for keyword in IANA_TLDs))
    # 81
    data["has_single_char_subdomain"] = data["domain"].apply(has_single_char_subdomain)
    # 82
    data["char_diversity"] = data["domain"].apply(character_diversity)
    # 83
    data["alphabet_size"] = data["domain"].apply(lambda x: len(set(x.replace(".", ""))))
    # new
    data["has_wildcard_san"] = data["dns_names"].apply(has_wildcard_domain)
    # new
    data["is_wildcard_match"] = data.apply(lambda row: is_wildcard_match(row), axis = 1)


def mean_san_domain_len(dns_names):
    if len(dns_names) == 0:
        return 0
    total_length = 0

    # calculate total length of all strings in the list
    for domain in dns_names:
        total_length += len(domain)

    # calculate average
    return total_length / len(dns_names)


def san_sus_keyword(dns_names):
    if len(dns_names) == 0:
        return 0
    num_match = 0
    for domain in dns_names:
        if any(keyword in domain for keyword in MY_SUSPICIOUS_KEYWORDS):
            num_match += 1
    return num_match/len(dns_names)


def san_sus_tld(dns_names):
    if len(dns_names) == 0:
        return 0
    num_match = 0
    for domain in dns_names:
        if len(domain.rsplit(".", 1)) > 1:

            if any(keyword == "." + domain.rsplit(".", 1)[1] for keyword in SUSPICIOUS_TLDs):
                num_match += 1
    return num_match/len(dns_names)


def san_shannon_entropy(dns_names):
    if len(dns_names) == 0:
        return 0
    shan_entropy_total = 0
    for domain in dns_names:
        shan_entropy_total += shannon_entropy(domain)
    return shan_entropy_total/len(dns_names)


def san_num_dashes(dns_names):
    if len(dns_names) == 0:
        return 0
    num_dash = 0
    for domain in dns_names:
        num_dash += domain.count('-')
    return num_dash/len(dns_names)


def san_num_tokens(dns_names):
    if len(dns_names) == 0:
        return 0
    num_tokens = 0
    for domain in dns_names:
        num_tokens += domain.replace("-", ".").count('.')+1
    return num_tokens/len(dns_names)


def san_num_parts(dns_names):
    if len(dns_names) == 0:
        return 0
    num_parts = 0
    for domain in dns_names:
        num_parts += domain.count('.')+1
    return num_parts/len(dns_names)


def san_token_is_tld(dns_names):
    if len(dns_names) == 0:
        return 0
    num_match = 0
    for domain in dns_names:
        if find_tld_in_subdomains(domain):
            num_match += 1
    return num_match / len(dns_names)


def san_frac_special_char(dns_names):
    num_specialchar = 0
    total_len = 0
    for domain in dns_names:
        num_specialchar += sum(1 for char in domain.replace(".", "") if char in set("-"))
        total_len += len(domain.replace(".", ""))

    if total_len == 0:
        return 0
    return num_specialchar/total_len


def san_is_ip(dns_names):
    if len(dns_names) == 0:
        return 0
    num_match = 0
    for domain in dns_names:
        if is_ip_address(domain):
            num_match += 1
    return num_match / len(dns_names)


def san_is_international(dns_names):
    if len(dns_names) == 0:
        return 0
    num_match = 0
    for domain in dns_names:
        if is_international_domain(domain):
            num_match += 1
    return num_match / len(dns_names)


def san_frac_vowels(dns_names):
    joined = "".join(dns_names)
    return vowel_fraction(joined)


def san_frac_digits(dns_names):
    joined = "".join(dns_names)
    return digit_fraction(joined)


def san_has_digit_only_subdomain(dns_names):
    if len(dns_names) == 0:
        return 0
    num_match = 0
    for domain in dns_names:
        if has_digit_subdomain(domain):
            num_match += 1
    return num_match / len(dns_names)


def san_mean_len_subdomains(dns_names):
    if len(dns_names) == 0:
        return 0
    means = 0
    for domain in dns_names:
        means += mean_subdomain_length(domain)
    return means / len(dns_names)


def san_valid_tld_iana(dns_names):
    if len(dns_names) == 0:
        return 0
    num_match = 0
    for domain in dns_names:
        if len(domain.rsplit(".", 1)) > 1:

            if any(keyword in "." + domain.rsplit(".", 1)[1] for keyword in IANA_TLDs):
                num_match += 1
    return num_match / len(dns_names)


def san_has_single_char_subdomain(dns_names):
    if len(dns_names) == 0:
        return 0
    num_match = 0
    for domain in dns_names:
        if has_single_char_subdomain(domain):
            num_match += 1
    return num_match / len(dns_names)


def build_san_domain_features(data):
    # 59
    data["mean_san_domain_len"] = data.dns_names.apply(mean_san_domain_len)
    # 61
    data["san_sus_keyword"] = data["dns_names"].apply(san_sus_keyword)
    # 62
    data["san_sus_tld"] = data["dns_names"].apply(san_sus_tld)
    # 63
    data["san_shannon_entropy"] = data["dns_names"].apply(san_shannon_entropy)
    # 64
    data["san_num_dashes"] = data["dns_names"].apply(san_num_dashes)
    # 65
    data["san_num_tokens"] = data["dns_names"].apply(san_num_tokens)
    # 66/67
    data["san_num_parts"] = data["dns_names"].apply(san_num_parts)
    # 69
    data["san_token_is_tld"] = data["dns_names"].apply(san_token_is_tld)
    # 71
    data["san_frac_special_char"] = data["dns_names"].apply(san_frac_special_char)
    # 72
    data["san_is_ip"] = data["dns_names"].apply(san_is_ip)
    # 73
    data["san_is_international"] = data["dns_names"].apply(san_is_international)
    # 74
    data["san_frac_vowels"] = data["dns_names"].apply(san_frac_vowels)
    # 75
    data["san_frac_digits"] = data["dns_names"].apply(san_frac_digits)
    # 77
    data["san_has_digit_only_subdomain"] = data["dns_names"].apply(san_has_digit_only_subdomain)
    # 78
    data["san_mean_len_subdomains"] = data["dns_names"].apply(mean_subdomain_length)
    # 80
    data["san_valid_tld_iana"] = data["dns_names"].apply(san_valid_tld_iana)
    # 81
    data["san_has_single_char_subdomain"] = data["dns_names"].apply(san_has_single_char_subdomain)
    # 82
    data["san_char_diversity"] = data["dns_names"].apply(lambda x: character_diversity("".join(x)))
    # 83
    data["san_alphabet_size"] = data["dns_names"].apply(lambda x: len(set("".join(x).replace(".", ""))))





def save_phish_tranco_sample(df):
    phish = df[df["phish"] == True]
    tranco = df[df["tranco"] == True]
    tranco_sample = tranco.sample(n=20_000)
    phish.to_pickle("phishDf2.pkl")
    tranco_sample.to_pickle("trancoSampleDf2.pkl")


def get_joined_df(num_tranco_samples):
    phish = pd.read_pickle("phishDf2.pkl")
    tranco = pd.read_pickle("trancoSampleDf2.pkl")
    return phish.append(tranco.sample(n=num_tranco_samples))


def save_features():
    df_final = get_joined_df(10_000)
    print(df_final.shape)
    build_features(df_final)
    print(df_final.shape)
    df_final.to_pickle("features2.pkl")


###########################
# allCerts2.pkl er það sem var processað í parseCertsToDf.py, phish og tranco er víxlað
# allCertsCleanedCorrect.pkl er sama nema búið að leiðrétta phish og tranco
# phishDf.pkl trancoSampleDf.pkl er búið til úr allCertsCleanedCorrect.pkl til þess að þurfa ekki að feature extracta á öllum gögnunum
# allCertsCorrWithIssuerOrg.pkl er með issuer organization annars einsog allCertsCleanedCorrect.pkl
###########################

###########################
# fyrst run-a parseCertsToDf.py, convertar öllu í df með því að flatten-a json structure-inn
# næst þarf að víxla phish og tranco ef allCerts2.pkl er notað
# bæta við issuer organization því það er ekki gert í parseCertsToDf.py Todo: bæta því við ef það á að run-a aftur DONE
# næst extracta þær rows sem við viljum, gera sampling, fækka repeated rows
# búa til features
###########################

def extract_issuer_org(text):
    if text is None or len(text) == 0:
        return ""
    split_text = text.split(", ")
    for part in split_text:
        if part.startswith("O="):
            return part.split("O=")[1]


def save_df_with_issuer_org():
    df = pd.read_pickle("allCertsCleanedCorrect.pkl")

    df["issuer_org"] = df.apply(lambda row: extract_issuer_org(row["issuer_dn"]), axis=1)
    df.to_pickle("allCertsCorrWithIssuerOrg.pkl")


def filter_tranco_certs(df_full):
    df_tranco_filt = df_full[(df_full["tranco"] == True) & (~df_full["subject_common_name"].isin(["imperva.com", "example.com", "synology.com", "kleinisd.net"]))]
    df_tranco_filt.to_pickle("trancoFiltered.pkl")




def balance_dataset(cert_df):
    common_name_counts = cert_df['subject_common_name'].value_counts().to_dict()
    count_of_counts = cert_df["subject_common_name"].value_counts().value_counts()
    cut_point = np.percentile(count_of_counts, 90)
    low_bound = np.percentile(count_of_counts, 75)

    new_df = cert_df.copy()
    for common_name in common_name_counts.keys():
        count = common_name_counts[common_name]
        if count > cut_point:
            sampling_num = random.randint(math.floor(low_bound), math.floor(cut_point))
            new_df.drop(new_df[new_df["subject_common_name"] == common_name].index, inplace=True)
            df_to_append = cert_df[cert_df["subject_common_name"] == common_name].sample(n=sampling_num)
            new_df = new_df.append(df_to_append)
    return new_df


blocklist = clean_block_list()["fullDomain"]
whitelist = top_tranco()["domain"]



def check_domains(domain_list, blocklist, whitelist, filt_phish, filt_tranco):
    blocklist_matches = []#{'Matches': []}
    whitelist_matches = []#{'Matches': []}

    domain_series = pd.Series(domain_list)
    # if filt_phish(domain_list):
    for domain in domain_list:
        if filt_phish([domain]):
            matches = blocklist[blocklist == domain].tolist()
            if len(matches) > 0:
                blocklist_matches.extend(matches)
            #blocklist_matches["Matches"].extend(matches)
            if len(blocklist_matches) == 0:
                wildcard_pattern = domain.replace(".", r"\.").replace("*", r"[^.]*")
                matches = blocklist[blocklist.str.match(f"^{wildcard_pattern}$")].tolist()
                if len(matches) > 0:
                    blocklist_matches.extend(matches)

        if filt_tranco([domain]):
            # for domain in domain_list:
            matches = whitelist[whitelist == domain].tolist()
            if len(matches) > 0:
                whitelist_matches.extend(matches)
            # whitelist_matches["Matches"].extend(matches)
            if len(whitelist_matches) == 0:
                # for domain in domain_list:
                wildcard_pattern = domain.replace(".", r"\.").replace("*", r"[^.]*")
                matches = whitelist[whitelist.str.match(f"^{wildcard_pattern}$")].tolist()
                if len(matches) > 0:
                    whitelist_matches.extend(matches)

    return blocklist_matches, whitelist_matches


def create_features_from_df():
    # df = pd.read_pickle("certPrufa.pkl")
    df = pd.read_pickle("filteredWithDomainMatchNewLabel.pkl")

    df.reset_index(drop=True, inplace=True)
    df.drop_duplicates(subset=["serial_number"], inplace=True)

    df_filt=df
    print("Phish shape: " + str(df_filt.shape))
    phish_final = df_filt[df_filt["phish"] == True]
    tranco_final = df_filt[df_filt["phish"] == False].sample(len(phish_final))
    joined_final = phish_final.append(tranco_final)
    build_features(joined_final)
    # joined_final.to_pickle("filteredWithDomainMatchNewLabel.pkl")
    joined_final["not_before_date"] = joined_final["not_before"].apply(datetime.datetime.utcfromtimestamp)
    joined_final["not_after_date"] = joined_final["not_after"].apply(datetime.datetime.utcfromtimestamp)
    joined_final["domain"] = joined_final.apply(lambda row: row["phish_matches"] + row["tranco_matches"], axis=1)
    joined_final["domain"] = joined_final.apply(lambda row: row["domain"][0], axis=1)
    print(joined_final.shape)
    joined_final.to_pickle("featuresWithDomainMatchNewLabel.pkl")
    # joined_final.to_pickle("featuresBalancedCertPrufaDomainMatch.pkl")


def create_domain_features():
    # df = pd.read_pickle("featuresWithDomainMatchNewLabel.pkl")
    df = pd.read_pickle("featuresBalancedCertPrufaDomainMatch.pkl")
    build_domain_features(df)
    # df.to_pickle("featuresCertAndDomainNewLabel.pkl")
    df.to_pickle("featuresBalancedCertPrufaDomainMatch.pkl")


def label_phish(lst):
    if len(lst) > 0:
        return 1
    else:
        return 0


def add_domain_matches_and_filter():
    start = time.time()
    df = pd.read_pickle("filteredCertPrufa.pkl")
    # df = pd.read_pickle("balancedCertPrufa.pkl")

    # df = pd.read_pickle("noTrancoPhishMatch.pkl")
    # df = df.sample(n=10, random_state=42)
    print(df.shape)
    filt_phish = Filter(create_phish_set())
    filt_tranco = Filter(create_tranco_set())
    df[['phish_matches', 'tranco_matches']] = df['names'].apply(
        lambda x: pd.Series(check_domains(x, blocklist, whitelist, filt_phish, filt_tranco),
                            index=['phish_matches', 'tranco_matches'])
    )
    print(df.columns)
    print(f"seconds: {time.time() - start}")
    # df.to_pickle("featuresCertPrufaDomainMatch.pkl")
    df.reset_index(drop=True, inplace=True)
    df['phish_matches'] = df['phish_matches'].apply(lambda x: list(set(x)))
    df['tranco_matches'] = df['tranco_matches'].apply(lambda x: list(set(x)))
    filtered_cond = df[
        (df['phish_matches'].apply(lambda x: len(x) > 1))
        | (df['tranco_matches'].apply(lambda x: len(x) > 1))
        | ((df['tranco_matches'].apply(lambda x: len(x) == 0)) & (df['phish_matches'].apply(lambda x: len(x) == 0)))
        | ((df['tranco_matches'].apply(lambda x: len(x) == 1)) & (df['phish_matches'].apply(lambda x: len(x) == 1)))]
    filtered_df = df.drop(filtered_cond.index)
    filtered_df['phish'] = filtered_df['phish_matches'].apply(lambda x: label_phish(x))
    filtered_df['tranco'] = filtered_df['tranco_matches'].apply(lambda x: label_phish(x))
    # filtered_df.to_pickle("featuresCertPrufaDomainMatch.pkl")
    print(filtered_df.shape)
    filtered_df.to_pickle("filteredWithDomainMatchNewLabel.pkl")
    # filtered_df.to_pickle("balancedCertPrufaDomainMatch.pkl")



if __name__ == '__main__':
    df = pd.read_pickle("featuresCertAndDomainNewLabel.pkl")
    build_san_domain_features(df)

