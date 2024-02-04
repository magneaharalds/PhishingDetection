import pandas as pd

feature_names = [
    "validation_level",
    "apple_ever_valid",
    "nss_ever_valid",
    "microsoft_ever_valid",
    "subject_has_country",
    "subject_has_province",
    "subject_has_locality",
    "subject_has_common_name",
    "subject_only_cn",
    #"num_subject_rdn",
    "subject_len",
    "length_seconds",
    #"notice_numbers", # vantar hjá öllum certs
    "ocsp_urls",
    "crl_dist_point_present",
    "num_san_dns_names",
    #"unique_tlds",
    "pub_key_algorithm",
    #"len_pub_key_algorithm", # vantar alveg held ég
    "version",
    "signature_algorithm_name",
    "len_serial_number",
    "len_issuer_dn",
    "issuer_has_common_name",
    #"issuer_org",
    "subject_is_empty",
    #"has_any_extensions", # vantar
    #"serial_number_conforms", # vantar
    #"valid_timestamps", # all rows have a valid timestamp
    "lcs_sans",
    "lcs_sans_normed",
    #"sans_cdn", # hvernig á að reikna þetta?
    # 35-36
    "authority_info_access",
    # 37-38
    "certificate_policies",
    # 39-40
    "basic_constraints",
    #"key_usage_present", # all rows have 1
    "key_usage_value",
    # 45-46
    # "extended_key_usage_present",
    # 49-50
    # "signed_certificate_timestamp",
    #47-48
    "authority_key_id",
    "phish"
]



def convert_bool_to_int(data):
    data["apple_ever_valid"] = data["apple_ever_valid"].astype(int)
    data["nss_ever_valid"] = data["nss_ever_valid"].astype(int)
    data["microsoft_ever_valid"] = data["microsoft_ever_valid"].astype(int)
    data["subject_has_country"] = data["subject_has_country"].astype(int)
    data["subject_has_province"] = data["subject_has_province"].astype(int)
    data["subject_has_locality"] = data["subject_has_locality"].astype(int)
    data["subject_has_common_name"] = data["subject_has_common_name"].astype(int)
    data["subject_only_cn"] = data["subject_only_cn"].astype(int)
    data["crl_dist_point_present"] = data["crl_dist_point_present"].astype(int)
    data["issuer_has_common_name"] = data["issuer_has_common_name"].astype(int)
    data["subject_is_empty"] = data["subject_is_empty"].astype(int)
    # data["valid_timestamps"] = data["valid_timestamps"].astype(int)
    data["authority_info_access"] = data["authority_info_access"].astype(int)
    data["certificate_policies"] = data["certificate_policies"].astype(int)
    data["basic_constraints"] = data["basic_constraints"].astype(int)
    # data["key_usage_present"] = data["key_usage_present"].astype(int)
    # data["extended_key_usage_present"] = data["extended_key_usage_present"].astype(int)
    # data["signed_certificate_timestamp"] = data["signed_certificate_timestamp"].astype(int)
    data["authority_key_id"] = data["authority_key_id"].astype(int)
    data["in_phish"] = data["in_phish"].astype(int)
    return data



def get_features_and_labels(with_dummies):
    df = pd.read_pickle("features.pkl")
    df.drop_duplicates(subset=["serial_number"], inplace=True)
    df["crl_dist_point_present"] = df.apply(lambda row: (len(row["crl_distribution_points"]) > 0), axis=1)

    df_features = df[feature_names]

    if with_dummies:
        df_features = pd.get_dummies(df_features,
                                    prefix=["validation_level", "pub_key_algorithm", "signature_algorithm_name"],
                                    columns=["validation_level", "pub_key_algorithm", "signature_algorithm_name"])
    df_features.reset_index(drop=True, inplace=True)

    df_features = convert_bool_to_int(df_features)
    df_features.dropna(axis=0, inplace=True)
    features = df_features.drop(columns=["phish"], axis=1)
    labels = df_features["phish"]
    return features, labels




def clean_block_list(filter_popular_sites: bool):
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
    phish = phish.drop(phish[phish['fullDomain'].str.endswith('googleapis.com')].index)
    if filter_popular_sites:
        # these were not included in filtering from BigQuery
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



def create_phish_set(filter_popular_sites: bool):
    block_list = clean_block_list()
    s = block_list['fullDomain'].unique()

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



