import json
import os
import ssl
import sys
from collections import OrderedDict
from pprint import pprint as pp
import featureExtraction
import numpy as np
import pandas as pd
from sklearn.neighbors import KNeighborsClassifier
from mlflow import MlflowClient
import seaborn
import matplotlib.pyplot as plt
from mlflow.models import infer_signature
# from utils import convert_bool_to_int
import tensorflow as tf
import pickle
from sklearn.svm import SVC
import tensorflow as tf
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.models import Sequential
import utils
from sklearn.model_selection import cross_val_score, cross_validate
import seaborn as sns
from wordsegment import load, segment
import joblib
import time


import pandas as pd

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



feature_names_domain = [
    "validation_level",
    "apple_ever_valid",
    "nss_ever_valid",
    "microsoft_ever_valid",
    "subject_has_country",
    "subject_has_province",
    "subject_has_locality",
    "subject_has_common_name", # hefur engin áhrif í rf
    "subject_only_cn",
    # "num_subject_rdn",
    "subject_len", # hefur engin áhrif í rf
    "length_seconds",
    # "notice_numbers", # vantar hjá öllum certs
    "ocsp_urls", # hefur engin áhrif í rf
    "crl_dist_point_present",
    "num_san_dns_names",
    # "unique_tlds",
    "pub_key_algorithm",
    # "len_pub_key_algorithm", # vantar alveg held ég
    "version", # hefur engin áhrif í rf
    "signature_algorithm_name",
    "len_serial_number",
    "len_issuer_dn",
    "issuer_has_common_name", # hefur engin áhrif í rf
    #"issuer_org",
    "subject_is_empty", # hefur engin áhrif í rf
    #"has_any_extensions", # vantar
    #"serial_number_conforms", # vantar
    #"valid_timestamps", # all rows have a valid timestamp
    "lcs_sans",
    "lcs_sans_normed",
    #"sans_cdn", # hvernig á að reikna þetta?
    # 35-36
    "authority_info_access",# hefur engin áhrif í rf
    # 37-38
    "certificate_policies",# hefur engin áhrif í rf
    # 39-40
    "basic_constraints", # hefur engin áhrif í rf
    #"key_usage_present", # all rows have 1
    "key_usage_value",
    # 45-46
    # "extended_key_usage_present",
    # 49-50
    # "signed_certificate_timestamp",
    #47-48
    "authority_key_id",# hefur engin áhrif í rf
    "domain_len",
    "new_sus_keyword",
    "sus_tld",
    "shannon_entropy",
    "num_dashes",
    "num_tokens",
    "num_parts",
    "token_is_tld_new",
    "frac_special_char",
    # "is_ip",  # no domain is strictly an ip
    "is_international", # hefur engin áhrif í rf
    "frac_vowels",
    "frac_digits",
    "has_digit_only_subdomain", # hefur engin áhrif í rf
    "mean_len_subdomains",
    # "valid_tld_iana", # every line has valid iana tld
    "has_single_char_subdomain",
    "char_diversity",
    "alphabet_size",
    "is_wildcard_match",
    "has_wildcard_san",
    # "domain_pred",
    # "phish"
]


rf_features = ['apple_ever_valid', 'nss_ever_valid', 'microsoft_ever_valid',
       'subject_has_country', 'subject_has_province', 'subject_has_locality',
       'subject_has_common_name', 'subject_only_cn', 'subject_len',
       'length_seconds', 'ocsp_urls', 'crl_dist_point_present',
       'num_san_dns_names', 'version', 'len_serial_number', 'len_issuer_dn',
       'issuer_has_common_name', 'subject_is_empty', 'lcs_sans',
       'lcs_sans_normed', 'authority_info_access', 'certificate_policies',
       'basic_constraints', 'key_usage_value', 'authority_key_id',
       'domain_len', 'new_sus_keyword', 'sus_tld', 'shannon_entropy',
       'num_dashes', 'num_tokens', 'num_parts', 'token_is_tld_new',
       'frac_special_char', 'is_international', 'frac_vowels', 'frac_digits',
       'has_digit_only_subdomain', 'mean_len_subdomains',
       'has_single_char_subdomain', 'char_diversity', 'alphabet_size',
       'is_wildcard_match', 'has_wildcard_san', 'lstm_feature_0',
       'lstm_feature_1', 'lstm_feature_2', 'lstm_feature_3', 'lstm_feature_4',
       'lstm_feature_5', 'lstm_feature_6', 'lstm_feature_7', 'lstm_feature_8',
       'lstm_feature_9', 'lstm_feature_10', 'lstm_feature_11',
       'lstm_feature_12', 'lstm_feature_13', 'lstm_feature_14',
       'lstm_feature_15', 'lstm_feature_16', 'lstm_feature_17',
       'lstm_feature_18', 'lstm_feature_19', 'lstm_feature_20',
       'lstm_feature_21', 'lstm_feature_22', 'lstm_feature_23',
       'lstm_feature_24', 'lstm_feature_25', 'lstm_feature_26',
       'lstm_feature_27', 'lstm_feature_28', 'lstm_feature_29',
       'lstm_feature_30', 'lstm_feature_31', 'validation_level_DV',
       'validation_level_EV', 'validation_level_OV',
       'validation_level_UNKNOWN', 'pub_key_algorithm_3',
       'pub_key_algorithm_5', 'signature_algorithm_name_ECDSA-SHA256',
       'signature_algorithm_name_ECDSA-SHA384',
       'signature_algorithm_name_SHA1-RSA',
       'signature_algorithm_name_SHA256-RSA',
       'signature_algorithm_name_SHA384-RSA',
       'signature_algorithm_name_SHA512-RSA']

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
    # data["in_phish"] = data["in_phish"].astype(int)
    return data



def len_greater_than_0(key, row):
    if row[key] is None or len(row[key]) == 0:
        return False
    else:
        return True


def return_value_if_present(key, row, value):
    try:
        row[key][value]
    except KeyError:
        return ""
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
    try:
        row[key][0]["user_notice"]
    except KeyError:
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
    elif key == "subject_alt_name":
        row_dict["dns_names"] = row["subject_alt_name"]["dns_names"]
    elif key == "subject_key_info":
        row_dict["key_algorithm_name"] = row[key]["key_algorithm"]["name"]
    elif key == "apple":
        row_dict["apple_ever_valid"] = row[key]["ever_valid"]
    elif key == "microsoft":
        row_dict["microsoft_ever_valid"] = row[key]["ever_valid"]
    elif key == "nss":
        row_dict["nss_ever_valid"] = row[key]["ever_valid"]
    elif key == "validity_period":
        row_dict["length_seconds"] = row[key]["length_seconds"]

    else:
        row_dict[key] = row[key]


def json_to_pickle(row, domain_name):
    df = pd.DataFrame(columns=column_names)
    build_row = dict.fromkeys(column_names)
    for key, value in row.items():
        key_switch(key, row, build_row)
    for key, value in row["parsed"].items():
        if key == "extensions":
            for keyInner, valueInner in row["parsed"]["extensions"].items():
                key_switch(keyInner, row["parsed"]["extensions"], build_row)
        else:
            key_switch(key, row["parsed"], build_row)
    for key, value in row["validation"].items():
        key_switch(key, row["validation"], build_row)


    df.loc[len(df)] = build_row

    featureExtraction.build_features(df)
    df["domain"] = domain_name
    featureExtraction.build_domain_features(df)
    return df





def predict(file_name, domain, tokenizer, max_len, trunc_type, padding_type, extract_layer_model):
    #################
    # Vector representation with LSTM model
    #################
    # max_len = 50
    # trunc_type = 'post'
    # padding_type = 'post'
    # with open('tokenizer.pickle', 'rb') as handle:
    #     tokenizer = pickle.load(handle)
    #
    # new_model = tf.keras.models.load_model('saved_model/my_model')
    #
    # extract_layer_model = tf.keras.Model(
    #     inputs=new_model.input,
    #     outputs=new_model.layers[-2].output
    # )

    ################################
    # Create "sentences" from domain names using word segmentation on each token
    ################################

    with open(file_name) as f:
        json_data = json.load(f)
    df = json_to_pickle(json_data, domain)

    sentences = []
    load()
    for domain in df.domain:
        parts = domain.split(".")
        sentence = ""
        for part in parts:
            segments = segment(part)
            bit = " ".join(segments)
            sentence = sentence + " " + bit
        sentences.append(sentence)
    df["domain_sent"] = sentences


    new_seq = tokenizer.texts_to_sequences(df["domain_sent"])
    padded = pad_sequences(new_seq,
                           maxlen=max_len,
                           padding=padding_type,
                           truncating=trunc_type)
    pred = extract_layer_model.predict(padded)
    df_preds = pd.DataFrame(pred, columns=[f'lstm_feature_{i}' for i in range(len(pred[0]))])

    ###################
    # Random forest prediction
    ###################

    df["new_sus_keyword"] = df["sus_keyword"]
    df["token_is_tld_new"] = df["token_is_tld"]

    df_features = df[feature_names_domain]
    df_features_merged = df_features.join(df_preds)
    df_features_merged = pd.get_dummies(df_features_merged,
                                        prefix=["validation_level", "pub_key_algorithm", "signature_algorithm_name"],
                                        columns=["validation_level", "pub_key_algorithm", "signature_algorithm_name"])

    missing_columns = set(rf_features) - set(df_features_merged.columns)
    for col in missing_columns:
        df_features_merged[col] = 0
    features = convert_bool_to_int(df_features_merged)
    features = features[rf_features]
    features.to_pickle("uspsFeatureCert.pkl")

    with open('scaler.pickle', 'rb') as handle:
        scaler = pickle.load(handle)

    feature_scaled = scaler.transform(features)

    rf = joblib.load('randomForest.joblib')
    rf_pred = rf.predict(feature_scaled)
    rf_prob = rf.predict_proba(feature_scaled)
    # if rf_pred[0] == 0:
    #     pred_class = "benign"
    # else:
    #     pred_class = "phish"

    return rf_prob
    # print(f"Predicted class " + pred_class)
    # print(f"Predicted phishin probability: {rf_prob}")




def main():
    max_len = 50
    trunc_type = 'post'
    padding_type = 'post'
    with open('tokenizer.pickle', 'rb') as handle:
        tokenizer = pickle.load(handle)

    new_model = tf.keras.models.load_model('saved_model/my_model')

    extract_layer_model = tf.keras.Model(
        inputs=new_model.input,
        outputs=new_model.layers[-2].output
    )
    start = time.time()
    rf_prob = predict('uspsCert.txt', "usps.com", tokenizer, max_len, trunc_type, padding_type, extract_layer_model)
    print(f"Predicted phishing probability for domain usps.com: {rf_prob}, prediction took {time.time() - start} seconds")

    start = time.time()
    rf_prob = predict('phishUsps.txt', "usps.proleus.com", tokenizer, max_len, trunc_type, padding_type, extract_layer_model)
    print(f"Predicted phishing probability for domain usps.proleus.com: {rf_prob}, prediction took {time.time() - start} seconds")

    start = time.time()
    rf_prob = predict('fedexCert.txt', "fedex.com", tokenizer, max_len, trunc_type, padding_type, extract_layer_model)
    print(f"Predicted phishing probability for domain fedex.com: {rf_prob}, prediction took {time.time() - start} seconds")

    start = time.time()
    rf_prob = predict('fedexPhish.txt', "saveformnow.com", tokenizer, max_len, trunc_type, padding_type, extract_layer_model)
    print(f"Predicted phishing probability for domain saveformnow.com: {rf_prob}, prediction took {time.time() - start} seconds")

    start = time.time()
    rf_prob = predict('dansktSkam.txt', "oevin.dk", tokenizer, max_len, trunc_type, padding_type,
                      extract_layer_model)
    print(f"Predicted phishing probability for domain oevin.dk: {rf_prob}, prediction took {time.time() - start} seconds")

    # with open('uspsCert.txt') as f:
    #     json_data = json.load(f)
    # df = json_to_pickle(json_data, "usps.com")
    # rf_prob = predict(df)
    #
    # print(f"Predicted phishing probability for domain usps.com: {rf_prob}")
    # with open('phishUsps.txt') as f:
    #     json_data = json.load(f)
    # otherDf = json_to_pickle(json_data, "usps.proleus.com")
    # rf_prob = predict(otherDf)
    # print(f"Predicted phishing probability for domain usps.proleus.com: {rf_prob}")
    # with open('fedexCert.txt') as f:
    #     json_data = json.load(f)
    # df = json_to_pickle(json_data, "fedex.com")
    # rf_prob = predict(df)
    # print(f"Predicted phishing probability for domain fedex.com: {rf_prob}")
    #
    # with open('fedexPhish.txt') as f:
    #     json_data = json.load(f)
    # otherDf = json_to_pickle(json_data, "saveformnow.com")
    # rf_prob = predict(otherDf)
    # print(f"Predicted phishing probability for domain saveformnow.com: {rf_prob}")
    #
    #
    # with open('dansktSkam.txt') as f:
    #     json_data = json.load(f)
    # otherDf = json_to_pickle(json_data, "oevin.dk")
    # rf_prob = predict(otherDf)
    # print(f"Predicted phishing probability for domain oevin.dk: {rf_prob}")


if __name__ == "__main__":
    main()
