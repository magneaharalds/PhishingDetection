import pandas as pd
import textwrap


def read_ieee_results():
    return pd.read_csv(filepath_or_buffer='/home/mha/thesis/ieee.csv', sep=',')


def read_scopus_results():
    return pd.read_csv(filepath_or_buffer='/home/mha/thesis/scopus.csv', sep=',')


def read_acm_results():
    tmp = pd.concat(
        [pd.read_csv(filepath_or_buffer='/home/mha/thesis/acm1.csv', sep=','),
         pd.read_csv(filepath_or_buffer='/home/mha/thesis/acm2.csv', sep=',')]
        , ignore_index=True)
    return tmp


def read_wos_results():
    return pd.read_excel('/home/mha/thesis/wos.xls', index_col=0, header=0, sheet_name=0)


ieee_full = read_ieee_results()
scopus_full = read_scopus_results()
wos_full = read_wos_results()
acm_full = read_acm_results()

ieeeColumnNames = ['Document Title', 'Authors', 'Publication Title', 'Publication Year', 'DOI', 'Abstract']
scopusColumnNames = ['Title', 'Authors', 'Source title', 'Year', 'DOI', 'Abstract']
wosColumnNames = ['Article Title', 'Authors', 'Source Title', 'Publication Year', 'DOI', 'Abstract']
acmColumnNames = ['Title', 'Authors', 'Proceedings title', 'Publication year', 'DOI', 'Abstract']

ieeeMapping = {'Document Title' : 'Title', 'Authors' : 'Authors', 'Publication Title' : 'Source title', 'Publication Year' : 'Year', 'DOI' : 'DOI', 'Abstract' : 'Abstract'}
wosMapping = {'Article Title': 'Title', 'Authors': 'Authors', 'Source Title': 'Source title', 'Publication Year': 'Year', 'DOI' : 'DOI', 'Abstract' : 'Abstract'}
acmMapping = {'Title' : 'Title', 'Authors' : 'Authors', 'Proceedings title' : 'Source title', 'Publication year' : 'Year', 'DOI' : 'DOI', 'Abstract' : 'Abstract'}


def print_columns():
    print("IEEE full doc columns")
    print(ieee_full.columns)
    print("Scopus full doc columns")
    print(scopus_full.columns)
    print("WOS full doc columns")
    print(wos_full.columns)
    print("ACM full doc columns")
    print(acm_full.columns)




def update_column_names():
    ieee = ieee_full[ieeeColumnNames].copy()
    scopus = scopus_full[scopusColumnNames].copy()
    wos = wos_full[wosColumnNames].copy()
    acm = acm_full[acmColumnNames].copy()

    ieee.rename(columns=ieeeMapping, inplace=True)
    wos.rename(columns=wosMapping, inplace=True)
    acm.rename(columns=acmMapping, inplace=True)

    ieee['Title'] = ieee['Title'].apply(str.lower)
    scopus['Title'] = scopus['Title'].apply(str.lower)
    wos['Title'] = wos['Title'].apply(str.lower)
    acm['Title'] = acm['Title'].apply(str.lower)

    return ieee, scopus, wos, acm


def print_abstract(df):
    for i in range(len(df)):
        print("-----------------------------------------------------------------------")
        print(df.loc[i, 'Title'])
        print(df.loc[i, 'Year'])
        print("-------------------")
        print(i)
        print(textwrap.fill(df.loc[i, 'Abstract'], 80))


def generate_final(print_count):
    ieee, scopus, wos, acm = update_column_names()
    df_all = pd.concat([ieee, scopus, wos, acm], ignore_index=True)

    df_no_dupl = df_all.drop_duplicates(subset=['DOI'], keep='first')
    df_no_dupl = df_no_dupl.drop_duplicates(subset=['Title'], keep='first')
    df_final = df_no_dupl.dropna(subset=['Abstract'])
    df_final.reset_index(drop=True, inplace=True)
    if print_count:
        print("ieee " + str(ieee.shape[0]))
        print("acm " + str(acm.shape[0]))
        print("wos " + str(wos.shape[0]))
        print("scopus " + str(scopus.shape[0]))
        print("number of papers with duplicates: " + str(df_all.shape[0]))
        print("number of papers without duplicates: " + str(df_no_dupl.shape[0]))
        print("duplicates removed = " + str(df_all.shape[0] - df_no_dupl.shape[0]))
        keep_titles = pd.read_csv(filepath_or_buffer='/home/mha/PycharmProjects/thesis/titles_to_keep.csv', sep=',',
                                  header=0)
        removed_no_abstract = df_no_dupl.shape[0] - df_final.shape[0]
        print("number of papers removed after abstract screening: " + str(df_final.shape[0] - keep_titles[keep_titles['keep'] == True].shape[0] + removed_no_abstract))
        print("number of papers after read through of abstract: " + str(keep_titles[keep_titles['keep'] == True].shape[0]))
    return df_final



if __name__ == '__main__':
    # withAcm = pd.read_csv(filepath_or_buffer='/home/mha/PycharmProjects/thesis/articles_with_ACM.csv', sep=',')
    # noAcm = pd.read_csv(filepath_or_buffer='/home/mha/PycharmProjects/thesis/articles_first_save.csv', sep=',')
    # merged = withAcm.merge(noAcm, how='outer', indicator=True)
    # onlyACM = merged.loc[merged['_merge'] == 'left_only']
    # onlyACM.reset_index(drop=True, inplace=True)
    # onlyACM = onlyACM.drop(columns = ['Unnamed: 0', '_merge'])
    # onlyACM = onlyACM.dropna(subset=['Abstract'])
    # onlyACM.reset_index(drop=True, inplace=True)
    # print_abstract(onlyACM)

    # onlyACM.to_csv('onlyAcm.csv', index=False)
    # final = generate_final(True)
    # final.to_csv('articles_with_ACM.csv')
    # print_abstract(df_final)
    df = generate_final(True)
    # print_abstract(df)
    keep_titles = pd.read_csv(filepath_or_buffer='/home/mha/PycharmProjects/thesis/titles_to_keep.csv', sep=',',
                              header=0)
    kept = df[df['Title'].isin(keep_titles[keep_titles['keep'] == True]['Title'])]
    with pd.option_context('display.max_rows', None, 'display.max_columns', None):  # more options can be specified also
        print(kept['DOI'])
    # kept.reset_index(drop=True, inplace=True)
    # for i in range(len(kept)):
    #     print(kept[i]['DOI'])
