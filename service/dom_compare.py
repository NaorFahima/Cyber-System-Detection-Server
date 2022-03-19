import requests
from utils.dom_operation import get_classes ,get_tags, jaccard_similarity
from difflib import SequenceMatcher
from io import StringIO
from lxml.html import parse


def similarity(document_1: str, document_2: str, k:float = 0.5)-> float:
    return k * structural_similarity(document_1, document_2) + (1 - k) * style_similarity(document_1, document_2)

def structural_similarity(document_1:str, document_2:str) -> float :
    """
    Computes the structural similarity between two DOM Trees
    :param document_1: html string
    :param document_2: html string
    :return: int
    """
    try:
        document_1 = parse(StringIO(document_1))
        document_2 = parse(StringIO(document_2))
    except Exception as e:
        print(e)
        return 0

    tags1 = get_tags(document_1)
    tags2 = get_tags(document_2)
    diff = SequenceMatcher()
    diff.set_seq1(tags1)
    diff.set_seq2(tags2)

    return diff.ratio()

def style_similarity(page1:str, page2:str) -> float:
    """
    Computes CSS style Similarity between two DOM trees

    A = classes(Document_1)
    B = classes(Document_2)

    style_similarity = |A & B| / (|A| + |B| - |A & B|)

    :param page1: html of the page1
    :param page2: html of the page2
    :return: Number between 0 and 1. If the number is next to 1 the page are really similar.
    """
    classes_page1 = get_classes(page1)
    classes_page2 = get_classes(page2)
    return jaccard_similarity(classes_page1, classes_page2)


def dom_compare(url1:str,url2:str) -> dict:
    print(f'{url1} ==== {url2}')
    try:
        html1 = requests.get(url1).text
        html2 = requests.get(url2).text
        return {'style': style_similarity(html1,html2) , 'structural' : structural_similarity(html1,html2) , 'similarity': similarity(html1,html2)}
    except Exception as e:
        print(e)
        return {'style': 0, 'structural' :0 , 'similarity':0}
    