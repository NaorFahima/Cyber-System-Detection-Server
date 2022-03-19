from parsel import Selector
from lxml.html import HtmlElement , HtmlComment


def get_classes(html:str) -> set:
    doc = Selector(text=html)
    classes = set(doc.xpath('//*[@class]/@class').extract())
    result = set()
    for cls in classes:
        for _cls in cls.split():
            result.add(_cls)
    return result

def get_tags(doc:object) -> list:
    '''
    Get tags from a DOM tree

    :param doc: lxml parsed object
    :return:
    '''
    tags = []

    for el in doc.getroot().iter():
        if isinstance(el,HtmlElement):
            tags.append(el.tag)
        elif isinstance(el,HtmlComment):
            tags.append('comment')
        else:
            raise ValueError('Don\'t know what to do with element: {}'.format(el))

    return tags

def jaccard_similarity(set1:set, set2:set) -> float:
    set1 = set(set1)
    set2 = set(set2)
    intersection = len(set1 & set2)

    if len(set1) == 0 and len(set2) == 0:
        return 1.0

    denominator = len(set1) + len(set2) - intersection
    return intersection / max(denominator, 0.000001)