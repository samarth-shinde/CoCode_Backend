import html
import requests
from bs4 import BeautifulSoup


# def scrape(url):
#     URL = str(url)
#     r = requests.get(URL)
#     print(r.text)
#     soup = BeautifulSoup(r.content)
#     print("soup created")
#     # If this line causes an error, run 'pip install html5lib' or install html5lib
#     table = soup.findAll("div", attrs={"class": "text"})
#     # print("table", table[4])
#     article = ""
#     for i in table[4].findAll("p"):
#         article += i.text
#         # print(i.text)
#         print(soup.prettify())
#     return article


def scrape(url):
    URL = str(url)
    try:
        r = requests.get(URL)
        r.raise_for_status()  # Check for any request errors

        soup = BeautifulSoup(r.content, "html.parser")
        div_text = soup.find("div", class_="text")

        if div_text is not None:
            article = ""
            for paragraph in div_text.find_all("p"):
                article += paragraph.text
            return article
        else:
            print("The <div class='text'> element was not found on the page.")
            return ""

    except requests.exceptions.RequestException as e:
        print("An error occurred:", e)
        return ""
