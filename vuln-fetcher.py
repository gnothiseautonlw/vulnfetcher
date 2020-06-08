import re
import json
import time
import requests
import argparse
from bs4 import BeautifulSoup

class Formatting:
    """ Give formatting to text: bold, underline, ... and fg and bg colors

    Reset all formatting with Formatting.reset
    Give fg color with: Formatting.fgcolor.<colorname>
    Give bg color with: Formatting.bgcolor.<colorname>

    Usage:
        print(formatting.bgcolor.green, "SKk", formatting.fgcolor.red, "Amartya")"""

    reset = '\033[0m'
    bold = '\033[01m'
    disable = '\033[02m'
    underline = '\033[04m'
    reverse = '\033[07m'
    strike_through = '\033[09m'
    invisible = '\033[08m'

    class fgcolor:
        black = '\033[30m'
        blue = '\033[34m'
        green = '\033[32m'
        light_green = '\033[92m'
        light_grey = '\033[37m'
        dark_grey = '\033[90m'
        red = '\033[31m'
        orange = '\033[33m'
        purple = '\033[35m'
        cyan = '\033[36m'
        light_red = '\033[91m'
        yellow = '\033[93m'
        light_blue = '\033[94m'
        pink = '\033[95m'
        light_cyan = '\033[96m'

    class bgcolor:
        black = '\033[40m'
        red = '\033[41m'
        green = '\033[42m'
        orange = '\033[43m'
        blue = '\033[44m'
        purple = '\033[45m'
        cyan = '\033[46m'
        lightgrey = '\033[47m'


class Vulnfetcher:
    """A class to lookup (currently only a dpkg generated file 'dpkg -l > file') modules
    for known vulnerabilities"""

    def __init__(self, filename, parse=True, output=True, print_report=True):
        """When initializing the class, a path to a file is provided
        I do a line count on the file (This was to implement a progressbar, which isn't done yet)
        I then start processing the file"""
        self.db = {}
        self.db_sorted = {}
        self.db_search = {}
        self.db_module = {}
        self.db_result = {}
        self.db_results = {}
        self.db_result_detail = {}
        self.db_score = {}
        self.file_line_count = 0

        # Websites that count as an interesting find:
        self.trusted_sources = ["https://vulmon.com/", "https://www.exploit-db.com", "https://www.cvedetails.com",
                                "https://www.rapid7.com"]
        self.cve_details_url = "https://www.cvedetails.com/cve/"
        # get the n first search results
        self.get_top_n = 5

        self.version_complete_match_score_weight = 2
        self.cvedetails_summary = "cvedetailssummary"
        self.cvedetails_scores_and_types_id = "cvssscorestable"
        self.cvedetails_gained_access_th = "Gained Access"
        self.cvedetails_gained_access_admin_string = "Admin"
        # TODO There is also "th Vulnerability Type(s)	--> Gain privileges", example: https://www.cvedetails.com/cve/CVE-2011-3628/
        self.cvedetails_gained_access_score_weight = 3

        self.header_user_agent = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko'}
        # self.header_user_agent = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.61 Safari/537.36'}
        self.search_engine_delay = 5
        self.file_name = filename
        self.output_file = filename + ".vulnfetcher"
        self.count_lines_in_file()
        if parse:
            self.file_parse(filename)
        if output:
            self.store_output()
            self.store_report()
        if print_report:
            self.print_report()

    def count_lines_in_file(self):
        """Count the number of lines in the file"""
        with open(self.file_name) as f:
            for i, l in enumerate(f):
                pass
        self.file_line_count = i + 1

    def parse_dpkg(self, line):
        """Parse a dpkg file. For each line, get the module name and version"""
        module_version_mayor_minor = '???'
        module_version_complete = '???'

        line = line.rstrip("\n").strip()  # remove newline at the end of the read line

        try:
            # regex for module name
            module_name = re.search('(?<=ii  )(\S*)', line, flags=re.DOTALL).group(0).strip()
            # regex for Mayor - dot - minor.
            # Find a whitespaces, then select either
            #     numbers followed by dot, followed by one number
            #     numbers followed by ':', followed by numbers, followed by '.', followed by one number
            #     number followed by numbers
            # There are basically three versions-formats I've seen so far:
            #     'normal version numbers': 1.15.2 (here I would select only 1.1)
            #     and version numbers in the format: 1:1.15.2 (here I would select 1:1.1)
            #     all numbers: 20091524
            module_version_mayor_minor = re.search('(?<=\s)(\d*\.\d|\d*:\d*\.\d|\d\d*)', line, flags=re.DOTALL).group(
                0).strip()
            # taking the above 3 formats in mind, here I try to take the complete version number
            module_version_complete = re.search('(?<=\s)\d+([\.:]\d+)*', line, flags=re.DOTALL).group(0).strip()
        except:
            self.db_score = {}
            self.db_module = {}
            self.db_search = {}
            self.db_result = {}
            self.db_result_detail = {}
            self.db_score['total'] = 0
            self.db_score['total_string'] = "00"
            self.db_module['raw_name'] = line
            self.db_module['name'] = line
            self.db_module['version_mayor_minor'] = module_version_mayor_minor
            self.db_module['version_complete'] = module_version_complete
            self.db_search['status_code'] = '???'
            self.db_search['url'] = ''
            return 0
        else:
            self.db_module['raw_name'] = line
            self.db_module['name'] = module_name
            self.db_module['version_mayor_minor'] = module_version_mayor_minor
            self.db_module['version_complete'] = module_version_complete
            return 1

    def get_google_links(self):
        """Search google and return a result array, containing a dictionary with title,
        url and description
        In the init of the class a variable is defined that tells how much of the first hits we want to process """

        # Use the format "module-name"+"module-version"+"exploit" (the '"' are used to enforce that google
        # has to include it, and can't leave it out... gives a bunch of false positives otherwise that are irrelevant
        search_term = '%22' + self.db_module['name'] + '%22+%22' + self.db_module['version_mayor_minor'] + '%22+exploit'
        self.db_search['term'] = search_term
        self.db_search['url'] = "https://www.google.com/search?q=" + search_term

        try:
            page = requests.get(self.db_search['url'], headers=self.header_user_agent)
            time.sleep(self.search_engine_delay)
        except:
            self.db_search['status_code'] = '???'
            return None
        else:
            if page.status_code == 200:
                self.db_search['status_code'] = page.status_code
                soup = BeautifulSoup(page.content, 'lxml')

                links_counter = 0
                results = []
                # navigate through the dom and get the tags I'm interested in
                for i in soup.find_all('div', {'class': 'rc'}):
                    try:
                        title = i.find('div', {'class': 'r'}).a.h3.text
                        description = i.find('div', {'class': 's'}).div.text
                        url = i.find('div', {'class': 'r'}).a.get('href')
                        results.append(dict(title=title, description=description, url=url))
                    except Exception as e:
                        print("Couln't parse google page: ", e)
                    links_counter += 1
                    if links_counter > self.get_top_n:
                        break

                return results
            else:
                # sometimes I get other status codes, like 429 -> 'too many requests, a temporary ban
                self.db_search['status_code'] = page.status_code
                return []

    def get_cve_details(self, result_url):
        """Visit a https://www.cvedetails.com/cve/ page and get some details of the vulnerability
        since we are on a local machine and looking for privesc, I attribute extra score if I find
        a vulnerability that indicates privilege escalation"""

        try:
            cve_details_page = requests.get(result_url, headers=self.header_user_agent)
            cve_details_soup = BeautifulSoup(cve_details_page.content, 'lxml')
        except Exception as e:
            print("Error trying to open page: " + result_url + " (", e, ")")
            return False
        else:
            if cve_details_page.status_code == 200:
                try:
                    cve_details_summary = cve_details_soup.find(class_=self.cvedetails_summary).text.replace('\n',
                                                                                                             '').replace(
                        '\t', '')
                    # Navigate through the dom to find the tags we're interested in
                    cve_details_table = cve_details_soup.find(id=self.cvedetails_scores_and_types_id)
                    cve_details_tablerows = cve_details_table.find_all('tr')
                except Exception as e:
                    print("Error trying to parse page: " + result_url + " (", e, ")")
                else:
                    # replace google snippet by the site summary
                    self.db_result['snippet'] = cve_details_summary
                    # go over the details table
                    for cve_details_tablerow in cve_details_tablerows:
                        try:
                            cve_details_tablerow_title = cve_details_tablerow.find_all('th')[0].text
                            cve_details_tablerow_content = cve_details_tablerow.find_all('td')[0].text.split("\n")[0]
                        except Exception as e:
                            print("Unable to parse results for page: " + result_url + " (", e, ")")
                        else:
                            self.db_result_detail[cve_details_tablerow_title] = cve_details_tablerow_content
                            if cve_details_tablerow_title == self.cvedetails_gained_access_th:
                                if cve_details_tablerow_content == self.cvedetails_gained_access_admin_string:
                                    self.db_score['gained_access'] += self.cvedetails_gained_access_score_weight
            else:
                print("Got status code:", cve_details_page.status_code, "for page: " + result_url)

    def calculate_score(self):
        """Calculates the total score of the search: it iterates over all 'score-keys' (except the total-key)
        and sums them all up. Since I use the score for easy sorting of the outputfile, I make sure that for
        all scores below 10, I add an extra zero before it"""
        self.db_score['total'] = 0

        for key in self.db_score:
            if key != 'total':
                self.db_score['total'] += self.db_score[key]

        # convert to string that allows for easy sorting
        if self.db_score['total'] < 10:
            self.db_score['total_string'] = '0' + str(self.db_score['total'])
        else:
            self.db_score['total_string'] = str(self.db_score['total'])

    def sort_dict(self, item: dict):
        """
        Sort nested dict
        Example:
             Input: {'a': 1, 'c': 3, 'b': {'b2': 2, 'b1': 1}}
             Output: {'a': 1, 'b': {'b1': 1, 'b2': 2}, 'c': 3}
        """
        return {k: self.sort_dict(v) if isinstance(v, dict) else v for k, v in sorted(item.items(), reverse=True)}

    def print_report(self):
        """Prints a report to the commandline"""
        for module_id in self.db:
            if self.db[module_id]['score']['total'] > 0:
                print(Formatting.bold, Formatting.underline)
                print(self.db[module_id]['module']['name'] + " " + self.db[module_id]['module']['version_complete'] +
                      Formatting.reset + ' (' + Formatting.fgcolor.blue + self.db[module_id]['search'][
                          'url'] + Formatting.reset + ')')
                print(Formatting.bold + 'Score: ' + self.db[module_id]['score']['total_string'] + Formatting.reset)
                url_counter = 1
                for result_id in self.db[module_id]['results']:
                    print(str(url_counter) + ')' + Formatting.fgcolor.blue,
                          self.db[module_id]['results'][result_id]['url'] + Formatting.reset)
                    print(self.db[module_id]['results'][result_id]['snippet'])
                    url_counter += 1
                    try:
                        for details_id in self.db[module_id]['results'][result_id]['details']:
                            print('   ' + details_id + ": " +
                                  self.db[module_id]['results'][result_id]['details'][details_id])
                    except:
                        pass

    def store_report(self, filename=''):
        """Prints a report to an output file"""

        if filename == '':
            filename = self.output_file + '.report'

        with open(filename, 'w') as f:
            for module_id in self.db_sorted:
                if self.db[module_id]['score']['total'] > 0:
                    f.write('\n')
                    f.write(
                        self.db[module_id]['module']['name'] + " " + self.db[module_id]['module']['version_complete']
                        + ' (' + self.db[module_id]['search']['url'] + ')' + '\n')
                    f.write('Score: ' + self.db[module_id]['score']['total_string'] + '\n')
                    url_counter = 1
                    for result_id in self.db[module_id]['results']:
                        f.write(str(url_counter) + ')' + self.db[module_id]['results'][result_id]['url'] + '\n')
                        f.write(self.db[module_id]['results'][result_id]['snippet'] + '\n')
                        url_counter += 1
                        try:
                            for details_id in self.db[module_id]['results'][result_id]['details']:
                                f.write('   ' + details_id + ": " +
                                        self.db[module_id]['results'][result_id]['details'][details_id] + '\n')
                        except:
                            pass

    def print_status(self):
        """Store the report to an output file"""
        # with a status bar, I could only limit the output to results with a score,
        # significant enough to show:
        # if db_score['total'] > round(self.get_top_n / 2):
        status_code_message = "Status: " + str(self.db_search['status_code'])
        if self.db_search['status_code'] == 200:
            print(Formatting.fgcolor.green + status_code_message + Formatting.reset, end='')
        else:
            print(Formatting.fgcolor.red + status_code_message + Formatting.reset, end='')

        score_message = " - Score: " + str(self.db_score['total'])
        if round(self.get_top_n / 2) < self.db_score['total'] <= self.get_top_n:
            print(Formatting.fgcolor.green + score_message + Formatting.reset, end='')
        elif self.db_score['total'] > self.get_top_n:
            print(Formatting.fgcolor.purple + score_message + Formatting.reset, end='')
        else:
            print(score_message, end='')
        print(" - " + self.db_module['name'] + " " + self.db_module['version_complete'] + " - ", end='')
        print(Formatting.fgcolor.blue + self.db_search['url'] + Formatting.reset)

    def file_parse(self, filename):
        """For each line, extract the module name and version number, the do an online search
        and retrieve relevant information"""
        line_counter = 0
        with open(filename) as file:
            for line in file:
                self.db_search = {}
                self.db_results = {}
                self.db_module = {}
                line_counter += 1
                # If I successfully parsed the current line in the input-file
                if self.parse_dpkg(line):
                    self.db_score = {}
                    self.db_score['gained_access'] = 0
                    self.db_score['version_complete_match'] = 0
                    self.db_score['trusted_count'] = 0
                    # then get the search results for this module-name and version number
                    links = self.get_google_links()
                    # For each link, iterate over it
                    for link in links:
                        self.db_result = {}
                        # iterate over all trusted sources
                        for trusted_source in self.trusted_sources:
                            # if our link is a trusted source, and the description contains the name of the module
                            if trusted_source in link['url']:
                                self.db_result['url'] = link['url']
                                self.db_result['snippet'] = link['description']

                                self.db_result_detail = {}
                                if self.cve_details_url in link['url']:
                                    # grab details
                                    self.get_cve_details(link['url'])
                                    self.db_result['details'] = self.db_result_detail

                                self.db_results[link['url']] = self.db_result

                                if self.db_module['version_complete'] in self.db_result['snippet']:
                                    self.db_score['version_complete_match'] += self.version_complete_match_score_weight
                                self.db_score['trusted_count'] += 1

                    self.calculate_score()

                self.db[self.db_score['total_string'] + ' - ' + self.db_module['name'] + " " + self.db_module[
                    'version_complete']] = {"module": self.db_module, "score": self.db_score, "search": self.db_search,
                                            "results": self.db_results}

                self.print_status()
        # if the entire file is processes, create a sorted database
        self.db_sorted = self.sort_dict(self.db)

    def store_output(self, filename="", sort_order="d"):
        """Store all results in a json output file. There's a choice between sorting ascending or descending"""
        if filename == "":
            filename = self.output_file + '.json'

        print("Writing file...")

        if sort_order == "d":
            with open(filename, 'w') as outfile:
                json.dump(self.db, outfile, sort_keys=True, indent=4)
        else:
            with open(filename, 'w') as outfile:
                json.dump(self.db_sorted, outfile, indent=4)


parser = argparse.ArgumentParser()
parser.add_argument("input", type=str,
                    help="The file you want to process. Currently only files coming from the "
                         "command 'dpkg -l > file' are supported")
parser.add_argument("-no", "--no-output", action="store_true",
                    help="By default an outputfile is generated. Use this option if you don't want to generate one")
parser.add_argument("-nr", "--no-report", action="store_true",
                    help="By default a report is printed to the commandline. Use this option "
                         "if you don't want to print one")
args = parser.parse_args()
input_file = args.input

vulnfetcher = Vulnfetcher(input_file, True, not args.no_output, not args.no_report)
