# Vulnfetcher
> An enumeration tool that can be chained to nmap, or take a long list of installed debian packages (generated by 'dpkg -l > file) and search for known vulnerabilities.

> The tool uses searchengines, and can run unattended in the background. When you come back, it will have a list of potential exploits and vulnerabilities ready.

> It doesn't pretend to be smarter than you: it performs basic searches, scores the results and highlights what sticks out. It basically drops lowhanging fruits in your lap while you perform manual enumeration.

> ![Vulnfetcher Nmap Demo](/demo/vulnfetcher_nmap_chain.gif)

## Install dependencies
```
pip3 install requests
pip3 install beautifulsoup4
pip3 install lxml
```
## Install
```
cd /opt
git clone https://github.com/gnothiseautonlw/vulnfetcher.git
```
## Usage
### nmap chaining
```
nmap -sC -sV -oA scan <CHANGE_THIS_TO_TARGET_HOST> && python3 /opt/vulnfetcher/vulnfetcher.py -sr scan.xml
```
### dpkg
```
dpkg -l > file
python3 /opt/vulnfetcher/vulnfetcher.py file
```
> v![Vulnfetcher Dpkg Demo](/demo/vulnfetcher_dpkg_optimized.gif)

## Output
Appart from the onscreen report while scanning and afterwards, the tool writes two files in the same folder as the input file:
* file.vulnfetcher.json
   * A sorted json file, containing all information the tool found and that it used to score the findings
* file.vulnfetcher.report
   * A sorted textfile containing the report that's printed on screen after the search is done

## Help
```
python3 /opt/vulnfetcher/vulnfetcher.py -h
```
## How it works
### Parsing:
* It takes the input file, tries to make sense of the module names and module version numbers
* For the search term, it takes the 'mayor' - 'dot' - 'first number of minor'. So "libpam-modules 1.15.2", becomes "1.1"
* Then goes out on the web, looking with the search term: '"module_name"+"module_version"+exploit'. So in our example, it will look for '"libpam-modules"+"1.1"+"exploit"'
* If it finds exact CVE numbers, it will go fetch those details and bring them to you
* If it finds a public exploit reference on for example the cvedetails website, it will reference to that exploit. In other words, it doesn't only use searchengine pages, it also fetches information of cvedetails pages and exploit-db pages
### Scoring:
* For each trusted site that returns a result, it get's one point.
* If names or version numbers aren't found, it penelizes the score.
* If an exact match for the complete version number is found, it adds to the score. So in our example if '1.15.2' would be found, this would result in a higher score
* If an exact cve-number is found, the details of that cve are fetched. If those details contain indications of a severe vulnerability, resulting in a higher score

## Suggested Development Roadmap
If a coder would like to pick this up, here's a suggested roadmap:
* Currently I use duckduckgo as searchengine and crawl those results
   * Maybe there are better solutions, like maybe a non-profit google-api-key?
* Adding a progress bar when searching.
   * It would allow to display only results with a higher score and keep the output more condenced when the search is running
* Extensive testing
* Support for more input formats
* Improving the scoring algorithm 
   * could be improved by doing more testing
* Make code more beautiful.
   * I actually learned python to write this program, so I expect the code can be improved a lot
