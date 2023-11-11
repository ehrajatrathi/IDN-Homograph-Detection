# IDN Homograph Attack Detection Tool

This tool is designed to detect potential Internationalized Domain Name (IDN) homograph attacks in URLs.

## Overview

The IDN homograph attack is a technique where an attacker creates URLs that appear legitimate but use characters from different alphabets, making them visually indistinguishable from the original ones. This tool aims to identify such potential attacks.

## Features

- Detection of potential IDN homograph attacks in URLs
- Generates a WHOIS information report for the detected URLs
- Scans files using VirusTotal (Premium Feature) 

## Usage

### Installation

1. Ensure you have Python installed.
2. Install the necessary dependencies by running: pip install tldextract whois reportlab requests


### Running the Tool

1. Execute the `homograph_attack_detection.py` script.
2. Input the URL to be checked in the provided text field.
3. Click "Check URL" to analyze the provided URL for potential IDN homograph attacks.
4. Utilize additional features such as file scanning and WHOIS report generation for detailed analysis.

### Premium Features (Feature Development in Progress)

- The file scanning and API key upload for VirusTotal services are available as premium features.
- To access these features, upload your VirusTotal API key within the tool.





   
