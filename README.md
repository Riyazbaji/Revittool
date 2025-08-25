![Java](https://img.shields.io/badge/Java-17-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![GitHub Repo Size](https://img.shields.io/badge/Repo%20Size-automatic-lightgrey)

# Revittool

Command-line tool for forward and reverse DNS lookups with cloud provider detection.

## Features

-> Forward DNS lookup for any domain
-> Reverse DNS lookup for any IPv4/IPv6 address
-> Batch mode: process multiple domains/IPs from a `.txt` file and export results to `.csv`
-> Detects cloud providers: Google Cloud, Amazon AWS, Microsoft Azure, Cloudflare, Oracle Cloud

## Usage

### Forward DNS Lookup
comand should be like this:

java Revittool -forward google.com

## Reverse DNS Lookup
comand should be like this:

java Revittool -reverse 156.63."." 

## For Batch mode Lookup
comand should be like this:

java Revittool -batch input.txt output.csv

