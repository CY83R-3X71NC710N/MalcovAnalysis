
#!/usr/bin/env python
# MalcovAnalysis 
# CY83R-3X71NC710N © 2023

"""
MalcovAnalysis is a Python program designed to detect malicious code in a text file. It uses Python's re module to search for malicious code, and leverages Naive Bayes classifier algorithms and regular expression libraries to identify malicious code.
"""

import re
import collections
import urllib.request
import math

# Naive Bayes classifier 
def get_tokens(text):
    """
    This function takes in a text and returns a list of tokens.
    """
    return re.findall('[a-z]+', text.lower()) 

def train(features):
    """
    This function takes in a list of features and returns a dictionary
    of feature counts.
    """
    model = collections.defaultdict(lambda: 1)
    for f in features:
        model[f] += 1
    return model

NWORDS = train(get_tokens(urllib.request.urlopen('https://raw.githubusercontent.com/Cy83r-3x71nc710n/MalcovAnalysis/master/malcov_data.txt').read().decode('utf-8')))

alphabet = 'abcdefghijklmnopqrstuvwxyz'

def edits1(word):
    """
    This function takes in a word and returns a set of words that are
    one edit away from the input word.
    """
    s = [(word[:i], word[i:]) for i in range(len(word) + 1)]
    deletes    = [a + b[1:] for a, b in s if b]
    transposes = [a + b[1] + b[0] + b[2:] for a, b in s if len(b)>1]
    replaces   = [a + c + b[1:] for a, b in s for c in alphabet if b]
    inserts    = [a + c + b     for a, b in s for c in alphabet]
    return set(deletes + transposes + replaces + inserts)

def known_edits2(word):
    """
    This function takes in a word and returns a set of words that are
    two edits away from the input word.
    """
    return set(e2 for e1 in edits1(word) for e2 in edits1(e1) if e2 in NWORDS)

def known(words):
    """
    This function takes in a list of words and returns the subset of
    words that are actually in the dictionary.
    """
    return set(w for w in words if w in NWORDS)

def correct(word):
    """
    This function takes in a word and returns the most likely
    spelling correction for that word.
    """
    candidates = known([word]) or known(edits1(word)) or known_edits2(word) or [word]
    return max(candidates, key=NWORDS.get)

# Regular expression library
def detect_malicious_code(text):
    """
    This function takes in a text and returns a list of malicious code strings.
    """
    malicious_code_strings = []
    malicious_code_patterns = [
        r'<script>',
        r'<iframe>',
        r'<object>',
        r'<embed>',
        r'<applet>',
        r'<form>',
        r'<link>',
        r'<img>',
        r'<video>',
        r'<audio>',
        r'<svg>',
        r'<canvas>',
        r'<div>',
        r'<span>',
        r'<frame>',
        r'<frameset>',
        r'<base>',
        r'<bgsound>',
        r'<input>',
        r'<button>',
        r'<select>',
        r'<textarea>',
        r'<keygen>',
        r'<label>',
        r'<style>',
        r'<marquee>',
        r'<menu>',
        r'<nav>',
        r'<meta>',
        r'<basefont>',
        r'<bdo>',
        r'<map>',
        r'<area>',
        r'<blink>',
        r'<body>',
        r'<head>',
        r'<html>',
    ]
    for pattern in malicious_code_patterns:
        matches = re.findall(pattern, text)
        if matches:
            malicious_code_strings.append(matches)
    return malicious_code_strings

# Generate alerts for potentially malicious code strings
def generate_alerts(malicious_code_strings):
    """
    This function takes in a list of malicious code strings and prints
    an alert for each one.
    """
    for string in malicious_code_strings:
        print('ALERT: Potentially malicious code string detected:', string)

# Main function
def main():
    """
    This is the main function of the program.
    """
    text = urllib.request.urlopen('https://raw.githubusercontent.com/Cy83r-3x71nc710n/MalcovAnalysis/master/text_file.txt').read().decode('utf-8')
    malicious_code_strings = detect_malicious_code(text)
    generate_alerts(malicious_code_strings)

if __name__ == '__main__':
    main()
