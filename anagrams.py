#!/run/current-system/sw/bin/env python

# simple program to generate anagrams of a string

import itertools

# input = input("Enter a line of text:").lower().replace(" ", "")
input = "louisfriend"

#generate all permutations of the string

permutations = list(itertools.permutations(input))

print(permutations)

words = "/home/daniel/src/project_moby_wordlists/COMMON.TXT"

res = ""

with open(words, 'r') as f:
    for string in permutations:
        for line in words:
            if string == line:
                print(string)
    #     for i in range(len(string)):
    #         word = string[0:i]
    #         for line in words:
    #             if word == line:
    #                 res.join(word)
    #                 res.join(" ")
    # if res != "":
    #     print(res)
                                        

