#!/bin/bash

# call ./debug <blah> | ./me

while read -r line; do wc -l "$line"; done | awk '{s+=$1} END {print s}'
