#!/bin/bash

while true; do
   
    perf stat  -e instructions -a sleep 1
   
done