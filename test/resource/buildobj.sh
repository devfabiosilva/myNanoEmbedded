#!/bin/bash

cd $(pwd)/resource -v
ld -r -b binary -o welcome.o welcome.txt

