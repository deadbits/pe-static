#!/bin/sh

[[ -z $1 ]] && echo "usage: ./bootstrap.sh <installation directory>"

instal_dir = $1

echo "\n\n"
echo " ************************************************"
echo " |            pe-static - version 1.0           |"  
echo " |                                              |"
echo " |                                              |"
echo " |           created by Adam M. Swanda          |"
echo " |   github.com/deadbits        deadbits.org    |"
echo " |                                              |"
echo " ************************************************"
echo "\n\n"


echo "\n* Cloning pe-static repository $1"
# clone the Github repo to local/sbin. change the dest folder if you want
git clone https://github.com/deadbits/pe-static $1

# change to the repo directory for initial setup
cd $1

echo "\n* Install Python requirements ..."
pip install -r requirements.txt

# clone the latest Yara-rules repo and compile them
echo "\n* Cloning Yara-Rules repository to pe-static/rules"
git clone https://github.com/Yara-Rules/Rules $1/rules
chmod +x install_gen.sh && ./install_gen.sh

echo "\n[*] pe-static ready to use Yara rules!"

