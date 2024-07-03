#!/bin/bash
#Variables
venv="blueboxsidedishvenv"
working_dir=$(pwd)
dependancies="requirements.txt"
db_name="bluebox.db"
upload_dir="Upload"
keys_dir="Keys"


#Setup application Dirs
if [ ! -d $working_dir/$upload_dir ]; then
    mkdir $upload_dir
fi
if [ ! -d $working_dir/$keys_dir ]; then
    mkdir $keys_dir
    touch $working_dir/$keys_dir/"keys.txt"
fi


#apt installs
sudo apt-get install osslsigncode libimage-exiftool-perl build-essential libffi-dev libfuzzy-dev sqlite3 python3.12-venv python-dev-is-python3 python3-pip


#check if venv exists if none create one
if [ ! -d $working_dir/$venv ]; then
    echo "**Creating virtual env. " $working_dir/$venv
    python3 -m venv $working_dir/$venv
    if [ $? -ne 0 ]; then
        echo "**Failed to create virtual env. :("
        exit 0
    fi
fi

#move to venv
source $working_dir/$venv/"bin/activate"

#check if dep file exists
if [ ! -f $working_dir/$dependancies ]; then
    echo "**"$working_dir/$dependancies" is missing :("
    exit 0
fi


echo "**Installing dependancies to virtual env. "
pip3 install -r $working_dir/$dependancies

if [ $? -ne 0 ]; then
    echo "**Something went wrong :("
    exit 0
else
    echo "**Python packages installed"
fi

#setup db
echo "**Setting up sqlite db"
sqlite3 $db_name ""

if [ $? -ne 0 ]; then
    echo "**DB creation failed"
    exit 0
fi

#mv $db_name $working_dir/$db_dir/
echo "**Done ;)"
echo
echo "RUN:: source $working_dir/$venv/bin/activate "