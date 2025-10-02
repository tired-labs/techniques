#!/bin/bash
# TRR number assignment script. Run from the 'tools' folder.
# "Usage: trrassign.sh OldTRRNumber (optional - default is TRR0000) NewTRRNumber (optional - default is next available number)"
# The script will replace OldTRRNumber inside files and in filenames in the 'reports/OldTRRNumber' folder with NewTRRNumber.


#Check input, determine upper and lower case version of the old and new numbers
if [ -n "$1" ]; then
  oldnum_upper="${1^^}"
  oldnum_lower="${1,,}"
else
  #if no old number provided, use TRR0000
  oldnum_upper="TRR0000"
  oldnum_lower="trr0000"
fi

if [ -n "$2" ]; then
  newnum_upper="${2^^}"
  newnum_lower="${2,,}"
else  
  #if no new number provided, use the next available TRR number
  
  #This method enumerates the folders in 'reports' to find the last assigned number
  #readarray -t myArr < <(find ./reports -mindepth 1 -maxdepth 1 -type d -printf '%f\n')
  #lastnum=$(echo ${myArr[-1]} | tr -dc '0-9')
  
  #This method uses jq to read the index.json to find the last assigned number
  lastnum=$(jq '.[-1].id' ./index.json | tr -dc '0-9')
  
  #convert to int and increment, print back into TRR number format
  printf "Last number assigned is: $lastnum\n"
  newnum=$((10#$lastnum))
  ((newnum++))
  newnum=$(printf "TRR%04d" $newnum)

  printf "Next available number is: ${newnum}\n"
  newnum_upper="${newnum^^}"
  newnum_lower="${newnum,,}"
fi

#verify we've got valid values for both old and new numbers before we proceed with reassignment
pattern="TRR[0-9]{4}"
if [[ ! $oldnum_upper =~ $pattern ]] || [[ ! $newnum_upper =~ $pattern ]]; then
	printf "Error: invalid TRR number while trying to assign $oldnum_upper to $newnum_upper."
	exit
fi

printf "TRR Number assignment script - assigning $oldnum_upper to $newnum_upper.\n"

#Replace the uppercase string in the README.md files
find ./reports/$oldnum_lower \( -name 'README.md' \) -exec sed -i "s/$oldnum_upper/$newnum_upper/g" {} +
#Replace the lowercase string in the README.md files
find ./reports/$oldnum_lower \( -name 'README.md' \) -exec sed -i "s/$oldnum_lower/$newnum_lower/g" {} +
#replace the number in all file names (filenames should only use lower case)
find ./reports/$oldnum_lower/* -name "*$oldnum_lower*" -execdir rename "$oldnum_lower" $newnum_lower {} ";"
#finally, rename the folder itself
mv ./reports/$oldnum_lower ./reports/$newnum_lower

printf "Reassignment complete.\n"