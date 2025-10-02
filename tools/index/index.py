##############################################################################
################################## IMPORTS ###################################
##############################################################################
import os
import re
import datetime
import argparse
import sys
import json

##############################################################################
############################## HELPER FUNCTIONS ##############################
##############################################################################
def parse_meta_table(meta_table):
    temp_dict = {}
    for line in meta_table[3:]:
        if len(line) != 0:
            elements = line.split("|")
            temp_dict[elements[1].strip()] = elements[2].strip()
    return temp_dict

def parse_proc_table(proc_table):
    procs={}
    for line in proc_table[3:]:
       if len(line) != 0:
           elements = line.split("|")
           procs[elements[1].split(".")[-1].strip()] = elements[2].strip()
    return procs

def parse_trr_meta(TRR_path):
    TRR_dict = {}  #dict to hold all the values parsed from the TRR meta
    
    #file_path = os.path.join(DID_path, "README.md")
    file = open(TRR_path, "r")

    #Parse the TRR README.md line by line
    for line in file:
        if line.strip().startswith("# "):
            #found the title
            TRR_dict['name'] = line.strip()[2:] #slice away the title markdown
                
        if line.strip() == "## Metadata":
            # found the start of the metadata section
            meta_table=[] #to hold the lines of the table for parsing
            meta_line=next(file) #get the next line
            while not meta_line.startswith("##"):   # loop till we reach the next header, reading in all metadata table lines
                # some elements will be links and enclosed in brackets, so we need to remove them
                meta_line = meta_line.replace("]","")
                meta_line = meta_line.replace("[","")
                meta_table.append(meta_line.strip())
                meta_line = next(file)

            meta_dict = parse_meta_table(meta_table) #load all the data from the meta table into the dict
            #need to do further processing to get the meta names right and formats right
            if 'ID' in meta_dict:
                TRR_dict['id'] = meta_dict['ID']
            else: 
                sys.exit("Parsing error: Metadata table is missing 'ID' field.")
            if 'Tactics' in meta_dict:
                TRR_dict['tactics'] = [item.strip() for item in meta_dict['Tactics'].split(",")]
            else: 
                sys.exit("Parsing error: Metadata table is missing 'Tactics' field.")
            if 'Contributors' in meta_dict:    
                TRR_dict['contributors'] = [item.strip() for item in meta_dict['Contributors'].split(",")]
            else: 
                sys.exit("Parsing error: Metadata table is missing 'Contributors' field.")
            if 'External IDs' in meta_dict:
                TRR_dict['external_ids'] = [item.strip() for item in meta_dict['External IDs'].split(",")]
            else: 
                sys.exit("Parsing error: Metadata table is missing 'External IDs' field.")
            if 'Platforms' in meta_dict:    
                TRR_dict['platforms'] = [item.strip() for item in meta_dict['Platforms'].split(",")]
            else: 
                sys.exit("Parsing error: Metadata table is missing 'Platforms' field.")

        if line.strip() == "## Procedures":
            # found the start of the procedures section
            proc_table=[]
            proc_line=next(file) #get the next line
            while not proc_line.startswith("##"):   # loop till we reach the next header, reading in all metadata table lines
                proc_table.append(proc_line.strip())
                proc_line = next(file)

            proc_dict = parse_proc_table(proc_table) #load all the data from the procedures table into the dict
            TRR_dict['procedures'] = proc_dict
    
    return(TRR_dict)

def update_index(trr_dict, index):
    #get timestamp for adding the creation time
    today = datetime.date.today()
    today_string = today.strftime("%Y-%m-%d")

    found_id = False
    for trr in index:
        if trr['id'] == trr_dict['id'] and trr['platforms'][0] == trr_dict['platforms'][0]:  #found the right one
            found_id = True
            trr['name'] = trr_dict['name']
            trr['contributors'] = trr_dict['contributors']
            trr['external_ids'] = trr_dict['external_ids']
            trr['platforms'] = trr_dict['platforms']
            trr['procedures'] = trr_dict['procedures']
            trr['tactics'] = trr_dict['tactics']

    if not found_id:  #ID isn't in index already, add it
        #add a publication date
        trr_dict['pub_date'] = today_string
        index.append(trr_dict) #add the new element to the index

def assign_new_id(orig_file, nextID):
    old_upper = "TRR0000"
    old_lower = "trr0000"
    new_upper = nextID.upper()
    new_lower = nextID.lower()
    
    #replace the old ID (TRR0000) with the new ID in all files and folders, return new path
    # We iterate over all files and subdirectories, renaming any that contain the old_lower number.
    for root, dirs, files in os.walk(os.path.join('reports', 'trr0000')):
        # Rename files
        for filename in files:
            filepath = os.path.join(root,filename)
            if filename == 'README.md':
                #replace content in the file
                with open(filepath, 'r') as f:
                    content = f.read()

                # Perform replacements
                content = content.replace(old_upper, new_upper)
                content = content.replace(old_lower, new_lower)

                # Write back to the file
                with open(filepath, 'w') as f:
                    f.write(content)
                
                print(f"Replaced ID in {filepath}")
            
            #rename the file if neeeded
            if old_lower in filename:
                new_filename = filename.replace(old_lower, new_lower)
                new_filepath = os.path.join(root, new_filename)
                try:
                    os.rename(filepath, new_filepath)
                    print(f"Renamed file: {filename} -> {new_filename}")
                except OSError as e:
                    sys.exit(f"Error renaming file {filepath}: {e}")
        

    # Rename the report folder itself
    new_report_dir = os.path.join('reports', new_lower)
    try:
        os.rename(os.path.join('reports', 'trr0000'), new_report_dir)
    except OSError as e:
        sys.exit(f"Error renaming main report folder {os.path.join('reports', 'trr0000')} to {new_report_dir}: {e}")
    
    print("Reassignment complete.")
    
    return orig_file.replace(old_lower, new_lower)

##############################################################################
#################################### MAIN ####################################
##############################################################################
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="This script will index a specified TRRs (merge mode) or the full repo (index mode). A merge test mode is available to ensure indexing will run successfully without updating the index. In merge mode, any new TRR (in a trr0000 folder) will bea assigned a new ID and the files and folders will be renamed to match the new ID. This script should be run from the root of the TRR repo.")
    parser.add_argument('mode', choices=['index', 'merge', 'merge_test'])
    parser.add_argument('-f', '--files', nargs='+', help="A list of files to parse (in 'merge' or 'merge_test' modes.")

    args = parser.parse_args()
    print(f"Running in {args.mode} mode.\n")

    #get timestamp for adding the update time
    today = datetime.date.today()
    today_string = today.strftime("%Y-%m-%d")

    #get the current index
    if args.mode != "merge_test":  #test mode won't make any changes to the index.json
        with open("index.json", "r") as f:
            content = f.read()
        if len(content) > 0:  #make sure there's data in the index.json
            index = json.loads(content) #parse the index as JSON
        else: 
            index = []  #if index.json is empty make it an empty JSON array.

    #get list of files to be parsed
    if args.mode == "merge" or args.mode == "merge_test":  #files will be provided as an argument
        if args.files:
            files = args.files
        else:
            sys.exit("Please provide list of files to parse in 'merge' or 'merge_test' modes.")
    elif args.mode == "index":  #make list of all TRR README.mds in the repo
        files = []
        for dirpath, dirnames, filenames in os.walk('reports'):
            for filename in filenames:
                if filename == "README.md":
                    full_path = os.path.join(dirpath, filename)
                    files.append(full_path)  
            
    #parse each file, updating the index if appropriate  
    for file in files:
        print(f"Parsing file: {file}")
        
        if args.mode == "merge":   #if we're in merge mode, check to see if the file is a new TRR (TRR0000 folder). If so, assign a new number before parsing and indexing.
            if file.startswith(os.path.join('reports', 'trr0000')):
               #determine what the last assigned number is
               last_id = index[-1]['id']  #get the ID from the last entry in the index
               last_num = re.search(r'\d+', last_id).group(0) # Extract only the digits
               new_num_int = int(last_num, 10) + 1  #convert number to int and increment
               new_id = f"TRR{new_num_int:04d}"  # format back into TRR number format
               print(f"New TRR detected, assigning a new ID number. Last TRR is {last_id}, next available ID is {new_id}")
               
               #update the folder, file names, etc to the next available number
               file = assign_new_id(file, new_id)
        
        trr_dict = parse_trr_meta(file)
        if args.mode == "merge_test":
            print(f"Parsing test completed successfully, indexed TRR would be:")
            print("------------------")
            print(trr_dict)
            print("------------------\n")
        else: # merge or index mode - update index.json
            if args.mode == "merge":
                #if in merge mode, add/update the last updated timestamp. (If we're reindexing everything, don't update the last_update timestamp.)
                trr_dict['last_update'] =  today_string
            
            update_index(trr_dict, index)
            
    # print(json.dumps(index, indent=2))
    
    if args.mode != "merge_test":  #test mode won't make any changes to the index.json
        with open("index.json", "w") as f:
            f.write(json.dumps(index, indent=2))

    sys.exit(0) #exit successfully    