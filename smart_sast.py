# -*- coding: utf-8 -*-
"""SMART SAST v1.0 - tool with JSON-based RAG"""

# INPUT
# -------------------------
output_filepath = "/content/gdrive/MyDrive/" #Directory path to load the analysis result (json file)
rag_folder = "/content/gdrive/MyDrive/CWE-top25" #Directory path where the RAG (json) files are stored

# License
# -------------------------
"""
     Apache License
Version 2.0, January 2004
https://github.com/NLPSaST/SmartSast/blob/main/LICENSE
"""
# MOUNT GOOGLE DRIVE
# ------------------
from google.colab import drive
from google.colab import userdata
drive.mount('/content/gdrive/', force_remount=True)

# INSTALL REQUIRED PACKAGES
# -------------------------
!pip install google-generativeai
!pip install -U llama-cpp-python
!pip install instructor
!pip install -qU langchain-text-splitters
!pip install fuzzywuzzy
!pip install pandas

# IMPORT LIBRARIES
# ----------------
import llama_cpp
from llama_cpp.llama_speculative import LlamaPromptLookupDecoding
import instructor
from pydantic import BaseModel
from typing import List
#rom rich.console import Console
from huggingface_hub import hf_hub_download
from langchain_text_splitters import RecursiveCharacterTextSplitter, Language
from datetime import datetime
from collections import defaultdict
import json
import os
import re
import time
from fuzzywuzzy import fuzz
import pathlib
import urllib.parse
import torch


# Determine the current runtime environment
if torch.cuda.is_available():
    device = 'cuda'  # Use GPU
elif 'COLAB_TPU_ADDR' in os.environ:
    device = 'tpu'  # Use TPU
else:
    device = 'cpu'  # Use CPU

print(f"Using device: {device}")

# DEFINE FUNCTIONS
# -----------------
#-Utility Funcions
#--Validation and Clean

def is_null_or_empty(obj):
    """
        Checks if an object is null, empty, or None.
        """
    if obj is None:
        return True
    elif isinstance(obj, str):
        return len(obj.strip()) == 0
    elif isinstance(obj, (list, tuple)):
        return len(obj) == 0
    elif isinstance(obj, dict):
        return all(is_null_or_empty(value) for value in obj.values())
    else:
        return False

def find_null_objects(objects):
    """
    Finds indices of objects that are null or empty.
    """
    null_indices = []
    for i, obj in enumerate(objects):
        if is_null_or_empty(obj):
            null_indices.append(i)
    return null_indices

def extract_objects(objects, null_indices):
    """
    Extracts objects that are not null or empty.
    """
    extracted_objects = []
    prev_index = -1

    for index in null_indices:
        if index - prev_index > 1:
            #print(index-1)
            extracted_objects.append(objects[index - 1])
        prev_index = index
    return extracted_objects

def clean_extracted_objects(extracted_objects):
    """
    Filters a list of dictionaries by removing those that have an empty list
    """
    extracted_objects_temp = []
    for i in range(len(extracted_objects)):
        if extracted_objects[i]["lines_range"] != []:
            extracted_objects_temp.append(extracted_objects[i])
        else:
            print("No matches found")
    extracted_objects = extracted_objects_temp
    return extracted_objects

#---------------------------------------------------------------------
def condense_consecutive_numbers(numbers):
    """
    Condense consecutive numbers in a list.
    """
    result = []
    start = None
    end = None

    for num in numbers:
        if start is None:
            start = end = num
        elif num == end + 1:
            end = num
        else:
            result.append(f"{start}-{end}" if start != end else start)
            start = end = num

    if start is not None:
        result.append(f"{start}-{end}" if start != end else start)
    return result

def consecutives_numbers(nums,N):
    """
    Identify and organize the numbers in a list into groups of consecutive numbers.
    """
    sequence = []
    new_sequence = []

    for i in range(len(nums)):
        if i == 0 or nums[i] == nums[i-1] + 1:
            new_sequence.append(nums[i])
        else:
            new_sequence = [nums[i]]

        if len(new_sequence) == N:
            sequence.append(f"{new_sequence[0]}-{new_sequence[-1]}")
            new_sequence.pop(0)
    return sequence

#--Fuzzy Search

def find_partial_matches(file_path, search_string, threshold=98):
    """
    Finds lines in a file that partially match a specific string.
    """
    line_numbers = []
    with open(file_path, 'r') as file:
        text = file.read()
        lines = text.splitlines()

        for i, line in enumerate(lines):
            ratio = fuzz.partial_ratio(line.strip(), search_string)
            if ratio >= threshold:
                line_numbers.append(i + 1)
    return line_numbers

def find_substring_in_list(main_list, sub_string, threshold=98):
    """
    Returns 1-based indices of strings in main_list where a substring fuzzy-matches sub_string.
    """
    indices = []
    for idx, main_string in enumerate(main_list):
        for i in range(len(main_string) - len(sub_string) + 1):
            substring_candidate = main_string[i:i + len(sub_string)]
            similarity = fuzz.ratio(substring_candidate, sub_string)
            if similarity >= threshold:
                indices.append((idx + 1))
    return indices

def search_text(file_lines, search):
    """
    Searches for a single line or multi-line paragraph in the file content.
    """
    value = []
    total_value = []
    if '\n' in search:
        line_paragraph = search.splitlines()
        n = len(line_paragraph)
        for patron in line_paragraph:
            value = find_substring_in_list(file_lines, patron)
            total_value.extend(value)
            #print(value)
        unique_value = list(set(total_value))
        unique_value = consecutives_numbers(unique_value, n)
        result = unique_value
    else:
        result = find_substring_in_list(file_lines, search)
        result = list(set(result))
    return result

#--Files
def list_of_files(directory):
    """
    Lists all files in a directory.
    """
    if os.path.exists(directory) and os.path.isdir(directory):
        files = []
        for files_name in os.listdir(directory):
            ruta_completa = os.path.join(directory, files_name)
            if os.path.isfile(ruta_completa):
                files.append(ruta_completa)
        return files
    else:
        return None

def list_files_by_extension(directory, extensions):
    """
    Lists all files in a directory that have one of the specified extensions.
    """
    found_files = []
    for filename in os.listdir(directory):
        full_path = os.path.join(directory, filename)
        if os.path.isfile(full_path) and any(filename.endswith(ext) for ext in extensions):
            found_files.append(full_path)
    return found_files

def file_to_analyze(file_path,num,vulnerability_data):
    """
    Processes a single file for vulnerability analysis based on the input source.
        - Validates and sanitizes the file path if applicable.
        - Passes the file to the analysis pipeline (`analyze_file`).
        - Prints analysis results to the console.
    """
    print(f"Analyzing: {file_path}")
    print("Process Google Drive path")
    file_path = sanitize_google_drive_path(file_path)
    analysis_result = analyze_file(file_path, vulnerability_data)
    print(analysis_result)

def file_analyzed(path):
    """
    Extracts file name, extension, and path from the given file.
    """
    file_name_with_extension = os.path.basename(path)
    file_name, file_extension = os.path.splitext(file_name_with_extension)
    path_file = os.path.dirname(path)
    return [file_name, file_extension, path_file]

def sanitize_google_drive_path(user_input_path, allowed_base_path="/content/gdrive/MyDrive"):
    """
    Sanitizes a user-provided Google Drive file path.
    """
    if not isinstance(user_input_path, str):
        return None
    try:
        absolute_path = os.path.abspath(user_input_path)
        if not absolute_path.startswith(allowed_base_path):
            return None
        if ".." in absolute_path or "//" in absolute_path:
            return None
        if not os.path.exists(absolute_path):
            return None # path doesn't exist.
        return absolute_path

    except OSError:
        return None
    except ValueError:
        return None

def path_identity(filepath):
    """
    Identify if the filepath refers to a directory or a file.
    """
    if os.path.exists(filepath):
        if os.path.isdir(filepath):
            return "directory"
        elif os.path.isfile(filepath):
            return "file"
        else:
            return None
    else:
        return None

#--Analysis
def extract_code_lines(file_lines, start_line, end_line, file_extension=".java"):
    """
    Extract lines, skipping empty and comment lines depending on language.
    """
    extracted_lines = []
    in_multiline_comment = False

    comment_starts = {
        ".java": "//", ".py": "#", ".cpp": "//", ".c": "//", ".php": "//", ".js": "//"
    }

    comment_start = comment_starts.get(file_extension, "//")

    for line_count, line in enumerate(file_lines, start=1):
        stripped = line.strip()
        if stripped.startswith("/*"):
            in_multiline_comment = True
        if "*/" in stripped:
            in_multiline_comment = False
        if in_multiline_comment:
            continue
        if stripped.startswith(comment_start) or not stripped:
            continue
        if start_line <= line_count <= end_line:
            extracted_lines.append(line.rstrip())
        elif line_count > end_line:
            break

    return "\n".join(extracted_lines)

def classify_value(value):
    """
    Classifies a value between 0 and 10 into categories.
    """
    value = min(value, 10)
    if value == 0.0:
        return "None"
    elif 0.1 <= value <= 3.9:
        return "Low"
    elif 4.0 <= value <= 6.9:
        return "Medium"
    elif 7.0 <= value <= 8.9:
        return "High"
    else:
        return "Critical"

def load_json_vulnerability_data(folder_path=rag_folder):
    """
    Load all JSON files from the specified folder and combine them into a vulnerability database.
    Returns a dictionary with CWE IDs as keys and vulnerability data as values.
    """
    vulnerability_db = {}

    if not os.path.exists(folder_path):
        print(f"Warning: RAG folder {folder_path} not found. Using empty vulnerability database.")
        return vulnerability_db

    for filename in os.listdir(folder_path):
        if filename.endswith('.json'):
            filepath = os.path.join(folder_path, filename)
            try:
                with open(filepath, 'r') as f:
                    data = json.load(f)
                if "ID" not in data or not str(data["ID"]).isdigit():
                    print(f"❌ Skipping {filename}: missing or invalid 'ID'")
                    continue
                cwe_id = f"CWE-{data['ID']}"
                vulnerability_db[cwe_id] = data
            except json.JSONDecodeError:
                print(f"❌ Skipping {filename}: JSON decode error")
            except Exception as e:
                print(f"❌ Error loading {filename}: {e}")
    print(f"✔️ Loaded {len(vulnerability_db)} CWE definitions from RAG folder.")
    return vulnerability_db

def code_splitter(code, file_extension, size, overlap):
    """
    Splits code into smaller chunks based on file extension using a text splitter.
    """
    language_mapping = {
        ".py": Language.PYTHON,
        ".java": Language.JAVA,
        ".cpp": Language.CPP,
        ".c": Language.C,
        ".cs": Language.CSHARP,
        ".go": Language.GO,
        ".php": Language.PHP,
        ".ks": Language.KOTLIN,
        ".kts": Language.KOTLIN,
        ".ktx": Language.KOTLIN,
        ".rb": Language.RUBY,
        ".rs": Language.RUST,
        ".scala": Language.SCALA,
        ".swift": Language.SWIFT,
        ".proto": Language.PROTO,
        ".md": Language.MARKDOWN,
        ".markdown": Language.MARKDOWN,
        ".html": Language.HTML,
        ".tex": Language.LATEX,
        ".lua": Language.LUA,
        ".perl": Language.PERL,
        ".pm": Language.PERL,
        ".haskell": Language.HASKELL,
        ".lhs": Language.HASKELL,
        ".cob": Language.COBOL,
        ".cbl": Language.COBOL,
        ".cpy": Language.COBOL
    }
    selected_language = language_mapping.get(file_extension, Language.JAVA)
    code_splitter = RecursiveCharacterTextSplitter.from_language(
        language=selected_language,
        chunk_size=size,
        chunk_overlap=overlap
    )
    return code_splitter.create_documents([code])

def code_analysis(code_split,vulnerability_data,num_chunks):
    all_vulnerabilities = []
    i = 0
    #print(f"report: {code_split}")
    for doc in code_split:
        #print(f"2 report: {doc.page_content}")
        cwe_code = extract_cwe_code(doc.page_content, vulnerability_data)
        #print(f"3 report: {cwe_code}")
        vulnerability_info = vulnerability_data.get(cwe_code) if cwe_code else None
        i += 1
        print(f"In Progress: {i}/{num_chunks}")
        vuln_info_str = ""
        if vulnerability_info:
            vuln_info_str = f"""
            Vulnerability Name: {vulnerability_info.get('Name', 'N/A')}
            Description: {vulnerability_info.get('Description', 'N/A')}
            Likelihood: {vulnerability_info.get('LikelihoodOfExploit', 'N/A')}
            Examples: {json.dumps(vulnerability_info.get('DemonstrativeExamples', []), indent=2)}
            Mitigations: {json.dumps(vulnerability_info.get('PotentialMitigations', []), indent=2)}
            """

        try:
            # Use non-streaming mode
            extraction = create(
                response_model=instructor.Partial[Risk],
                messages=[{
                    "role": "user",
                    "content": f"""<s>[INST] <<SYS>>
                    You are a cybersecurity AI program. List all identified vulnerabilities and security risks identify in the following code.
                    Here is vulnerability information from our database:
                    {vuln_info_str}
                    Analyze the code: {doc.page_content}
                    [/INST]"""
                }],
                stream=False,  # Disable streaming
            )

            # Handle both single Risk and list of Risks
            if isinstance(extraction, list):
                for item in extraction:
                    obj = item.model_dump()
                    if vulnerability_info:
                        obj.update({
                            "vulnerability_details": {
                                "name": vulnerability_info.get('Name'),
                                "description": vulnerability_info.get('Description'),
                                "mitigations": vulnerability_info.get('PotentialMitigations', [])
                            }
                        })
                    all_vulnerabilities.append(obj)
            else:
                obj = extraction.model_dump()
                if vulnerability_info:
                    obj.update({
                        "vulnerability_details": {
                            "name": vulnerability_info.get('Name'),
                            "description": vulnerability_info.get('Description'),
                            "mitigations": vulnerability_info.get('PotentialMitigations', [])
                        }
                    })
                all_vulnerabilities.append(obj)

        except Exception as e:
            print(f"❌ Error during model inference: {e}")
            # Print raw response for debugging
            raw_response = llama.create_chat_completion_openai_v1(
                messages=[{
                    "role": "user",
                    "content": f"""<s>[INST] <<SYS>>
                    You are a cybersecurity AI program. List all identified vulnerabilities and security risks identify in the following code.
                    Here is vulnerability information from our database:
                    {vuln_info_str}
                    Analyze the code: {doc.page_content}
                    [/INST]"""
                }]
            )
            print(f"⚠️ Raw model response: {raw_response}")
    print(all_vulnerabilities)
    return all_vulnerabilities

def analyze_file(file_path, vulnerability_data):
    """
    Analyzes a single file for vulnerabilities.
    """
    file_name, file_extension, path_file = file_analyzed(file_path)

    with open(file_path, "r") as file:
        file_lines = file.readlines()
        code_to_read = "".join(file_lines)
    start_time = time.time()
    code_split = code_splitter(code_to_read, file_extension, size=3000, overlap=100) #2000
    all_vulnerabilities = []

    # Get the number of chunks
    num_chunks = len(code_split)
    #console = Console()
    all_vulnerabilities = code_analysis(code_split,vulnerability_data,num_chunks)

    # Process extracted vulnerabilities
    extracted_objects = []
    for vulnerability in all_vulnerabilities:
        search_string = vulnerability["Vulnerable_code"]
        lines = find_partial_matches(file_path, search_string)
        if lines:
            condensed_list = condense_consecutive_numbers(lines)
            vulnerability["lines_range"] = condensed_list
            extracted_objects.append(vulnerability)

    # Ensure there's at least one vulnerability before accessing the last one
    if all_vulnerabilities:
        last_vulnerability = all_vulnerabilities[-1]
        null_indices = find_null_objects(all_vulnerabilities)
        # Corrected logic to combine extracted objects and potentially the last one
        processed_objects_from_null = extract_objects(all_vulnerabilities, null_indices)
        # Check if the last vulnerability is already in the processed objects before adding
        if last_vulnerability not in processed_objects_from_null:
             extracted_objects.extend(processed_objects_from_null)
        else:
            extracted_objects = processed_objects_from_null
    else:
         print("No vulnerabilities or risk has been identify.")
         # Handle the case where no vulnerabilities are found
         output_no_vuln = {
            "date": datetime.now().strftime("%Y%m%d%H%M%S"),
            "file_name": file_name,
            "file_extension": file_extension,
            "path_file": path_file,
            "analisis duration": 0.0, # Duration will be calculated later
            "risk [in progress]": "None",
            "cwss_average [in progress]": 0.0,
            "vulnerabilities": []
         }
         save_out(output_no_vuln)
         return output_no_vuln

    # Dedup extracted_objects based on a unique identifier (e.g., vulnerability name and vulnerable code)
    seen_signatures = set()
    deduplicated_extracted_objects = []
    for obj in extracted_objects:
        # Create a simple signature for deduplication
        signature = (obj.get('Vulnerability_name'), obj.get('Vulnerable_code'))
        if signature not in seen_signatures:
            deduplicated_extracted_objects.append(obj)
            seen_signatures.add(signature)

    extracted_objects = deduplicated_extracted_objects


    for i in range(len(extracted_objects)):
        search_strings = extracted_objects[i]["Vulnerable_code"]
        resultados = search_text(file_lines, search_strings)
        extracted_objects[i]["lines_range"] = resultados

    extracted_objects = clean_extracted_objects(extracted_objects)

    if extracted_objects: # Only calculate CWSS if there are vulnerabilities
        cwss_values = cwss_eval(extracted_objects, file_lines)
        total_cwss = cwss_values[0]
        extracted_objects = cwss_values[1]

        # Calculate average CWSS
        total_cwss = [obj["CWSS"] for obj in extracted_objects]
        cwss_average = sum(total_cwss) / len(total_cwss) if total_cwss else 0
        category = classify_value(cwss_average)
    else: # Handle case with no extracted objects after cleaning
        cwss_average = 0.0
        category = "None"

    end_time = time.time()
    elapsed_time = round(end_time - start_time, 2)

    # Prepare output for saving
    output1 = {
        "date": datetime.now().strftime("%Y%m%d%H%M%S"),
        "file_name": file_name,
        "file_extension": file_extension,
        "path_file": path_file,
        "analisis duration": elapsed_time,
        "risk [in progress]": category,
        "cwss_average [in progress]": cwss_average,
        "vulnerabilities": extracted_objects
    }

    save_out(output1)
    return output1  # Return the output dictionary

def cwss_eval(extracted_objects,file_lines):
    """
    Processes a list of extracted objects, each containing a range of lines from a file, and evaluates them based on their associated Common Weakness Scoring System (CWSS) value.
    """
    total_cwss = []

    for i in range(len(extracted_objects)):
        line_ranges = extracted_objects[i].get("lines_range")
        if not line_ranges:
            print(f"Skipping CWSS eval for object {i} due to empty line_ranges.")
            continue

        total_cwss.append(extracted_objects[i]["CWSS"])
        total_lines = len(file_lines)

        processed_ranges = []
        if isinstance(line_ranges, str):
             # Attempt to parse string format like "[1]", "[31, 15]", "[1-5]"
            try:
                # Safely evaluate the string, expecting a list or a single number
                parsed_range = eval(line_ranges)
                if isinstance(parsed_range, int):
                    processed_ranges = [(parsed_range, parsed_range)]
                elif isinstance(parsed_range, list):
                    for r in parsed_range:
                         if isinstance(r, int):
                            processed_ranges.append((r, r))
                         elif isinstance(r, str) and "-" in r:
                             parts = r.split("-")
                             if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
                                processed_ranges.append((int(parts[0]), int(parts[1])))
                else:
                    print(f"Warning: Could not interpret line_ranges string format: {line_ranges}")
                    continue # Skip if parsing fails unexpectedly
            except (SyntaxError, NameError):
                print(f"Warning: Could not parse line_ranges string using eval: {line_ranges}")
                continue # Skip if eval fails


        elif isinstance(line_ranges, (list, tuple)):
            for r in line_ranges:
                if isinstance(r, int):
                    processed_ranges.append((r, r))
                elif isinstance(r, str) and "-" in r:
                    parts = r.split("-")
                    if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
                        processed_ranges.append((int(parts[0]), int(parts[1])))
                elif isinstance(r, (list, tuple)) and len(r) == 2 and isinstance(r[0], int) and isinstance(r[1], int):
                     processed_ranges.append((r[0], r[1]))
                else:
                     print(f"Warning: Could not interpret list/tuple range element: {r}")


        for j, line_range_tuple in enumerate(processed_ranges, start=1):
            start, end = line_range_tuple
            # Adjust start and end with boundary checks
            start = max(1, start - 3) # Ensure start is at least 1
            end = min(total_lines, end + 3)

            extracted_code = extract_code_lines(file_lines, start, end)
            extracted_objects[i][f"text{j}"] = extracted_code
            #print(extracted_objects[i]) # Keep for debugging if needed

    return total_cwss, extracted_objects

def extract_cwe_code(code_snippet, vulnerability_data):
    """
    Extracts the CWE code from the code snippet based on known patterns or keywords.
    This is a simple example and may need to be expanded based on your specific needs.
    """
    # Define a mapping of keywords to CWE codes
    cwe_mapping = {
    # Injections
    "SQL Injection": "CWE-89",
    "NoSQL Injection": "CWE-943",
    "OS Command Injection": "CWE-78",
    "LDAP Injection": "CWE-90",
    "XPath Injection": "CWE-643",

    # XSS and other web vul.
    "Cross-Site Scripting": "CWE-79",
    "Cross-Site Request Forgery": "CWE-352",
    "Server-Side Request Forgery": "CWE-918",

    # Memorry attack
    "Buffer Overflow": "CWE-120",
    "Out-of-Bounds Write": "CWE-787",
    "Use After Free": "CWE-416",

    # Autenthication/authorization
    "Broken Authentication": "CWE-287",
    "Insecure Direct Object Reference": "CWE-639",
    "Missing Authentication": "CWE-306",

    # Configuration/cryptography
    "Sensitive Data Exposure": "CWE-311",
    "Weak Cryptography": "CWE-327",
    "Hardcoded Credentials": "CWE-798",

    # Logic
    "Business Logic Flaw": "CWE-840",
    "Unrestricted Upload": "CWE-434",
    "Race Condition": "CWE-362",

    # APIs and Services
    "Insecure Deserialization": "CWE-502",
    "Mass Assignment": "CWE-915",
    "Improper Input Validation": "CWE-20"
    }

    for keyword, cwe_code in cwe_mapping.items():
        if keyword.lower() in code_snippet.lower():
            return cwe_code
    if vulnerability_data:
        for cwe_id, vuln_info in vulnerability_data.items():
            vuln_name = vuln_info.get("Name", "").lower()
            vuln_desc = vuln_info.get("Description", "").lower()
            if (fuzz.partial_ratio(vuln_name, code_snippet.lower()) > 80 or
                fuzz.partial_ratio(vuln_desc, code_snippet.lower()) > 80):
                return cwe_id
    return None


#-- Output
def print_analysis_report(analysis):
    """
    Prints the analysis results in a readable format
    """
    print(f"-------Report-------")
    print(f"\nAnalysis Report for: {analysis['file_info']['file_name']}")
    print(f"Risk Level [in progress]: {analysis['file_info']['risk_level']}")
    print(f"Average CWSS [in progress]: {analysis['file_info']['cwss_average']}")
    print("\nSummary Statistics:")
    print(f"- Total vulnerabilities: {analysis['stats']['total_vulnerabilities']}")
    print(f"- Unique CWE IDs: {analysis['stats']['unique_cwe_ids']}")
    print(f"- Exact duplicates (same name+code+lines): {analysis['stats']['exact_duplicates']}")
    print(f"- Name-only duplicates: {analysis['stats']['name_duplicates']}")

    if analysis.get('exact_duplicates'):
        print("\nExact Duplicates Found:")
        # The keys in real_duplicates_str_keys are strings
        for (name_code_lines_str), entries in analysis['exact_duplicates'].items():
             # Convert the string key back to a tuple for easier access
            try:
                # Safely evaluate the string representation of the tuple
                # Handle cases where the signature might not be a perfect tuple string
                name, code, lines = eval(name_code_lines_str)
                if not isinstance(lines, tuple):
                    lines = (lines,) # Ensure lines is a tuple for consistent display
            except (SyntaxError, NameError, TypeError):
                print(f"Warning: Could not parse duplicate key string: {name_code_lines_str}")
                continue # Skip this entry if parsing fails

            print(f"\nVulnerability: {name} (CWE: {entries[0]['cwe']})")
            print(f"Vulnerable Code: {code}")
            print(f"Lines: {lines}")
            print(f"Found {len(entries)} instances:")
            for entry in entries:
                print(f"  - Index {entry['index']}: CWSS {entry['cwss']}")
                print(f"    Description: {entry['description']}")
                print(f"    Solution: {entry['solution']}\n")

    if analysis.get('name_duplicates'):
        print("\nName-Only Duplicates (different implementations):")
        for name, entries in analysis['name_duplicates'].items():
            print(f"\nVulnerability Name: {name}")
            print(f"Found {len(entries)} instances across different code locations:")
            for entry in entries:
                print(f"  - Index {entry['index']}: CWE-{entry['cwe']} (CWSS: {entry['cwss']})")


#=========================================================
def analyze_vulnerability_duplicates_and_clean(json_data):
    """
    Analyzes the vulnerabilities for duplicates and provides a detailed comparison.
    It now retrieves the file information (date, name, etc.) directly from the input JSON
    """
    if not isinstance(json_data, dict) or 'vulnerabilities' not in json_data:
        return {"error": "Invalid JSON structure or missing 'vulnerabilities' field"}

    report_date = json_data.get("date", datetime.now().strftime("%Y%m%d%H%M%S"))
    file_name = json_data.get("file_name", "UNKNOWN_FILE")
    file_extension = json_data.get("file_extension", "UNKNOWN_EXT")
    path_file = json_data.get("path_file", "UNKNOWN_PATH")
    duration = json_data.get("analisis duration", 0.0) # Use correct key
    risk = json_data.get("risk [in progress]", "UNKNOWN_RISK") # Use correct key
    cwss_average = json_data.get("cwss_average [in progress]", 0.0) # Use correct key

    file_extension = json_data.get("file_extension", os.path.splitext(file_name)[1] if file_name != "UNKNOWN_FILE" else "UNKNOWN_EXT")

    duplicates = defaultdict(list)
    unique_cwes = set()

    final_vulnerabilities_report = []
    example_exact_duplicates = {}

    for idx, vuln in enumerate(json_data['vulnerabilities']):
        vuln_name = vuln.get('Vulnerability_name', 'UNNAMED')
        cwe = vuln.get('CWE', 'UNKNOWN')
        unique_cwes.add(cwe)

        signature = (
            vuln_name,
            vuln.get('Vulnerable_code', ''),
            tuple(vuln.get('lines_range', []))
        )

        vuln_details = {
            'Vulnerability_name': vuln_name,
            'CWE': cwe,
            'CWSS': vuln.get('CWSS'),
            'Description': vuln.get('Description'),
            'Vulnerable_code': vuln.get('Vulnerable_code', ''),
            'lines_range': str(vuln.get('lines_range', [])),
            'Solution': vuln.get('Solution')
        }

        for key, value in vuln.items():
            if key.startswith('text'):
                vuln_details[key] = value

        duplicates[signature].append(vuln_details)

    real_duplicates = {str(k): v for k, v in duplicates.items() if len(v) > 1}

    for sig, entries in duplicates.items():
        if len(entries) == 1:
            final_vulnerabilities_report.append(entries[0])
        else:
            if str(sig) not in example_exact_duplicates:
                 final_vulnerabilities_report.append(entries[0])
                 example_exact_duplicates[str(sig)] = entries
    name_duplicates_raw = defaultdict(list)
    for vuln in json_data['vulnerabilities']:
        vuln_name = vuln.get('Vulnerability_name', 'UNNAMED')
        current_signature = (
            vuln_name,
            vuln.get('Vulnerable_code', ''),
            tuple(vuln.get('lines_range', []))
        )
        if len(duplicates[current_signature]) == 1:
             name_duplicates_raw[vuln_name].append({
                'index': json_data['vulnerabilities'].index(vuln),
                'Vulnerability_name': vuln_name,
                'CWE': vuln.get('CWE', 'UNKNOWN'),
                'CWSS': vuln.get('CWSS'),
                'Vulnerable_code': vuln.get('Vulnerable_code', ''),
                'lines_range': str(vuln.get('lines_range', [])),
                'Solution': vuln.get('Solution')
            })

    name_duplicates = {k: v for k, v in name_duplicates_raw.items() if len(v) > 1}

    report = {
        "file_info": {
            "date": report_date,
            "file_name": file_name,
            "file_extension": file_extension,
            "path_file": path_file,
            "analysis duration": duration,
            "risk_level [in progress]": risk,
            "cwss_average [in progress]": cwss_average,
        },
        "cleaned_vulnerabilities": final_vulnerabilities_report,
        "stats": {
            "total_vulnerabilities": len(json_data['vulnerabilities']),
            "unique_cwe_ids": len(unique_cwes),
            "exact_duplicates": sum(len(v) - 1 for v in real_duplicates.values()),
            "name_duplicates": sum(len(v) - 1 for v in name_duplicates.values()),
            "clean_vulnerabilities_count": len(final_vulnerabilities_report)
        },
        "exact_duplicates": real_duplicates,
        "name_duplicates": name_duplicates
    }
    return report

#=========================================================
def analyze_vulnerability_duplicates(json_data):
    """
    Analyzes vulnerabilities for duplicate names and provides detailed comparison
    """
    if not isinstance(json_data, dict) or 'vulnerabilities' not in json_data:
        return {"error": "Invalid JSON structure or missing 'vulnerabilities' field"}

    duplicates = defaultdict(list)
    unique_cwes = set()

    for idx, vuln in enumerate(json_data['vulnerabilities']):
        vuln_name = vuln.get('Vulnerability_name', 'UNNAMED')
        cwe = vuln.get('CWE', 'UNKNOWN')
        unique_cwes.add(cwe)

        signature = (
            vuln_name,
            vuln.get('Vulnerable_code', ''),
            tuple(vuln.get('lines_range', []))
        )

        duplicates[signature].append({
            'index': idx,
            'cwe': cwe,
            'cwss': vuln.get('CWSS'),
            'description': vuln.get('Description'),
            'solution': vuln.get('Solution')
        })

    real_duplicates = {k: v for k, v in duplicates.items() if len(v) > 1}

    real_duplicates_str_keys = {json.dumps(k): v for k, v in real_duplicates.items()}

    name_only_duplicates = defaultdict(list)
    for sig, entries in duplicates.items():
        name_only_duplicates[sig[0]].extend(entries)
    name_only_duplicates = {k: v for k, v in name_only_duplicates.items() if len(v) > 1}


    return {
        'file_info': {
            'file_name': json_data.get('file_name'),
            'risk_level': json_data.get('risk [in progress]'),
            'cwss_average': json_data.get('cwss_average [in progress]') # Use correct key
        },
        'stats': {
            'total_vulnerabilities': len(json_data['vulnerabilities']),
            'unique_cwe_ids': len(unique_cwes),
            'exact_duplicates': len(real_duplicates),
            'name_duplicates': len(name_only_duplicates)
        },
        'exact_duplicates': real_duplicates_str_keys,
        'name_duplicates': name_only_duplicates
    }

def save_out(output1):
    """
    Save output to JSON with device and RAG info in filename
    """
    rag_used = "RAG" if vulnerability_data else "noRAG"

    output_filename0 = f"{output1['date']}-smart_sast_2_0_4-raw_data-{device}-{rag_used}-{output1['file_name']}.json"
    output_path0 = f"{output_filepath}{output_filename0}"
    # Save the original output
    print(f"Saving original analysis to: {output_path0}")
    with open(output_path0, 'w') as json_file:
        json.dump(output1, json_file, indent=4)

    # Generate analysis result and save
    analysis_result1 = analyze_vulnerability_duplicates(output1)
    output_filename1 = f"{output1['date']}-smart_sast_2_0_4-statistics-{device}-{rag_used}-{output1['file_name']}.json"
    output_path1 = f"{output_filepath}{output_filename1}"
    if 'error' in analysis_result1:
        print(f"Error generating dup_vul report: {analysis_result1['error']}")
    else:
        print(f"Saving raw report to: {output_path1}")
        with open(output_path1, 'w') as json_file:
            json.dump(analysis_result1, json_file, indent=4)

    # Generate analysis result 2 and save
    analysis_result2 = analyze_vulnerability_duplicates_and_clean(output1)
    output_filename2 = f"{output1['date']}-smart_sast_2_0_4-vul-{device}-{rag_used}-{output1['file_name']}.json"
    output_path2 = f"{output_filepath}{output_filename2}"
    if 'error' in analysis_result2:
         print(f"Error generating dup_clean report: {analysis_result2['error']}")
    else:
        print(f"Saving report 2 to: {output_path2}")
        with open(output_path2, 'w') as json_file:
            json.dump(analysis_result2, json_file, indent=4)

    if 'error' not in analysis_result1:
        print_analysis_report(analysis_result1)


#-- Main

def _action(path_directory, num, vulnerability_data):
    """
    Determines whether the input path is a file or directory and initiates analysis accordingly.
        - If a directory: lists and filters files by desired extensions, then analyzes each.
        - If a file: sends it directly for analysis.
        - Prints file analysis progress and results.
        - Handles cases where the path is neither a valid file nor a directory.
    """

    type_directory = path_identity(path_directory)

    print(f"⚠️'{path_directory}' it is {type_directory}")

    if type_directory == "directory":
        files = list_of_files(path_directory)
        if files:
            print(f"Files at '{path_directory}':")
            files_to_analyze = list_files_by_extension(path_directory, desired_extensions)

            for file_path in files_to_analyze:
                print(f"Analyzing: {file_path}")
                file_to_analyze(file_path, num, vulnerability_data)
        else:
            print(f"No files found at '{path_directory}' or the directory is empty.")
    elif type_directory == "file":
        print(f"Analyzing: {path_directory}")
        file_to_analyze(path_directory, num, vulnerability_data)
    else:  # Handles cases where type_directory is neither "directory" nor "file" (e.g., "invalid", "not_found")
        print(f"❌ Error: The path '{path_directory}' is not a valid file or directory. Please check the path and try again.")

def main():
    """
    Entry point for the vulnerability analysis tool (when run as a script).

    Prompts the user to enter a file or directory path from Google Drive,
    sets the analysis mode, and triggers analysis through `_action()`.
    """

    file_path = input("Enter the Google Drive file or directory path: ")
    print(f"Google Drive path (example: /content/gdrive/MyDrive/test.java): {file_path}")
    option = "1"
    _action(file_path, option, vulnerability_data)

#------------------------------------------------------
# Start
# -----

# Load vulnerability data from JSON files
vulnerability_data = load_json_vulnerability_data()


# Define a model for risks
class Risk(BaseModel):
    Vulnerability_name: str
    CWE: str
    CWSS: float
    Description: str
    Vulnerable_code: str
    lines_range : str
    Solution: str

# LLM MODEL
model_id = "Qwen/Qwen2.5-Coder-7B-Instruct-GGUF"
filename = "qwen2.5-coder-7b-instruct-q8_0.gguf"
local_model_path = hf_hub_download(repo_id=model_id, filename=filename)


print("⏳ Reading Model's metadata...")
temp_llama = llama_cpp.Llama(model_path=local_model_path, n_gpu_layers=0, verbose=False)
model_metadata = temp_llama.metadata
model_max_ctx = model_metadata.get("context_length", 13000)  # Fallback
print(f"📏 Model Max. context_length: {model_max_ctx} tokens")

# Dinamic assignement of n_ctx resources
if device == 'cuda':
    n_ctx = min(model_max_ctx, 16000)
    n_gpu_layers = 999
    print("⚠️ GPU in used")
elif device == 'cpu':
    n_ctx = min(model_max_ctx, 4096)
    n_gpu_layers = 0
    print("⚠️ CPU in used")
elif device == 'tpu':
    n_ctx = min(model_max_ctx, 1300000)
    n_gpu_layers = 999
    print("⚠️ TPU in used")
else:
    n_ctx = 4096
    n_gpu_layers = 0

print(f"🎯 In use n_ctx = {n_ctx} y n_gpu_layers = {n_gpu_layers}")

# Model setup
llama = llama_cpp.Llama(
    model_path=local_model_path,
    n_gpu_layers=n_gpu_layers,
    chat_format="chatml",
    n_ctx=n_ctx,
    logits_all=True,
    verbose=True,
    max_new_tokens=512,
    repetition_penalty=1.1,
    temperature=0.001,
    context_length=n_ctx,
    stream=False,
    draft_model=LlamaPromptLookupDecoding(num_pred_tokens=2)
)
desired_extensions = [".py",".java",".cpp",".c",".cs",".go",".php",".ks",".kts",".ktx",".rb",".rs",".scala",".swift",".proto",".md",".markdown",".html",".tex",".lua",".perl",".pm",".haskell",".lhs",".cob",".cbl",".cpy"]

create = instructor.patch(
    create=llama.create_chat_completion_openai_v1,
    mode=instructor.Mode.JSON_SCHEMA
)

if __name__ == "__main__":
    main()
