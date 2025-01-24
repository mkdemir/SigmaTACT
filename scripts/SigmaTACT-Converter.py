import os
import yaml
import logging
import argparse
import json
from hashlib import sha256
from datetime import datetime, date
from typing import List, Dict, Optional
from concurrent.futures import ThreadPoolExecutor
from threading import Lock
import time

# Logger Configuration
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] - [%(levelname)s] - [Message: %(message)s]',
    handlers=[
        logging.FileHandler("sigma_yaml_parser.log", encoding='utf-8'),  # Logs to file
        logging.StreamHandler()  # Logs to console
    ]
)
logger = logging.getLogger(__name__)
write_lock = Lock()

def parse_yaml_files(rules_dir: str, exclude_paths: Optional[List[str]] = None) -> List[str]:
    """
    Recursively searches for YAML files in the specified directory, excluding specified paths.

    Args:
        rules_dir (str): The root directory where YAML files are located.
        exclude_paths (Optional[List[str]]): List of paths to exclude from the search.

    Returns:
        List[str]: List of paths to the YAML files found in the directory.
    """
    yaml_files = []
    exclude_paths = set(exclude_paths or [])  # Convert to set for faster lookups

    for root, dirs, files in os.walk(rules_dir):
        # Skip excluded paths
        if any(os.path.abspath(root).startswith(os.path.abspath(exclude)) for exclude in exclude_paths):
            logger.info(f"Excluding path: {root}")
            continue

        for file in files:
            if file.endswith(('.yml', '.yaml')):
                yaml_files.append(os.path.join(root, file))

    if not yaml_files:
        logger.warning(f"No YAML files found in directory: {rules_dir}.")
    
    return yaml_files

def load_yaml_file(yaml_file: str) -> Optional[List[Dict]]:
    """
    Loads a YAML file and ensures that the content is returned as a list of dictionaries.
    If the content is a dictionary, it wraps it into a list.

    Args:
        yaml_file (str): The path to the YAML file.

    Returns:
        Optional[List[Dict]]: The content of the YAML file as a list, or None if invalid.
    """
    try:
        with open(yaml_file, 'r', encoding='utf-8') as file:  # Use UTF-8 encoding
            content = yaml.safe_load(file)
            if isinstance(content, list):
                return content
            elif isinstance(content, dict):
                logger.info(f"File {yaml_file} contains a single rule. Wrapping it in a list.")
                return [content]
            else:
                logger.warning(f"File {yaml_file} has invalid root structure: {content}")
                return []
    except yaml.YAMLError as e:
        logger.error(f"Error parsing YAML file {yaml_file}: {e}")
        return []
    except Exception as e:
        logger.error(f"Unexpected error while loading file {yaml_file}: {e}")
        return []

def validate_yaml_content(content: List[Dict]) -> bool:
    required_keys = {"title", "id", "logsource", "detection"}
    for rule in content:
        if not required_keys.issubset(rule.keys()):
            logger.warning(f"Missing required keys in rule: {rule.get('title', 'Unnamed')}")
            return False
    return True

def calculate_file_hash(file_path: str) -> str:
    """
    Calculates the SHA-256 hash of a file.

    Args:
        file_path (str): The path to the file.

    Returns:
        str: The SHA-256 hash of the file.
    """
    hash_sha256 = sha256()
    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                hash_sha256.update(chunk)
    except Exception as e:
        logger.error(f"Error calculating hash for file {file_path}: {e}")
        return ""
    return hash_sha256.hexdigest()

def ensure_output_directory(output_dir: str) -> None:
    """
    Ensures the output directory exists. If it doesn't, it is created.

    Args:
        output_dir (str): The output directory where the file will be saved.

    Raises:
        Exception: If the directory cannot be created.
    """
    try:
        os.makedirs(output_dir, exist_ok=True)
        logger.info(f"Output directory ensured: {output_dir}")
    except Exception as e:
        logger.error(f"Failed to create output directory {output_dir}: {e}")
        raise

def generate_output_filename(base_name: str = "output", output_dir: str = "output_dir") -> str:
    """
    Generates a filename with the current date appended to the base name
    and ensures the output directory exists.

    Args:
        base_name (str): The base name for the output file.
        output_dir (str): Directory where the output file will be saved.

    Returns:
        str: The final output file path.
    """
    ensure_output_directory(output_dir)
    current_date = datetime.now().strftime("%Y-%m-%d")
    return os.path.join(output_dir, f"{base_name}_{current_date}.jsonl")

def date_converter(obj) -> str:
    """
    Converts date objects to ISO 8601 format for JSON serialization.

    Args:
        obj: The object to be serialized.

    Returns:
        str: ISO 8601 formatted date string.
    """
    if isinstance(obj, date):
        return obj.isoformat()
    raise TypeError(f"Type {type(obj)} is not serializable")

def process_yaml_file(
    yaml_file: str, 
    processed_hashes: Dict[str, str], 
    jsonl_file, 
    updated_hashes: Dict[str, str],
    error_files: List[str]
) -> None:
    """
    Processes a single YAML file: calculates its hash, checks if already processed, 
    converts its content to JSONL, and saves it.

    Args:
        yaml_file (str): The YAML file to process.
        processed_hashes (Dict[str, str]): The dictionary of processed file hashes.
        jsonl_file: The open JSONL file to write to.
        updated_hashes (Dict[str, str]): Dictionary to collect updated file hashes.
    """
    start_time = time.time()
    try:
        file_hash = calculate_file_hash(yaml_file)
        if processed_hashes.get(yaml_file) == file_hash:
            logger.info(f"Skipping already processed file: {yaml_file} (hash: {file_hash})")
            return

        content = load_yaml_file(yaml_file)
        if content:
            if not validate_yaml_content(content):
                logger.error(f"Validation failed for file {yaml_file}. Skipping...")
                return

            logger.info(f"Processing YAML file: {yaml_file} (hash: {file_hash})")
            for item in content:
                # item['file_hash'] = file_hash
                # item['process_date'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                # item['file_path'] = yaml_file
                # item['file_name'] = os.path.basename(yaml_file)
                # json.dump(item, jsonl_file, default=date_converter)
                # Extract only the title and description
                product = item.get('logsource', {}).get('product', None)
                category = item.get('logsource', {}).get('category', None)

                output_item = {
                    'title': item.get('title', None),
                    'status': item.get('status', None),
                    'description': item.get('description', None),
                    'references': item.get('references', None),
                    'date': item.get('date', None),
                    'modified': item.get('modified', None),
                    'tags': item.get('tags', None),
                    'product': product,
                    'category': category,
                    'logsource': f"{product}-{category}" if product and category else None,
                    'level': item.get('level', None),
                    'file_hash': file_hash,
                    'process_date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    'file_path': os.path.dirname(yaml_file),  # Only the directory path, not the file name
                    'file_name': os.path.basename(yaml_file)
                }

                # Dump the selected fields to the JSONL file
                with write_lock:
                    try:
                        json.dump(output_item, jsonl_file, default=date_converter, ensure_ascii=False)
                        jsonl_file.write("\n")
                    except Exception as e:
                        logger.error(f"Error writing JSON line: {e}, Item: {output_item}")

            updated_hashes[yaml_file] = file_hash
            logger.info(f"File {yaml_file} processed and hash recorded: {file_hash}")
    except Exception as e:
        logger.error(f"Failed to process file {yaml_file}: {e}")
        error_files.append(yaml_file)
    finally:
        elapsed_time = time.time() - start_time
        logger.info(f"File {yaml_file} processed in {elapsed_time:.2f} seconds.")

def load_and_process_yaml(
    yaml_files: List[str], 
    output_filename: str = "output.jsonl", 
    processed_hashes_filename: str = "sigma_hashes.json"
) -> None:
    """
    Processes a list of YAML files, converting them to JSONL format and saving the output.

    Args:
        yaml_files (List[str]): List of YAML file paths to process.
        output_filename (str): Output filename for JSONL.
        processed_hashes_filename (str): File storing processed hashes.
    """
    if not yaml_files:
        logger.warning("No YAML files to process.")
        return

    # Load previously processed hashes
    processed_hashes = {}
    if os.path.exists(processed_hashes_filename):
        try:
            with open(processed_hashes_filename, 'r', encoding='utf-8') as file:
                processed_hashes = json.load(file)
        except Exception as e:
            logger.error(f"Error loading processed hashes from {processed_hashes_filename}: {e}")

    updated_hashes = {}
    error_files = []

    # Open the JSONL file for appending
    try:
        with open(output_filename, 'a', encoding='utf-8') as jsonl_file:
            with ThreadPoolExecutor() as executor:
                for yaml_file in yaml_files:
                    executor.submit(
                        process_yaml_file,
                        yaml_file,
                        processed_hashes,
                        jsonl_file,
                        updated_hashes,
                        error_files
                    )
    except Exception as e:
        logger.error(f"Error opening output file {output_filename}: {e}")

    # Save updated hashes
    try:
        with open(processed_hashes_filename, 'w', encoding='utf-8') as file:
            json.dump({**processed_hashes, **updated_hashes}, file, ensure_ascii=False, indent=4)
            logger.info(f"Processed hashes updated and saved to {processed_hashes_filename}.")
    except Exception as e:
        logger.error(f"Error saving processed hashes to {processed_hashes_filename}: {e}")

    if error_files:
        logger.warning(f"The following files encountered errors during processing: {error_files}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Parse Sigma YAML files and convert them to JSONL format.")
    parser.add_argument(
        "--rules-dir", type=str, required=True,
        help="Root directory containing Sigma YAML files."
    )
    parser.add_argument(
        "--output-dir", type=str, default="output_dir",
        help="Directory to save the output JSONL file. (default: output_dir)"
    )
    parser.add_argument(
        "--exclude-paths", type=str, nargs="*",
        help="List of paths to exclude from processing."
    )

    args = parser.parse_args()

    rules_dir = args.rules_dir
    output_dir = args.output_dir
    exclude_paths = args.exclude_paths

    yaml_files = parse_yaml_files(rules_dir, exclude_paths)
    output_filename = generate_output_filename("sigma_output", output_dir)
    load_and_process_yaml(yaml_files, output_filename)
