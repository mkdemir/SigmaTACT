import glob
import os
import sys
import json
from collections import Counter
from datetime import datetime

def print_banner():
    """Prints a formatted banner with script details."""
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    RESET = "\033[0m"

    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print(CYAN + "=" * 60 + RESET)
    print(GREEN + "             MITRE Report Script".center(60) + RESET)
    print(GREEN + "          Developed by Mustafa Kaan Demir".center(60) + RESET)
    print(GREEN + f"          Version: 1.0.0".center(60) + RESET)
    print(GREEN + f"          Date: {current_time}".center(60) + RESET)
    print(CYAN + "=" * 60 + RESET)
    print("\nInitializing the script...\n")

def find_files(output_dir, pattern):
    """Find files matching a specific pattern in the given directory."""
    file_pattern = os.path.join(output_dir, pattern)
    return glob.glob(file_pattern)

def read_jsonl_file(file_path):
    """Reads a JSONL file and returns a list of parsed JSON objects."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return [json.loads(line) for line in f]
    except FileNotFoundError:
        print(f"[-] File not found: {file_path}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"[-] Error decoding JSON in file {file_path}: {e}")
        sys.exit(1)

def analyze_data(data):
    """Analyzes data to extract MITRE tactics, techniques, and related information."""
    mitre_tactics = []
    mitre_techniques = []
    mitre_sub_techniques = []
    mitre_other_techniques = []
    log_sources = []
    levels = []
    rule_titles = []
    descriptions = []
    dates = []
    references = []

    def normalize_tag(tag):
        return tag.replace("-", "_")

    for entry in data:
        # Extract the rule title
        rule_title = entry.get("title", "Unknown Title")
        rule_titles.append(rule_title)

        # Extract the description
        description = entry.get("description", "No description available")
        descriptions.append(description)
        
        # Extract the modification date
        date = entry.get("date", "Unknown Date")
        dates.append(date)

        # Extract the references
        reference_list = entry.get("references", ["No references provided"])
        references.append(", ".join(reference_list) if isinstance(reference_list, list) else str(reference_list))

        # Extract and normalize tags
        tags = entry.get("tags", [])

        if not isinstance(tags, list):
            tags = []  # Ensure tags is always a list

        for tag in tags:
            normalized_tag = normalize_tag(tag)

            # Categorize tags as tactics, techniques, or others
            if "attack." in normalized_tag and normalized_tag.count('.') == 1 and not normalized_tag[8:].isdigit():
                mitre_tactics.append((normalized_tag, rule_title, entry.get("level", "Unknown Level"), description, date, references))
            elif "attack." in normalized_tag and normalized_tag.count('.') == 1:
                mitre_techniques.append((normalized_tag, rule_title, entry.get("level", "Unknown Level"), description, date, references))
            elif "attack." in normalized_tag and normalized_tag.count('.') >= 2:
                mitre_sub_techniques.append((normalized_tag, rule_title, entry.get("level", "Unknown Level"), description, date, references))
            else:
                mitre_other_techniques.append((normalized_tag, rule_title, entry.get("level", "Unknown Level"), description, date, references))

        # Extract log source category
        if "logsource" in entry:
            log_sources.append(entry["logsource"])

        # Extract level information
        if "level" in entry:
            levels.append(entry["level"])


    return {
        "tactics": mitre_tactics,
        "techniques": mitre_techniques,
        "sub_techniques": mitre_sub_techniques,
        "other_techniques": mitre_other_techniques,
        "log_sources": log_sources,
        "levels": levels,
        "rule_titles": rule_titles,
        "descriptions": descriptions,
        "date": dates,
        "references": references,
    }

def generate_html_report(data, output_file):
    """Generates an HTML report from the analyzed data."""
    # Generate statistics for MITRE Tactics, Techniques, and Sub-techniques
    tactic_counts = Counter([tactic for tactic, _, _, _, _, _ in data["tactics"]])
    technique_counts = Counter([technique for technique, _, _, _, _, _ in data["techniques"]])
    sub_technique_counts = Counter([sub_technique for sub_technique, _, _, _, _, _ in data["sub_techniques"]])
    other_technique_counts = Counter([other_technique for other_technique, _, _, _, _, _ in data["other_techniques"]])
    log_source_counts = Counter(data["log_sources"])
    level_counts = Counter(data["levels"])

    # Add dynamic category filtering
    def filter_by_category(category, data_list):
        return [item for item in data_list if category in item]

    # Create HTML report with dynamic filtering functionality
    html_report = '''
    <html>
    <head>
        <title>MITRE Tactics and Techniques Report</title>
        <link rel="stylesheet" type="text/css" href="https://cdn.datatables.net/1.12.1/css/jquery.dataTables.min.css">
        <style>
            body { 
                font-family: 'Helvetica Neue', Arial, sans-serif; 
                margin: 0; 
                padding: 0; 
                background-color: #f4f7fb;
            }
            .container {
                width: 90%; 
                max-width: 1200px;
                margin: 30px auto; 
                background-color: white; 
                padding: 30px; 
                border-radius: 8px;
                box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
            }
            h1 {
                color: #343a40;
                font-size: 40px;
                font-weight: 600;
                text-align: center;
                margin-bottom: 20px;
            }
            h2 {
                color: #007bff;
                font-size: 28px;
                margin-bottom: 15px;
                border-bottom: 2px solid #007bff;
                padding-bottom: 8px;
            }
            .table-container {
                margin-top: 20px;
            }
            table {
                width: 100%; 
                border-collapse: collapse;
            }
            th, td {
                padding: 12px; 
                text-align: left; 
                border-bottom: 1px solid #dee2e6;
                font-size: 16px;
            }
            th {
                background-color: #007bff;
                color: white;
                font-weight: 600;
            }
            tr:nth-child(even) {
                background-color: #f9f9f9;
            }
            tr:hover {
                background-color: #f1f1f1;
            }
            .progress-bar-container {
                height: 30px;
                width: 100%;
                background-color: #e0e0e0;
                border-radius: 5px;
            }
            .progress-bar {
                height: 100%;
                border-radius: 5px;
            }
            .footer {
                text-align: center;
                margin-top: 50px;
                font-size: 14px;
                color: #6c757d;
            }
            .summary {
                background-color: #e9ecef;
                padding: 20px;
                border-radius: 8px;
                margin-bottom: 30px;
            }
            .summary p {
                margin: 0;
                font-size: 16px;
            }
            input[type="text"] {
                width: 100%;
                padding: 8px;
                margin: 10px 0;
                border: 1px solid #ccc;
                border-radius: 4px;
            }
        </style>
        <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
        <script src="https://cdn.datatables.net/1.12.1/js/jquery.dataTables.min.js"></script>
        <script>
            $(document).ready(function() {
                $('#tacticsTable').DataTable();
                $('#techniquesTable').DataTable();
                $('#subTechniquesTable').DataTable();
                $('#otherTechniquesTable').DataTable();
                $('#logSourcesTable').DataTable();
                $('#levelsTable').DataTable();
                $('#rulesTable').DataTable();
            });
            // Dinamik renkler için kategori eşlemeleri
            const category_colors = {
                'attack.execution': '#28a745',  // Green
                'attack.privilege-escalation': '#007bff',  // Blue
                'attack.persistent-access': '#ffc107',  // Yellow
                'attack.initial-access': '#dc3545',  // Red
                // Daha fazla kategori ekleyebilirsiniz
            };
            function filterTable(tableId, inputId) {
                var input, filter, table, tr, td, i, txtValue;
                input = document.getElementById(inputId);
                filter = input.value.toUpperCase();
                table = document.getElementById(tableId);
                tr = table.getElementsByTagName("tr");

                for (i = 0; i < tr.length; i++) {
                    td = tr[i].getElementsByTagName("td")[0]; // First column is used for filtering
                    if (td) {
                        txtValue = td.textContent || td.innerText;
                        if (txtValue.toUpperCase().indexOf(filter) > -1) {
                            tr[i].style.display = "";
                        } else {
                            tr[i].style.display = "none";
                        }
                    }
                }
            }
        </script>
    </head>
    <body>
        <div class="container">
            <h1>SigmaTACT - MITRE Tactics and Techniques Report</h1>
            
            <!-- Summary -->
            <div class="summary">
                <h2>Summary</h2>
                <p>This report contains statistical analysis of MITRE Tactics, Techniques, Sub-techniques, Log Sources, and Levels extracted from Sigma rules. Each section provides detailed counts and visualizations to help understand the distribution and frequency of security techniques.</p>
                <br>
                <br>
                <p><strong>Total Rules Processed: </strong>''' + str(len(data["rule_titles"])) + '''</p>
                <br>
                <p><strong>Total Mitre Tactics Processed: </strong>''' + str(len(tactic_counts)) + '''</p>
                <br>
                <p><strong>Total Mitre Techniques Processed: </strong>''' + str(len(technique_counts)) + '''</p>
                <br>
                <p><strong>Total Mitre Sub Techniques Processed: </strong>''' + str(len(sub_technique_counts)) + '''</p>
                <br>
                <p><strong>Total Mitre Other Techniques Processed: </strong>''' + str(len(other_technique_counts)) + '''</p>
                <br>
                <p><strong>Total Log Sources Processed: </strong>''' + str(len(log_source_counts)) + '''</p>
            </div>

            <!-- MITRE Tactics Table -->
            <h2>Top MITRE Tactics</h2>
            <div class="table-container">
                <table id="tacticsTable" class="display">
                    <thead><tr><th>Tactic</th><th>Count</th><th>Rule Title</th><th>Visualization</th></tr></thead>
                    <tbody>
    '''

    # MITRE Tactics Table - Adding visual progress bars with DataTables integration
    for tactic, count in tactic_counts.most_common():
        bar_length = (count / max(tactic_counts.values())) * 100
        rule_details_for_tactic = [(title, level, description, date, references) for tag, title, level, description, date, references in data["tactics"] if tag == tactic]

        html_report += f'''
                    <tr>
                        <td>{tactic}</td>
                        <td>{count}</td>
                        <td>
                            <details style="cursor: pointer;">
                                <summary>Show Rules ({len(rule_details_for_tactic)})</summary>
                                <br>
                                <ul style="margin: 0; padding: 0 0 0 15px;">
                                    {''.join(f"<li style='list-style-type: circle;'>{title} - Level: {level}<br>Description: {description}<br></li>" for title, level, description, date, references in rule_details_for_tactic)}
                                </ul>
                            </details>
                        </td>             
                        <td>
                            <div class="progress-bar-container">
                                <div class="progress-bar" style="width: {bar_length}%; background-color: #28a745;"></div>
                            </div>
                        </td>
                    </tr>
    '''

    # MITRE Techniques Table
    html_report += '''
                    </tbody>
                </table>
            </div>

            <!-- MITRE Techniques Table -->
            <h2>Top MITRE Techniques</h2>
            <div class="table-container">
                <table id="techniquesTable" class="display">
                    <thead><tr><th>Technique</th><th>Count</th><th>Rule Title</th><th>Visualization</th></tr></thead>
                    <tbody>
    '''
    for technique, count in technique_counts.most_common():
        bar_length = (count / max(technique_counts.values())) * 100
        rule_details_for_technique = [(title, level, description, date, references) for tag, title, level, description, date, references in data["techniques"] if tag == technique]

        html_report += f'''
                    <tr>
                        <td>{technique}</td>
                        <td>{count}</td>
                        <td>
                            <details style="cursor: pointer;">
                                <summary>Show Rules ({len(rule_details_for_technique)})</summary>
                                <br>
                                <ul style="margin: 0; padding: 0 0 0 15px;">
                                    {''.join(f"<li style='list-style-type: circle;'>{title} - Level: {level}<br>Description: {description}<br></li>" for title, level, description, date, references in rule_details_for_technique)}
                                </ul>
                            </details>
                        </td>             
                        <td>
                            <div class="progress-bar-container">
                                <div class="progress-bar" style="width: {bar_length}%; background-color: #007bff;"></div>
                            </div>
                        </td>
                    </tr>
    '''

    # MITRE Sub-Techniques Table
    html_report += '''
                    </tbody>
                </table>
            </div>

            <!-- MITRE Sub-Techniques Table -->
            <h2>Top MITRE Sub-Techniques</h2>
            <div class="table-container">
                <table id="subTechniquesTable" class="display">
                    <thead><tr><th>Sub-Technique</th><th>Count</th><th>Rule Title</th><th>Visualization</th></tr></thead>
                    <tbody>
    '''
    for sub_technique, count in sub_technique_counts.most_common():
        bar_length = (count / max(sub_technique_counts.values())) * 100
        rule_details_for_sub_technique = [(title, level, description, date, references) for tag, title, level, description, date, references in data["sub_techniques"] if tag == sub_technique]

        html_report += f'''
                    <tr>
                        <td>{sub_technique}</td>
                        <td>{count}</td>
                        <td>
                            <details style="cursor: pointer;">
                                <summary>Show Rules ({len(rule_details_for_sub_technique)})</summary>
                                <br>
                                <ul style="margin: 0; padding: 0 0 0 15px;">
                                    {''.join(f"<li style='list-style-type: circle;'>{title} - Level: {level}<br>Description: {description}<br></li>" for title, level, description, date, references in rule_details_for_sub_technique)}
                                </ul>
                            </details>
                        </td>             
                        <td>
                            <div class="progress-bar-container">
                                <div class="progress-bar" style="width: {bar_length}%; background-color: #ffc107;"></div>
                            </div>
                        </td>
                    </tr>
    '''

    # MITRE Other Techniques Table
    html_report += '''
                    </tbody>
                </table>
            </div>

            <!-- MITRE Other Techniques Table -->
            <h2>Top MITRE Other Techniques</h2>
            <div class="table-container">
                <table id="otherTechniquesTable" class="display">
                    <thead><tr><th>Other Technique</th><th>Count</th><th>Rule Title</th><th>Visualization</th></tr></thead>
                    <tbody>
    '''
    for other_technique, count in other_technique_counts.most_common():
        bar_length = (count / max(other_technique_counts.values())) * 100
        rule_details_for_other_technique = [(title, level, description, date, references) for tag, title, level, description, date, references in data["other_techniques"] if tag == other_technique]

        html_report += f'''
                    <tr>
                        <td>{other_technique}</td>
                        <td>{count}</td>
                        <td>
                            <details style="cursor: pointer;">
                                <summary>Show Rules ({len(rule_details_for_other_technique)})</summary>
                                <br>
                                <ul style="margin: 0; padding: 0 0 0 15px;">
                                    {''.join(f"<li style='list-style-type: circle;'>{title} - Level: {level}<br>Description: {description}<br></li>" for title, level, description, date, references in rule_details_for_other_technique)}
                                </ul>
                            </details>
                        </td>             
                        <td>
                            <div class="progress-bar-container">
                                <div class="progress-bar" style="width: {bar_length}%; background-color: #6c757d;"></div>
                            </div>
                        </td>
                    </tr>
    '''
    # Log Source Category Table
    html_report += '''
                    </tbody>
                </table>
            </div>

            <!-- Log Source Category Table -->
            <h2>Top Log Source Categories</h2>
            <div class="table-container">
                <table id="logSourcesTable" class="display">
                    <thead><tr><th>Log Source Category</th><th>Count</th><th>Rule Title</th><th>Visualization</th></tr></thead>
                    <tbody>
    '''
    for log_source, count in log_source_counts.most_common():
        bar_length = (count / max(log_source_counts.values())) * 100
        rule_titles_for_log_source = [title for src, title in zip(data["log_sources"], data["rule_titles"]) if src == log_source]
        html_report += f'''
                    <tr>
                        <td>{log_source}</td>
                        <td>{count}</td>
                        <td>{', '.join(rule_titles_for_log_source)}</td>
                        <td>
                            <div class="progress-bar-container">
                                <div class="progress-bar" style="width: {bar_length}%; background-color: #17a2b8;"></div>
                            </div>
                        </td>
                    </tr>
    '''
    # Top Levels Table
    html_report += '''
                    </tbody>
                </table>
            </div>

            <!-- Levels Table -->
            <h2>Top Levels</h2>
            <div class="table-container">
                <table id="levelsTable" class="display">
                    <thead><tr><th>Level</th><th>Count</th><th>Rule Title</th><th>Visualization</th></tr></thead>
                    <tbody>
    '''
    for level, count in level_counts.most_common():
        bar_length = (count / max(level_counts.values())) * 100
        rule_titles_for_level = [title for lvl, title in zip(data["levels"], data["rule_titles"]) if lvl == level]
        html_report += f'''
                    <tr>
                        <td>{level}</td>
                        <td>{count}</td>
                        <td>{', '.join(rule_titles_for_level)}</td>
                        <td>
                            <div class="progress-bar-container">
                                <div class="progress-bar" style="width: {bar_length}%; background-color: #dc3545;"></div>
                            </div>
                        </td>
                    </tr>
    '''
    # Rule Details Table
    html_report += '''
                    </tbody>
                </table>
            </div>

            <!-- Rule Details Section -->
            <h2>Rule Details</h2>
            <div class="table-container" style="overflow-x: auto;">
                <table id="rulesTable" class="display">
                    <thead><tr><th>Rule Title</th><th>Description</th><th>References</th></tr></thead>
                    <tbody>
                    <!-- Rule rows will be added dynamically here -->
    '''
    # Populate the table rows with rule data
    for rule_title, description, reference in zip(data["rule_titles"], data["descriptions"], data["references"]):
        html_report += f'''
                <tr>
                    <td>{rule_title}</td>
                    <td>{description}</td>
                    <td>{reference}</td>
                </tr>
    '''

    html_report += '''
                    </tbody>
                </table>
            </div>
    </div>
            <!-- Footer -->
            <div class="footer">
                <p>Report generated using Sigma rules and MITRE ATT&CK framework data.</p>
                <p><strong>Generated on:</strong> <span id="report-date"></span></p>
                <p><a href="https://www.mitre.org/attack-framework" target="_blank">Learn more about MITRE ATT&CK Framework</a></p>
                <p>&copy; 2025 mkdemir all rights reserved.</p>
            </div>

            <script>
                // Dynamically set the report generation date
                document.getElementById('report-date').textContent = new Date().toLocaleString();
            </script>
        </div>
    </body>
    </html>
    '''

    # Write the HTML report to the output file
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html_report)
    print(f"[+] Report generated successfully: {output_file}")

def main():
    print_banner()

    # Define the output directory and file pattern
    output_dir = 'output_dir'
    matching_files = find_files(output_dir, 'sigma_output_*.jsonl')

    # Exit if no matching files are found
    if not matching_files:
        print("[-] No matching files found.")
        sys.exit(1)

    # Select the first matching file
    file_path = matching_files[0]
    print(f"[+] File path selected: {file_path}")

    # Read and analyze the data
    data = read_jsonl_file(file_path)
    analyzed_data = analyze_data(data)

    # Generate the HTML report
    current_date = datetime.now().strftime("%Y-%m-%d")
    output_file = f"SIGMA_MITRE_{current_date}.html"
    generate_html_report(analyzed_data, output_file)

if __name__ == "__main__":
    main()
