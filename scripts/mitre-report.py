import json
from collections import Counter

# Specify the file path
file_path = r'output_dir/sigma-rule_2025-01-20.jsonl'  # Specify the file path here

# Variables to store MITRE Tactics, Techniques, and Sub-techniques information
mitre_tactics = []
mitre_techniques = []
mitre_sub_techniques = []
mitre_other_techniques = []
log_sources = []
levels = []

# Open the file and read line by line
print(f"Reading file: {file_path}")

# Normalization function (removes unwanted characters)
def normalize_tag(tag):
    return tag.replace("-", "_")  # Replaces "-" characters with "_"

try:
    with open(file_path, 'r') as f:
        for line in f:
            try:
                data = json.loads(line)  # Each line in JSONL file is a JSON object
                
                # Check if 'tags' key exists
                tags = data.get("tags", []) if data.get("tags") is not None else []

                # Separate MITRE Tactics, Techniques, and Sub-techniques
                for tag in tags:
                    normalized_tag = normalize_tag(tag)  # Normalize the tag

                    # Tactics: Tags containing 'attack.' with no numerical ID (e.g., attack.initial-access)
                    if "attack." in normalized_tag and normalized_tag.count('.') == 1 and not normalized_tag[8:].isdigit():
                        mitre_tactics.append(normalized_tag)
                    # Techniques: Tags containing 'attack.' with two dots (e.g., attack.execution)
                    elif "attack." in normalized_tag and normalized_tag.count('.') == 1:
                        mitre_techniques.append(normalized_tag)
                    # Sub-techniques: Tags containing 'attack.' with three or more dots (e.g., attack.t1218.003)
                    elif "attack." in normalized_tag and normalized_tag.count('.') >= 2:
                        mitre_sub_techniques.append(normalized_tag)
                    else:
                        mitre_other_techniques.append(normalized_tag)
                        
                # Extract Log Source Category
                if "logsource_category" in data:
                    log_sources.append(data["logsource_category"])
                
                # Extract Level information
                if "level" in data:
                    levels.append(data["level"])

            except json.JSONDecodeError as e:
                print(f"Error reading {file_path}: {e}")

except FileNotFoundError:
    print(f"File not found: {file_path}")

# Generate statistics for MITRE Tactics, Techniques, and Sub-techniques
tactic_counts = Counter(mitre_tactics)
technique_counts = Counter(mitre_techniques)
sub_technique_counts = Counter(mitre_sub_techniques)
other_technique_counts = Counter(mitre_other_techniques)
log_source_counts = Counter(log_sources)
level_counts = Counter(levels)

# Create HTML report
html_report = '''
<html>
<head>
    <title>MITRE Tactics and Techniques Report</title>
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
    </style>
</head>
<body>
    <div class="container">
        <h1>MITRE Tactics and Techniques Report</h1>
        
        <!-- Summary -->
        <div class="summary">
            <h2>Summary</h2>
            <p>This report contains statistical analysis of MITRE Tactics, Techniques, Sub-techniques, Log Sources, and Levels extracted from Sigma rules. Each section provides detailed counts and visualizations to help understand the distribution and frequency of security techniques.</p>
        </div>

        <!-- MITRE Tactics Table -->
        <h2>Top MITRE Tactics</h2>
        <div class="table-container">
            <table>
                <tr><th>Tactic</th><th>Count</th><th>Visualization</th></tr>
'''
# MITRE Tactics Chart - Adding visual progress bars
for tactic, count in tactic_counts.most_common():
    bar_length = (count / max(tactic_counts.values())) * 100
    html_report += f'''
                <tr>
                    <td>{tactic}</td>
                    <td>{count}</td>
                    <td>
                        <div class="progress-bar-container">
                            <div class="progress-bar" style="width: {bar_length}%; background-color: #28a745;"></div>
                        </div>
                    </td>
                </tr>
'''
html_report += '''
            </table>
        </div>

        <!-- MITRE Techniques Table -->
        <h2>Top MITRE Techniques</h2>
        <div class="table-container">
            <table>
                <tr><th>Technique</th><th>Count</th><th>Visualization</th></tr>
'''
for technique, count in technique_counts.most_common():
    bar_length = (count / max(technique_counts.values())) * 100
    html_report += f'''
                <tr>
                    <td>{technique}</td>
                    <td>{count}</td>
                    <td>
                        <div class="progress-bar-container">
                            <div class="progress-bar" style="width: {bar_length}%; background-color: #007bff;"></div>
                        </div>
                    </td>
                </tr>
'''
html_report += '''
            </table>
        </div>

        <!-- MITRE Sub-techniques Table -->
        <h2>Top MITRE Sub-techniques</h2>
        <div class="table-container">
            <table>
                <tr><th>Sub-technique</th><th>Count</th><th>Visualization</th></tr>
'''
for sub_technique, count in sub_technique_counts.most_common():
    bar_length = (count / max(sub_technique_counts.values())) * 100
    html_report += f'''
                <tr>
                    <td>{sub_technique}</td>
                    <td>{count}</td>
                    <td>
                        <div class="progress-bar-container">
                            <div class="progress-bar" style="width: {bar_length}%; background-color: #ffc107;"></div>
                        </div>
                    </td>
                </tr>
'''
html_report += '''
            </table>
        </div>

        <!-- Log Source Category Table -->
        <h2>Top Log Source Categories</h2>
        <div class="table-container">
            <table>
                <tr><th>Log Source Category</th><th>Count</th><th>Visualization</th></tr>
'''
for log_source, count in log_source_counts.most_common():
    bar_length = (count / max(log_source_counts.values())) * 100
    html_report += f'''
                <tr>
                    <td>{log_source}</td>
                    <td>{count}</td>
                    <td>
                        <div class="progress-bar-container">
                            <div class="progress-bar" style="width: {bar_length}%; background-color: #17a2b8;"></div>
                        </div>
                    </td>
                </tr>
'''

# MITRE Other Techniques Table
html_report += '''
        <!-- MITRE Other Techniques Table -->
        <h2>Other MITRE Techniques</h2>
        <div class="table-container">
            <table>
                <tr><th>Other Technique</th><th>Count</th><th>Visualization</th></tr>
'''
for other_technique, count in other_technique_counts.most_common():
    bar_length = (count / max(other_technique_counts.values())) * 100
    html_report += f'''
                <tr>
                    <td>{other_technique}</td>
                    <td>{count}</td>
                    <td>
                        <div class="progress-bar-container">
                            <div class="progress-bar" style="width: {bar_length}%; background-color: #dc3545;"></div>
                        </div>
                    </td>
                </tr>
'''
html_report += '''
            </table>
        </div>
'''

html_report += '''
            </table>
        </div>

        <!-- Levels Table -->
        <h2>Top Levels</h2>
        <div class="table-container">
            <table>
                <tr><th>Level</th><th>Count</th><th>Visualization</th></tr>
'''
for level, count in level_counts.most_common():
    bar_length = (count / max(level_counts.values())) * 100
    html_report += f'''
                <tr>
                    <td>{level}</td>
                    <td>{count}</td>
                    <td>
                        <div class="progress-bar-container">
                            <div class="progress-bar" style="width: {bar_length}%; background-color: #dc3545;"></div>
                        </div>
                    </td>
                </tr>
'''
html_report += '''
            </table>
        </div>

        <div class="footer">
            <p>Report generated using Sigma rules and MITRE ATT&CK framework data.</p>
        </div>
    </div>
</body>
</html>
'''

# Save the HTML report to a file
output_html_file = 'mitre_report.html'  # Specify the path where you want to save the HTML file
with open(output_html_file, 'w') as f:
    f.write(html_report)

output_html_file  # Return the file path
