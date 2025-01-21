import json
from collections import Counter

# Specify the file path
file_path = r'output_dir/sigma_output_2025-01-21.jsonl'  # Specify the file path here

# Variables to store MITRE Tactics, Techniques, and Sub-techniques information along with rule titles
mitre_tactics = []
mitre_techniques = []
mitre_sub_techniques = []
mitre_other_techniques = []
log_sources = []
levels = []
rule_titles = []  # List to store rule titles

# Open the file and read line by line
print(f"Reading file: {file_path}")

# Normalization function (removes unwanted characters)
def normalize_tag(tag):
    return tag.replace("-", "_")  # Replaces "-" characters with "_"

try:
    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            try:
                data = json.loads(line)  # Each line in JSONL file is a JSON object

                # Data validation
                if not isinstance(data, dict):
                    raise ValueError("Invalid data format: Expected a JSON object.")

                # Get rule title
                rule_title = data.get("title", "Unknown Title")  # Default to "Unknown Title" if no title exists
                rule_titles.append(rule_title)

                # Check if 'tags' key exists
                tags = data.get("tags", []) if data.get("tags") is not None else []

                # Separate MITRE Tactics, Techniques, and Sub-techniques
                for tag in tags:
                    normalized_tag = normalize_tag(tag)  # Normalize the tag

                    # Tactics: Tags containing 'attack.' with no numerical ID (e.g., attack.initial-access)
                    if "attack." in normalized_tag and normalized_tag.count('.') == 1 and not normalized_tag[8:].isdigit():
                        mitre_tactics.append((normalized_tag, rule_title))
                    # Techniques: Tags containing 'attack.' with two dots (e.g., attack.execution)
                    elif "attack." in normalized_tag and normalized_tag.count('.') == 1:
                        mitre_techniques.append((normalized_tag, rule_title))
                    # Sub-techniques: Tags containing 'attack.' with three or more dots (e.g., attack.t1218.003)
                    elif "attack." in normalized_tag and normalized_tag.count('.') >= 2:
                        mitre_sub_techniques.append((normalized_tag, rule_title))
                    else:
                        mitre_other_techniques.append((normalized_tag, rule_title))

                # Extract Log Source Category
                if "logsource" in data:
                    log_sources.append(data["logsource"])

                # Extract Level information
                if "level" in data:
                    levels.append(data["level"])

            except json.JSONDecodeError as e:
                print(f"Error reading {file_path}: {e}")
            except ValueError as e:
                print(f"Data validation error: {e}")

except FileNotFoundError:
    print(f"File not found: {file_path}")

# Generate statistics for MITRE Tactics, Techniques, and Sub-techniques
tactic_counts = Counter([tactic for tactic, _ in mitre_tactics])
technique_counts = Counter([technique for technique, _ in mitre_techniques])
sub_technique_counts = Counter([sub_technique for sub_technique, _ in mitre_sub_techniques])
other_technique_counts = Counter([other_technique for other_technique, _ in mitre_other_techniques])
log_source_counts = Counter(log_sources)
level_counts = Counter(levels)

# Add dynamic category filtering
def filter_by_category(category, data_list):
    return [item for item in data_list if category in item]

# Example dynamic filter usage
selected_category = "attack.execution"
filtered_techniques = filter_by_category(selected_category, mitre_techniques)

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
        <h1>MITRE Tactics and Techniques Report</h1>
        
        <!-- Summary -->
        <div class="summary">
            <h2>Summary</h2>
            <p>This report contains statistical analysis of MITRE Tactics, Techniques, Sub-techniques, Log Sources, and Levels extracted from Sigma rules. Each section provides detailed counts and visualizations to help understand the distribution and frequency of security techniques.</p>
        </div>

        <!-- MITRE Tactics Table -->
        <h2>Top MITRE Tactics</h2>
        <div class="table-container">
            <table id="tacticsTable" class="display">
                <thead><tr><th>Tactic</th><th>Count</th><th>Rule Title</th><th>Visualization</th></tr></thead>
                <tbody>
'''
# MITRE Tactics Chart - Adding visual progress bars with DataTables integration
for tactic, count in tactic_counts.most_common():
    bar_length = (count / max(tactic_counts.values())) * 100
    rule_titles_for_tactic = [title for tag, title in mitre_tactics if tag == tactic]

    # Taktik için uygun renk
    #color = category_colors.get(tactic, '#6c757d')  # Varsayılan gri renk
    html_report += f'''
                <tr>
                    <td>{tactic}</td>
                    <td>{count}</td>
                    <td>{', '.join(rule_titles_for_tactic)}</td>
                    <td>
                        <div class="progress-bar-container">
                            <div class="progress-bar" style="width: {bar_length}%; background-color: #28a745;"></div>
                        </div>
                    </td>
                </tr>
'''
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
    rule_titles_for_technique = [title for tag, title in mitre_techniques if tag == technique]
    html_report += f'''
                <tr>
                    <td>{technique}</td>
                    <td>{count}</td>
                    <td>{', '.join(rule_titles_for_technique)}</td>
                    <td>
                        <div class="progress-bar-container">
                            <div class="progress-bar" style="width: {bar_length}%; background-color: #007bff;"></div>
                        </div>
                    </td>
                </tr>
'''
html_report += '''
                </tbody>
            </table>
        </div>

        <!-- MITRE Sub-techniques Table -->
        <h2>Top MITRE Sub-techniques</h2>
        <div class="table-container">
            <table id="subTechniquesTable" class="display">
                <thead><tr><th>Sub-technique</th><th>Count</th><th>Rule Title</th><th>Visualization</th></tr></thead>
                <tbody>
'''
for sub_technique, count in sub_technique_counts.most_common():
    bar_length = (count / max(sub_technique_counts.values())) * 100
    rule_titles_for_sub_technique = [title for tag, title in mitre_sub_techniques if tag == sub_technique]
    html_report += f'''
                <tr>
                    <td>{sub_technique}</td>
                    <td>{count}</td>
                    <td>{', '.join(rule_titles_for_sub_technique)}</td>
                    <td>
                        <div class="progress-bar-container">
                            <div class="progress-bar" style="width: {bar_length}%; background-color: #ffc107;"></div>
                        </div>
                    </td>
                </tr>
'''
html_report += '''
                </tbody>
            </table>
        </div>

        <!-- Other Techniques Table -->
        <h2>Other Techniques</h2>
        <div class="table-container">
            <table id="otherTechniquesTable" class="display">
                <thead><tr><th>Other Technique</th><th>Count</th><th>Rule Title</th><th>Visualization</th></tr></thead>
                <tbody>
'''
for other_technique, count in other_technique_counts.most_common():
    bar_length = (count / max(other_technique_counts.values())) * 100
    rule_titles_for_other_technique = [title for tag, title in mitre_other_techniques if tag == other_technique]
    html_report += f'''
                <tr>
                    <td>{other_technique}</td>
                    <td>{count}</td>
                    <td>{', '.join(rule_titles_for_other_technique)}</td>
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

        <!-- Log Source Category Table -->
        <h2>Top Log Source Categories</h2>
        <input type="text" id="logSourcesFilter" onkeyup="filterTable('logSourcesTable', 'logSourcesFilter')" placeholder="Filter Log Sources...">
        <div class="table-container">
            <table id="logSourcesTable">
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
html_report += '''
            </table>
        </div>

        <!-- Levels Table -->
        <h2>Top Levels</h2>
        <input type="text" id="levelsFilter" onkeyup="filterTable('levelsTable', 'levelsFilter')" placeholder="Filter Levels...">
        <div class="table-container">
            <table id="levelsTable">
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
                </tbody>
            </table>
        </div>

        <!-- Footer -->
        <div class="footer">
            <p>Report generated using Sigma rules and MITRE ATT&CK framework data.</p>
        </div>
    </div>
</body>
</html>
'''

# Write the report to an HTML file
with open("advanced_mitre_report_main.html", "w", encoding="utf-8") as file:
    file.write(html_report)
print("Advanced Report with DataTables filtering generated successfully: advanced_mitre_report_main.html")
