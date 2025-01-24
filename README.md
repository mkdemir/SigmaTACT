# SigmaTACT

<!-- markdownlint-disable MD033 -->

<p align="center">
    <img src="./assets/SigmaTACT_Logo.png" width="300" alt="SigmaTACT Logo">
</p>

SigmaTACT is a tool that converts Sigma rules into structured formats based on specific columns and generates actionable reports for enhanced threat visibility.

## 📚 Table of Contents

- [SigmaTACT](#sigmatact)
  - [📚 Table of Contents](#-table-of-contents)
  - [Introduction](#introduction)
  - [Features](#features)
  - [Installation](#installation)
  - [Usage](#usage)
    - [Convert Sigma Rules](#convert-sigma-rules)
    - [Generate a Report](#generate-a-report)
    - [Example Workflow](#example-workflow)
  - [Contributing](#contributing)
  - [License](#license)

## Introduction

SigmaTACT is designed to transform Sigma rules into structured data based on predefined columns (e.g., log sources, MITRE ATT&CK tactics/techniques, or other custom attributes). This structured data can then be analyzed to produce detailed reports, helping security teams identify threats more effectively and align their detections with organizational priorities.

## Features

- 🛠️ **Sigma Rule Transformation**: Convert Sigma rules into structured formats tailored to specific columns or attributes.
- 📊 **Advanced Reporting**: Generate detailed, visually rich reports from the converted data for analysis and decision-making.
- 🔄 **Support for Various Columns**: Organize rules by log source, tactic, technique, or other custom criteria.
- 🤝 **Seamless Integration**: Integrate with existing workflows and tools for smoother operations.

## Installation

To install SigmaTACT, clone the repository and install the necessary dependencies:

```bash
git clone https://github.com/yourusername/SigmaTACT.git
cd SigmaTACT
pip install -r requirements.txt
```

## Usage

SigmaTACT provides an easy-to-use interface to transform and analyze Sigma rules.

### Convert Sigma Rules

Use the following command to convert Sigma rules into a structured format based on specified columns:

```bash
python SigmaTACT-Converter.py --input-dir /path/to/sigma/rules --output-dir /path/to/output
```

### Generate a Report

After converting the rules, you can generate a detailed report:

```bash
python SigmaTACT-Report.py
```

### Example Workflow

1. **Conversion**: First, use `SigmaTACT-Converter.py` to transform the Sigma rules.
2. **Reporting**: Next, use `SigmaTACT-Report.py` to generate a report from the transformed data.

## Contributing

We welcome contributions to SigmaTACT! Whether it's reporting issues, suggesting new features, or submitting pull requests, your help is appreciated.

1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/your-feature`).
3. Commit your changes (`git commit -m "Add your feature"`).
4. Push to the branch (`git push origin feature/your-feature`).
5. Open a pull request.

## License

SigmaTACT is licensed under the [MIT License](./LICENSE). Feel free to use and modify it for your needs.

<p align="center">Happy Threat Hunting! 🛡️</p>
