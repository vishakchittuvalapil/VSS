# Vulnerability Scanning Service (VSS) Data - Cloud Guard Reports

Welcome to the repository for VSS data extracted from Oracle Cloud Infrastructure (OCI) Cloud Guard reports. This repository aims to provide insights into vulnerabilities and open ports detected on your OCI compute resources.The scripts will help you to download the output in csv and xlsx format which otherwise was not available in Cloud Guard and VSS.The scanned_host_open_ports.py script will just download the data from cloudguard of vss scanned host which has open port problems.The scanned_host_vulnerabilities.py will download the data from cloudguard of vsss scanned host which has vulnerabilties.The final vss_cloudguard_report_script.py will download both the data i.e open ports and vulnerabilities in 2 sheets on a single spreadsheet.Use whichever script depending on the data you require from Cloud Guard


## Prerequisites

To work with the data or scripts in this repository, ensure you have the following:

- Access to OCI Cloud Guard reports
- Access to CloudShell
- Python (3.8 or higher) installed
- Required Python packages:
  - `pandas`
  - `openpyxl`
  - `oci`

Install the packages using pip in CloudShell:

```bash
pip install --user openpyxl
pip install --user pandas
```

## Getting Started

### 1. Clone the Repository

```bash
git clone https://github.com/vishakchittuvalapil/VSS.git
cd VSS
```

### 2. Add Your Scripts in the Cloud Shell

Place the downloaded scripts in the respective folder on your cloud shell.

### 3. Run Analysis Scripts

Navigate to the `scripts` folder and execute the  scripts:
Eg:
```bash
python vss_cloudguard_report_script.py
```
### 4. Finally download the output from CLoudshell.
This script will generate insights and save them to the `visualizations/` folder.

## Sample Output

The repository includes sample reports and visualizations to give you an idea of the output:

- **Risk Breakdown**: Vulnerabilities categorized by severity.
- **Resource Trends**: Number of vulnerabilities detected per resource type.

## Contributing

Contributions are welcome! Feel free to open issues or submit pull requests to enhance the repository. Suggestions for new features, bug fixes, or additional visualizations are highly encouraged.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

For any questions or support, contact [Vishak Chittuvalapil](mailto:vishakchittuvalapil@gmail.com).
