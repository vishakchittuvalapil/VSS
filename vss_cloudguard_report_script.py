import oci
from datetime import datetime, timedelta
import pandas as pd

# Function to convert datetime with timezone to string in ISO format
def datetime_with_timezone_to_string(dt):
    if dt and hasattr(dt, 'tzinfo') and dt.tzinfo is not None:
        return dt.isoformat()  # Convert to ISO string with timezone info
    return dt.isoformat() if dt else None

# Load OCI configuration
config = oci.config.from_file()

# Get the current date and calculate the date 180 days ago
today = datetime.today()
first_date = today - timedelta(days=180)
print(f"Fetching problems detected since: {first_date}")

# Initialize the Cloud Guard client
cloud_guard_client = oci.cloud_guard.CloudGuardClient(config)

# Fetch all problems
list_problems_response = cloud_guard_client.list_problems(
    compartment_id=config['tenancy'],
    compartment_id_in_subtree=True,
    access_level="ACCESSIBLE",
    time_first_detected_greater_than_or_equal_to=first_date,
    limit=1000  # Adjust limit as needed
)

# Access the list of problems
problems = list_problems_response.data.items

# Filter problems for "Scanned host has vulnerabilities"
filtered_vulnerabilities = [
    problem for problem in problems
    if problem.detector_rule_id == "SCANNED_HOST_VULNERABILITY"
]

# Filter problems for "Scanned host has open ports"
filtered_open_ports = [
    problem for problem in problems
    if problem.detector_rule_id == "SCANNED_HOST_OPEN_PORTS"
]

# Initialize lists to hold rows for both sheets
vulnerabilities_data = []
open_ports_data = []

# Process "Scanned host has vulnerabilities"
for problem in filtered_vulnerabilities:
    # Fetch detailed problem information
    problem_details = cloud_guard_client.get_problem(problem.id).data

    # Extract relevant fields
    problem_ocid = problem_details.id
    resource_ocid = problem_details.resource_id
    resource_name = problem_details.resource_name
    resource_type = problem_details.resource_type
    risk_level = problem_details.risk_level
    status = problem_details.lifecycle_detail
    region = problem_details.region
    compartment_id = problem_details.compartment_id
    first_detected = datetime_with_timezone_to_string(problem_details.time_first_detected)
    last_detected = datetime_with_timezone_to_string(problem_details.time_last_detected)

    # CVE Details
    number_critical_cves = problem_details.additional_details.get("Number of Critical CVEs", "0")
    number_high_cves = problem_details.additional_details.get("Number of High CVEs", "0")
    number_medium_cves = problem_details.additional_details.get("Number of Medium CVEs", "0")
    number_low_cves = problem_details.additional_details.get("Number of Low CVEs", "0")

    critical_cves = problem_details.additional_details.get("Critical CVEs", "[]")
    high_cves = problem_details.additional_details.get("High CVEs", "[]")
    medium_cves = problem_details.additional_details.get("Medium CVEs", "[]")
    low_cves = problem_details.additional_details.get("Low CVEs", "[]")

    # Recommendation and Description
    recommendation = problem_details.recommendation or "No recommendation available"
    description = problem_details.description or "No description available"

    # Additional fields
    lifecycle_state = problem_details.lifecycle_state
    labels = "; ".join(problem_details.labels) if problem_details.labels else "None"
    detector_id = problem_details.detector_id

    # Add row to vulnerabilities data
    vulnerabilities_data.append([
        problem_ocid, resource_ocid, resource_name, resource_type, 
        risk_level, status, region, compartment_id, 
        first_detected, last_detected, number_critical_cves, 
        number_high_cves, number_medium_cves, number_low_cves, 
        critical_cves, high_cves, medium_cves, low_cves, 
        recommendation, description, lifecycle_state, labels, detector_id
    ])

# Process "Scanned host has open ports"
for problem in filtered_open_ports:
    # Fetch detailed problem information
    problem_details = cloud_guard_client.get_problem(problem.id).data

    # Extract relevant fields
    problem_ocid = problem_details.id
    resource_ocid = problem_details.resource_id
    resource_name = problem_details.resource_name
    resource_type = problem_details.resource_type
    risk_level = problem_details.risk_level
    status = problem_details.lifecycle_detail
    region = problem_details.region
    compartment_id = problem_details.compartment_id
    first_detected = datetime_with_timezone_to_string(problem_details.time_first_detected)
    last_detected = datetime_with_timezone_to_string(problem_details.time_last_detected)

    # Extract additional details
    additional_details = problem_details.additional_details or {}
    open_ports = additional_details.get("Open ports", "N/A")
    disallowed_ports = additional_details.get("Disallowed ports list", "N/A")

    # Recommendation and Description
    recommendation = problem_details.recommendation or "No recommendation available"
    description = problem_details.description or "No description available"

    # Additional fields
    lifecycle_state = problem_details.lifecycle_state
    labels = "; ".join(problem_details.labels) if problem_details.labels else "None"
    detector_id = problem_details.detector_id

    # Add row to open ports data
    open_ports_data.append([
        problem_ocid, resource_ocid, resource_name, resource_type, 
        risk_level, status, region, compartment_id, 
        first_detected, last_detected, open_ports, 
        disallowed_ports, recommendation, 
        description, lifecycle_state, labels, detector_id
    ])

# Convert lists to DataFrames for Excel export
vulnerabilities_df = pd.DataFrame(vulnerabilities_data, columns=[
    "Problem OCID", "Resource OCID", "Resource Name", "Resource Type", 
    "Risk Level", "Status", "Region", "Compartment", 
    "First Detected", "Last Detected", "Number of Critical CVEs", 
    "Number of High CVEs", "Number of Medium CVEs", "Number of Low CVEs", 
    "Critical CVEs", "High CVEs", "Medium CVEs", "Low CVEs", 
    "Recommendation", "Description", "Lifecycle State", "Labels", "Detector ID"
])

open_ports_df = pd.DataFrame(open_ports_data, columns=[
    "Problem OCID", "Resource OCID", "Resource Name", "Resource Type", 
    "Risk Level", "Status", "Region", "Compartment", 
    "First Detected", "Last Detected", "Open Ports", 
    "Disallowed Ports", "Recommendation", 
    "Description", "Lifecycle State", "Labels", "Detector ID"
])

# Save both DataFrames to an Excel file with separate sheets
output_file = "detailed_problem_report.xlsx"
with pd.ExcelWriter(output_file, engine='openpyxl') as writer:
    vulnerabilities_df.to_excel(writer, sheet_name='Vulnerabilities', index=False)
    open_ports_df.to_excel(writer, sheet_name='Open Ports', index=False)

print(f"Script executed successfully. Excel report saved as {output_file}")
