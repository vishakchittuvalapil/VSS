import oci
from datetime import datetime, timedelta
import csv

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

# Filter problems for "Scanned host has open ports"
filtered_problems = [
    problem for problem in problems
    if problem.detector_rule_id == "SCANNED_HOST_OPEN_PORTS"  # Ensure correct detector rule ID
]

# Prepare CSV output file
output_file = "detailed_problem_report_open_ports.csv"
with open(output_file, mode="w", newline="") as csv_file:
    csv_writer = csv.writer(csv_file)
    
    # Write CSV header
    csv_writer.writerow([
        "Problem OCID", "Resource OCID", "Resource Name", "Resource Type", 
        "Risk Level", "Status", "Region", "Compartment", 
        "First Detected", "Last Detected", "Open Ports", 
        "Disallowed Ports", "Recommendation", 
        "Description", "Lifecycle State", "Labels", "Detector ID"
    ])
    
    # Process each problem and fetch detailed information
    for problem in filtered_problems:
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
        first_detected = problem_details.time_first_detected
        last_detected = problem_details.time_last_detected

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

        # Write details to CSV
        csv_writer.writerow([
            problem_ocid, resource_ocid, resource_name, resource_type, 
            risk_level, status, region, compartment_id, 
            first_detected, last_detected, open_ports, 
            disallowed_ports, recommendation, 
            description, lifecycle_state, labels, detector_id
        ])

print(f"Script executed successfully. CSV report saved as {output_file}")
