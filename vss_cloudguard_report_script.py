#!/usr/bin/env python3
import os
import json
from collections import Counter

import oci
import pandas as pd

DEFAULT_REGION = "us-ashburn-1"
XLSX_OUT = "vss_cloudguard_problems.xlsx"

RULE_HOST_VULN = "SCANNED_HOST_VULNERABILITY"
RULE_CONTAINER_VULN = "SCANNED_CONTAINER_IMAGE_VULNERABILITY"
RULE_HOST_OPEN_PORTS = "SCANNED_HOST_OPEN_PORTS"
RULES = {RULE_HOST_VULN, RULE_CONTAINER_VULN, RULE_HOST_OPEN_PORTS}

SHEET_NAMES = {
    RULE_HOST_VULN: "Host_Vuln",
    RULE_CONTAINER_VULN: "Container_Vuln",
    RULE_HOST_OPEN_PORTS: "Host_Open_Ports",
}

COMMON_COLS = [
    "Problem OCID",
    "Detector Rule ID (list)",
    "Detector Rule ID (get)",
    "GetProblem Status",
    "GetProblem Error Code",
    "GetProblem Error Message",
    "Detector ID",
    "Risk Level",
    "Risk Score",
    "Lifecycle State",
    "Lifecycle Detail",
    "Region",
    "Compartment OCID",
    "Target OCID",
    "Resource OCID",
    "Resource Name",
    "Resource Type",
    "First Detected",
    "Last Detected",
    "Recommendation",
    "Description",
    "Labels",
]

HOST_VULN_KEYS = [
    "CVE Critical Count",
    "CVE High Count",
    "CVE Medium Count",
    "CVE Low Count",
    "Critical CVEs",
    "High CVEs",
    "Medium CVEs",
    "Low CVEs",
]

CONTAINER_ONLY_AD_KEYS = [
    "Number of Critical severity problems",
    "Number of High severity problems",
    "Number of Medium severity problems",
    "Number of Low severity problems",
    "Critical Severity Problems",
    "High Severity Problems",
    "Medium Severity Problems",
    "Low Severity Problems",
]

CONTAINER_VULN_KEYS = [
    "CVE Critical Count",
    "CVE High Count",
    "CVE Medium Count",
    "CVE Low Count",
    "Critical CVEs",
    "High CVEs",
    "Medium CVEs",
    "Low CVEs",
]

OPEN_PORT_KEYS = [
    "Open ports",
    "Disallowed ports list",
    "Allowed ports list",
]

EMPTY_MAP = {"": pd.NA, "None": pd.NA, "N/A": pd.NA, "null": pd.NA}


def ensure_region(cfg: dict) -> dict:
    if not cfg.get("region"):
        cfg["region"] = os.getenv("OCI_REGION") or os.getenv("OCI_DEFAULT_REGION") or DEFAULT_REGION
    return cfg


def dt_to_str(dt):
    return dt.isoformat() if dt else None


def to_cell(v):
    if v is None:
        return None
    if isinstance(v, (dict, list)):
        return json.dumps(v, ensure_ascii=False)
    return v


def list_all_problems(cg, tenancy_ocid):
    resp = oci.pagination.list_call_get_all_results(
        cg.list_problems,
        compartment_id=tenancy_ocid,
        compartment_id_in_subtree=True,
        access_level="ACCESSIBLE",
        limit=1000,
    ).data
    return resp.items if hasattr(resp, "items") else resp


def drop_all_empty_cols(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return df
    df = df.replace(EMPTY_MAP).infer_objects(copy=False)
    return df.dropna(axis=1, how="all")


def ensure_schema(df: pd.DataFrame, columns: list) -> pd.DataFrame:
    if df.empty:
        return pd.DataFrame(columns=columns)
    for c in columns:
        if c not in df.columns:
            df[c] = None
    return df[columns]


def get_add(add: dict, key: str):
    return to_cell((add or {}).get(key))


def base_row_from_list(p, list_rid: str):
    # Build the row primarily from LIST object (so we can still export even without get_problem)
    return {
        "Problem OCID": getattr(p, "id", None),
        "Detector Rule ID (list)": list_rid,
        "Detector Rule ID (get)": None,
        "GetProblem Status": None,
        "GetProblem Error Code": None,
        "GetProblem Error Message": None,
        "Detector ID": getattr(p, "detector_id", None),
        "Risk Level": getattr(p, "risk_level", None),
        "Risk Score": getattr(p, "risk_score", None),
        "Lifecycle State": getattr(p, "lifecycle_state", None),
        "Lifecycle Detail": getattr(p, "lifecycle_detail", None),
        "Region": getattr(p, "region", None),
        "Compartment OCID": getattr(p, "compartment_id", None),
        "Target OCID": getattr(p, "target_id", None),
        "Resource OCID": getattr(p, "resource_id", None),
        "Resource Name": getattr(p, "resource_name", None),
        "Resource Type": getattr(p, "resource_type", None),
        "First Detected": dt_to_str(getattr(p, "time_first_detected", None)),
        "Last Detected": dt_to_str(getattr(p, "time_last_detected", None)),
        "Recommendation": getattr(p, "recommendation", None),
        "Description": getattr(p, "description", None),
        "Labels": "; ".join(getattr(p, "labels", None) or []) or None,
    }


def main():
    cfg = ensure_region(oci.config.from_file())
    cg = oci.cloud_guard.CloudGuardClient(cfg)

    print(f"Using region: {cfg['region']}")
    print(f"Tenancy OCID: {cfg['tenancy']}")

    problems = list_all_problems(cg, cfg["tenancy"])
    print(f"Total problems returned: {len(problems)}")

    filtered = [p for p in problems if getattr(p, "detector_rule_id", None) in RULES]
    print(f"Matched target rule IDs (by list_problems): {len(filtered)}")

    list_rule_counts = Counter(getattr(p, "detector_rule_id", None) for p in filtered)
    print("Counts by list_problems detector_rule_id:")
    for k in [RULE_HOST_VULN, RULE_CONTAINER_VULN, RULE_HOST_OPEN_PORTS]:
        print(f"  {k}: {list_rule_counts.get(k, 0)}")

    host_vuln_rows, container_vuln_rows, host_open_ports_rows = [], [], []
    get_ok = 0
    get_fail = 0
    fail_codes = Counter()

    for i, p in enumerate(filtered, start=1):
        list_rid = getattr(p, "detector_rule_id", None)
        row = base_row_from_list(p, list_rid=list_rid)

        # Try to enrich via get_problem, but do not fail the whole report if unauthorized
        add = {}
        try:
            d = cg.get_problem(p.id).data
            row["Detector Rule ID (get)"] = getattr(d, "detector_rule_id", None)
            row["GetProblem Status"] = "OK"
            add = getattr(d, "additional_details", None) or {}
            get_ok += 1
        except oci.exceptions.ServiceError as e:
            row["GetProblem Status"] = "FAILED"
            row["GetProblem Error Code"] = getattr(e, "code", None)
            row["GetProblem Error Message"] = str(getattr(e, "message", ""))[:300]
            get_fail += 1
            fail_codes[getattr(e, "code", "UNKNOWN")] += 1

        # Classify based on LIST rule id (matches CLI)
        if list_rid == RULE_HOST_VULN:
            row.update({
                "CVE Critical Count": get_add(add, "CVE Critical Count") or get_add(add, "Number of Critical CVEs"),
                "CVE High Count":     get_add(add, "CVE High Count")     or get_add(add, "Number of High CVEs"),
                "CVE Medium Count":   get_add(add, "CVE Medium Count")   or get_add(add, "Number of Medium CVEs"),
                "CVE Low Count":      get_add(add, "CVE Low Count")      or get_add(add, "Number of Low CVEs"),
                "Critical CVEs":      get_add(add, "Critical CVEs"),
                "High CVEs":          get_add(add, "High CVEs"),
                "Medium CVEs":        get_add(add, "Medium CVEs"),
                "Low CVEs":           get_add(add, "Low CVEs"),
            })
            host_vuln_rows.append(row)

        elif list_rid == RULE_CONTAINER_VULN:
            for k in CONTAINER_ONLY_AD_KEYS:
                row[k] = get_add(add, k)

            row.update({
                "CVE Critical Count": get_add(add, "CVE Critical Count") or get_add(add, "Number of Critical CVEs"),
                "CVE High Count":     get_add(add, "CVE High Count")     or get_add(add, "Number of High CVEs"),
                "CVE Medium Count":   get_add(add, "CVE Medium Count")   or get_add(add, "Number of Medium CVEs"),
                "CVE Low Count":      get_add(add, "CVE Low Count")      or get_add(add, "Number of Low CVEs"),
                "Critical CVEs":      get_add(add, "Critical CVEs"),
                "High CVEs":          get_add(add, "High CVEs"),
                "Medium CVEs":        get_add(add, "Medium CVEs"),
                "Low CVEs":           get_add(add, "Low CVEs"),
            })
            container_vuln_rows.append(row)

        elif list_rid == RULE_HOST_OPEN_PORTS:
            row["Open ports"] = get_add(add, "Open ports") or get_add(add, "Open Ports")
            row["Disallowed ports list"] = get_add(add, "Disallowed ports list") or get_add(add, "Disallowed Ports List")
            row["Allowed ports list"] = get_add(add, "Allowed ports list") or get_add(add, "Allowed Ports List")
            host_open_ports_rows.append(row)

        if i % 50 == 0:
            print(f"Processed: {i}/{len(filtered)} (get_ok={get_ok}, get_fail={get_fail})")

    print(f"\nget_problem results: OK={get_ok}, FAILED={get_fail}")
    if fail_codes:
        print("Failure codes:")
        for code, cnt in fail_codes.most_common():
            print(f"  {code}: {cnt}")

    host_vuln_schema = COMMON_COLS + HOST_VULN_KEYS
    container_vuln_schema = COMMON_COLS + CONTAINER_ONLY_AD_KEYS + CONTAINER_VULN_KEYS
    open_ports_schema = COMMON_COLS + OPEN_PORT_KEYS

    host_vuln_df = drop_all_empty_cols(ensure_schema(pd.DataFrame(host_vuln_rows), host_vuln_schema))
    container_vuln_df = drop_all_empty_cols(ensure_schema(pd.DataFrame(container_vuln_rows), container_vuln_schema))
    open_ports_df = drop_all_empty_cols(ensure_schema(pd.DataFrame(host_open_ports_rows), open_ports_schema))

    with pd.ExcelWriter(XLSX_OUT, engine="openpyxl") as w:
        host_vuln_df.to_excel(w, sheet_name=SHEET_NAMES[RULE_HOST_VULN], index=False)
        container_vuln_df.to_excel(w, sheet_name=SHEET_NAMES[RULE_CONTAINER_VULN], index=False)
        open_ports_df.to_excel(w, sheet_name=SHEET_NAMES[RULE_HOST_OPEN_PORTS], index=False)

    print(
        f"\nWrote Excel: {XLSX_OUT} | "
        f"Host_Vuln={len(host_vuln_df)} rows, "
        f"Container_Vuln={len(container_vuln_df)} rows, "
        f"Host_Open_Ports={len(open_ports_df)} rows"
    )


if __name__ == "__main__":
    main()
