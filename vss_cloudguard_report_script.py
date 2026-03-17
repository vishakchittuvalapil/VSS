#!/usr/bin/env python3
import os, json
import oci
import pandas as pd

# ---- Detector rules to export ----
RULE_HOST_VULN = "SCANNED_HOST_VULNERABILITY"
RULE_CONTAINER_VULN = "SCANNED_CONTAINER_IMAGE_VULNERABILITY"
RULE_HOST_OPEN_PORTS = "SCANNED_HOST_OPEN_PORTS"
RULES = {RULE_HOST_VULN, RULE_CONTAINER_VULN, RULE_HOST_OPEN_PORTS}

# ---- Output ----
XLSX_OUT = "cloudguard_problems.xlsx"

# Excel sheet names must be <= 31 chars
SHEET_NAMES = {
    RULE_HOST_VULN: "Host_Vuln",
    RULE_CONTAINER_VULN: "Container_Vuln",
    RULE_HOST_OPEN_PORTS: "Host_Open_Ports",
}

# ---- Common columns on all sheets ----
COMMON_COLS = [
    "Problem OCID",
    "Detector Rule ID",
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

# ---- Host vulnerability CVE columns (order as you like) ----
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

# ---- Container sheet: alignment you requested (container-only fields) ----
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

# Optional: keep CVE columns on Container sheet too (set [] to remove them)
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

# ---- Host open ports columns ----
OPEN_PORT_KEYS = [
    "Open ports",
    "Disallowed ports list",
    "Allowed ports list",
]

EMPTY_MAP = {"": pd.NA, "None": pd.NA, "N/A": pd.NA, "null": pd.NA}


def ensure_region(cfg: dict) -> dict:
    if not cfg.get("region"):
        cfg["region"] = os.getenv("OCI_REGION") or os.getenv("OCI_DEFAULT_REGION") or "us-ashburn-1"
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
    data = oci.pagination.list_call_get_all_results(
        cg.list_problems,
        compartment_id=tenancy_ocid,
        compartment_id_in_subtree=True,
        access_level="ACCESSIBLE",
        limit=1000,
    ).data
    return data.items if hasattr(data, "items") else data


def base_row(d):
    return {
        "Problem OCID": d.id,
        "Detector Rule ID": getattr(d, "detector_rule_id", None),
        "Detector ID": getattr(d, "detector_id", None),
        "Risk Level": getattr(d, "risk_level", None),
        "Risk Score": getattr(d, "risk_score", None),
        "Lifecycle State": getattr(d, "lifecycle_state", None),
        "Lifecycle Detail": getattr(d, "lifecycle_detail", None),
        "Region": getattr(d, "region", None),
        "Compartment OCID": getattr(d, "compartment_id", None),
        "Target OCID": getattr(d, "target_id", None),
        "Resource OCID": getattr(d, "resource_id", None),
        "Resource Name": getattr(d, "resource_name", None),
        "Resource Type": getattr(d, "resource_type", None),
        "First Detected": dt_to_str(getattr(d, "time_first_detected", None)),
        "Last Detected": dt_to_str(getattr(d, "time_last_detected", None)),
        "Recommendation": getattr(d, "recommendation", None),
        "Description": getattr(d, "description", None),
        "Labels": "; ".join(getattr(d, "labels", None) or []) or None,
    }


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


def main():
    cfg = ensure_region(oci.config.from_file())
    cg = oci.cloud_guard.CloudGuardClient(cfg)

    print(f"Using region: {cfg['region']}")

    problems = list_all_problems(cg, cfg["tenancy"])
    filtered = [p for p in problems if getattr(p, "detector_rule_id", None) in RULES]

    print(f"Total problems returned: {len(problems)}")
    print(f"Matched target rule IDs: {len(filtered)}")

    host_vuln_rows, container_vuln_rows, host_open_ports_rows = [], [], []

    for i, p in enumerate(filtered, start=1):
        d = cg.get_problem(p.id).data
        add = d.additional_details or {}
        rid = getattr(d, "detector_rule_id", None)

        row = base_row(d)

        if rid == RULE_HOST_VULN:
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

        elif rid == RULE_CONTAINER_VULN:
            # Container-only columns in EXACT order you requested
            for k in CONTAINER_ONLY_AD_KEYS:
                col = k if k not in row else f"Additional - {k}"
                row[col] = get_add(add, k)

            # Optional container CVE columns (same order as Host_Vuln)
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

        elif rid == RULE_HOST_OPEN_PORTS:
            # keys vary slightly; try common variants
            row["Open ports"] = get_add(add, "Open ports") or get_add(add, "Open Ports")
            row["Disallowed ports list"] = get_add(add, "Disallowed ports list") or get_add(add, "Disallowed Ports List")
            row["Allowed ports list"] = get_add(add, "Allowed ports list") or get_add(add, "Allowed Ports List")
            host_open_ports_rows.append(row)

        if i % 50 == 0:
            print(f"Fetched details: {i}/{len(filtered)}")

    # ---- Per-sheet schema/order ----
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
        f"Wrote Excel: {XLSX_OUT} | "
        f"Host_Vuln={len(host_vuln_df)} rows, "
        f"Container_Vuln={len(container_vuln_df)} rows, "
        f"Host_Open_Ports={len(open_ports_df)} rows"
    )


if __name__ == "__main__":
    main()
