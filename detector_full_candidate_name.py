import csv
import json
import re
import ast

def mask_phone(val):
    return val[:2] + "XXXXXX" + val[-2:]

def mask_aadhar(val):
    return val[:4] + " " + "XXXX" + " " + val[-4:]

def mask_passport(val):
    return val[0] + "XXXX" + val[-3:]

def mask_upi(val):
    parts = val.split("@")
    if len(parts[0]) <= 2:
        return "X" * len(parts[0]) + "@" + parts[1]
    return parts[0][:2] + "XXX@" + parts[1]

def mask_name(val):
    parts = val.split()
    masked = []
    for p in parts:
        if len(p) > 1:
            masked.append(p[0] + "XXX")
        else:
            masked.append("X")
    return " ".join(masked)

def mask_email(val):
    local, domain = val.split("@")
    return local[:2] + "XXX@" + domain

def mask_address(val):
    return "[REDACTED_ADDRESS]"

def mask_ip(val):
    return "[REDACTED_IP]"

def mask_device(val):
    return "[REDACTED_DEVICE]"

def safe_json_load(s):
    try:
        return json.loads(s)
    except json.JSONDecodeError:
        fixed = s
        fixed = re.sub(r'(\w+):', r'"\1":', fixed)
        fixed = re.sub(r':\s*([A-Za-z0-9_\-@.]+)', r': "\1"', fixed)
        fixed = fixed.replace("'", '"')
        fixed = fixed.replace(",}", "}")
        fixed = fixed.replace(",]", "]")
        try:
            return json.loads(fixed)
        except Exception:
            return {}

def detect_and_redact(data):
    is_pii = False
    redacted = {}

    for key, value in data.items():
        val = str(value)

        if key == "phone" and re.fullmatch(r"\d{10}", val):
            redacted[key] = mask_phone(val)
            is_pii = True
        elif key == "aadhar" and re.fullmatch(r"\d{12}", val):
            redacted[key] = mask_aadhar(val)
            is_pii = True
        elif key == "passport" and re.fullmatch(r"[A-Z][0-9]{7}", val):
            redacted[key] = mask_passport(val)
            is_pii = True
        elif key == "upi_id" and "@" in val:
            redacted[key] = mask_upi(val)
            is_pii = True
        elif key == "name" and len(val.split()) >= 2:
            redacted[key] = mask_name(val)
            is_pii = True
        elif key == "email" and "@" in val:
            if "name" in data or "address" in data:
                redacted[key] = mask_email(val)
                is_pii = True
            else:
                redacted[key] = val
        elif key == "address":
            redacted[key] = mask_address(val)
            is_pii = True
        elif key == "ip_address":
            if "device_id" in data:
                redacted[key] = mask_ip(val)
                is_pii = True
            else:
                redacted[key] = val
        elif key == "device_id":
            if "ip_address" in data:
                redacted[key] = mask_device(val)
                is_pii = True
            else:
                redacted[key] = val
        else:
            redacted[key] = val

    return redacted, is_pii

def process_record(record):
    data = safe_json_load(record["data_json"])
    redacted, is_pii = detect_and_redact(data)
    return {
        "record_id": record["record_id"],
        "redacted_data_json": json.dumps(redacted),
        "is_pii": str(is_pii)
    }

def main():
    import sys
    if len(sys.argv) != 2:
        print("Usage: python3 detector_full_candidate_name.py iscp_pii_dataset.csv")
        return

    input_file = sys.argv[1]
    output_file = "redacted_output_candidate_full_name.csv"

    with open(input_file, newline="", encoding="utf-8") as infile, open(output_file, "w", newline="", encoding="utf-8") as outfile:
        reader = csv.DictReader(infile)
        fieldnames = ["record_id", "redacted_data_json", "is_pii"]
        writer = csv.DictWriter(outfile, fieldnames=fieldnames)
        writer.writeheader()

        for row in reader:
            writer.writerow(process_record(row))

if __name__ == "__main__":
    main()
