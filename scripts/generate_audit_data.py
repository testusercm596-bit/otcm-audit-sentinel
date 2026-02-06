"""
Generate synthetic audit log data for OpenText Content Manager
"""
import json
import random
from datetime import datetime, timedelta

# Configuration
EVENT_TYPES = ["ObjectAdded", "ObjectDeleted", "RevisionUpdated", "DocumentViewed", "DocumentExtracted"]

OBJECT_TYPES = [
    "Record", "Location", "Active Audit Event", "Activity", "Check In Style",
    "Consignment Approver", "Consignment Record Rejection", "Record Action",
    "Request", "Saved Search", "To Do Item", "User Label", "Workflow"
]

# Real users from sample data
USERS = [
    {"name": "pnayak2", "uri": 9001, "regular_hours": True},
    {"name": "OPENTEXT\\pnayak2", "uri": 9001, "regular_hours": True},
    {"name": "jitendra@w0kyd.onmicrosoft.com", "uri": 9002, "regular_hours": True},
    {"name": "opentext\\jsmith", "uri": 9003, "regular_hours": True},
    {"name": "admin@opentext.com", "uri": 9004, "regular_hours": False},
    {"name": "OPENTEXT\\rjones", "uri": 9005, "regular_hours": True},
    {"name": "consultant@external.com", "uri": 9006, "regular_hours": False},
]

def generate_timestamp(regular_hours=True, outlier=False):
    """Generate realistic timestamps"""
    # Base date: January 2026 to February 2026
    start_date = datetime(2026, 1, 6)  # Monday
    days_range = 30
    
    # Pick a random day
    random_days = random.randint(0, days_range)
    target_date = start_date + timedelta(days=random_days)
    
    if outlier:
        # Outlier: weekend or late night
        if random.random() < 0.5:
            # Weekend
            target_date = target_date + timedelta(days=(5 - target_date.weekday()))  # Saturday
        # Late night hours
        hour = random.choice([22, 23, 0, 1, 2])
        minute = random.randint(0, 59)
    elif regular_hours:
        # Weekday only
        while target_date.weekday() >= 5:  # Skip weekends
            target_date += timedelta(days=1)
        # Business hours: 9am - 5pm
        hour = random.randint(9, 16)
        minute = random.randint(0, 59)
    else:
        # Semi-regular: weekdays but extended hours
        while target_date.weekday() >= 5:
            target_date += timedelta(days=1)
        hour = random.randint(7, 19)
        minute = random.randint(0, 59)
    
    timestamp = target_date.replace(hour=hour, minute=minute, second=0, microsecond=0)
    
    # Format as required
    iso_format = timestamp.isoformat() + "Z"
    readable_format = timestamp.strftime("%d-%m-%Y at %H:%M")
    
    return iso_format, readable_format

def generate_audit_entry(uri_base):
    """Generate a single audit log entry"""
    # Select user (80% regular hours, 20% outliers)
    is_outlier = random.random() < 0.15  # 15% outliers
    
    if is_outlier:
        user = random.choice([u for u in USERS if not u["regular_hours"]])
    else:
        user = random.choice(USERS)
    
    # Generate timestamp
    iso_ts, readable_ts = generate_timestamp(
        regular_hours=user["regular_hours"],
        outlier=is_outlier
    )
    
    # Select event and object type
    event_type = random.choice(EVENT_TYPES)
    object_type = random.choice(OBJECT_TYPES)
    
    # Map event type to readable action
    action_map = {
        "ObjectAdded": "Added",
        "ObjectDeleted": "Deleted",
        "RevisionUpdated": "Modified",
        "DocumentViewed": "Viewed",
        "DocumentExtracted": "Extracted"
    }
    action = action_map.get(event_type, "Modified")
    
    # Generate object URI
    object_uri = random.randint(1000, 9999)
    
    # Generate location name if applicable
    location_names = [
        "Finance Department", "HR Records", "Legal Documents", "Project Files",
        "Customer Data", "Compliance Reports", "Internal Audit", "Executive Office"
    ]
    
    entry = {
        "HistoryDoneOn": {
            "DateTime": iso_ts,
            "StringValue": readable_ts
        },
        "HistoryEventDescription": {
            "Value": f"{action} - {object_type} - done by '{user['name']}' on {readable_ts}"
        },
        "HistoryEventType": {
            "Value": event_type,
            "StringValue": action
        },
        "HistoryForObjectType": {
            "Value": object_type,
            "StringValue": object_type
        },
        "HistoryForObjectUri": {
            "Value": object_uri
        },
        "HistoryIsSecurityViolation": {
            "Value": random.random() < 0.05  # 5% security violations
        },
        "HistoryLoginLocation": {
            "LocationFormattedName": {
                "Value": user["name"]
            },
            "NameString": user["name"],
            "Uri": user["uri"]
        },
        "PossiblyHasSubordinates": False,
        "TrimType": "History",
        "Uri": uri_base
    }
    
    # Add optional fields for certain object types
    if object_type in ["Record", "Location"]:
        entry["HistoryLocation"] = {
            "NameString": random.choice(location_names),
            "Uri": random.randint(100, 500)
        }
    
    if object_type == "Record":
        entry["HistoryRecord"] = {
            "NameString": f"D26/{random.randint(100, 999)}",
            "Uri": object_uri
        }
    
    return entry

def generate_audit_dataset(count=50):
    """Generate multiple audit log entries"""
    results = []
    base_uri = 40000
    
    for i in range(count):
        entry = generate_audit_entry(base_uri + i)
        results.append(entry)
    
    # Sort by timestamp (most recent first)
    results.sort(key=lambda x: x["HistoryDoneOn"]["DateTime"], reverse=True)
    
    # Create full response structure
    dataset = {
        "Results": results,
        "PropertiesAndFields": {
            "History": [
                "HistoryDoneOn",
                "HistoryEventDescription",
                "HistoryEventType",
                "HistoryForObjectType",
                "HistoryForObjectUri",
                "HistoryIsSecurityViolation",
                "HistoryLocation",
                "HistoryLoginLocation"
            ]
        },
        "TotalResults": count,
        "CountStringEx": f"{count} active audit events",
        "MinimumCount": count,
        "Count": count,
        "HasMoreItems": False,
        "TrimType": "History",
        "ResponseStatus": {}
    }
    
    return dataset

if __name__ == "__main__":
    # Generate 50 entries
    print("Generating 50 synthetic audit log entries...")
    audit_data = generate_audit_dataset(50)
    
    # Save to file
    output_file = "generated_audit_logs.json"
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(audit_data, f, indent=4, ensure_ascii=False)
    
    print(f"✓ Generated {len(audit_data['Results'])} audit entries")
    print(f"✓ Saved to: {output_file}")
    
    # Statistics
    event_types = {}
    security_violations = 0
    outliers = 0
    
    for entry in audit_data['Results']:
        event_type = entry['HistoryEventType']['Value']
        event_types[event_type] = event_types.get(event_type, 0) + 1
        
        if entry['HistoryIsSecurityViolation']['Value']:
            security_violations += 1
        
        # Check if timestamp is outside regular hours
        dt_str = entry['HistoryDoneOn']['StringValue']
        hour = int(dt_str.split('at ')[1].split(':')[0])
        if hour < 9 or hour > 17:
            outliers += 1
    
    print("\n📊 Statistics:")
    print(f"  Event Types: {event_types}")
    print(f"  Security Violations: {security_violations}")
    print(f"  Outlier Timestamps: {outliers}")
