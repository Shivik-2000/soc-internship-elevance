# Privilege Escalation Detection

## Overview
This folder contains screenshots and evidence of Privilege Escalation 
detection using the custom SIEM Dashboard built on ELK Stack (Kibana).

## What Was Detected
- Unauthorized privilege escalation attempts
- Sudden role/permission changes flagged
- Admin account access from unusual sources
- Suspicious sudo/runas command executions

## Dashboard Panels
- Privilege Change Events Over Time (Line Chart)
- Top Users with Escalation Attempts (Bar Chart)
- Suspicious Admin Logins (Data Table)
- Alert Timeline for Escalation Events

## Tools Used
- ELK Stack (Elasticsearch, Logstash, Kibana)
- Winlogbeat / Auditbeat for log ingestion
- Kibana Lens for visualization
