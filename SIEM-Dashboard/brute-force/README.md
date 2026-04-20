# Brute Force Attack Detection

## Overview
This folder contains screenshots and evidence of Brute Force attack 
detection using the custom SIEM Dashboard built on ELK Stack (Kibana).

## What Was Detected
- Multiple failed login attempts from a single IP
- Authentication failure spikes visualized in Kibana
- Alerts triggered after threshold exceeded

## Dashboard Panels
- Failed Login Attempts Over Time (Line Chart)
- Top Source IPs (Bar Chart)
- Geo-map of Attack Origins

## Tools Used
- ELK Stack (Elasticsearch, Logstash, Kibana)
- Winlogbeat / Filebeat for log ingestion
- Kibana Lens for visualization
