# Exfiltration Attempts Detection

## Overview
This folder contains screenshots and evidence of Data Exfiltration 
attempt detection using the custom SIEM Dashboard built on ELK Stack (Kibana).

## What Was Detected
- Unusual outbound data transfer volumes
- Connections to suspicious external IPs
- Large file transfers outside business hours
- DNS-based exfiltration patterns identified

## Dashboard Panels
- Outbound Traffic Volume Over Time (Line Chart)
- Top Destination IPs (Bar Chart)
- Unusual Data Transfer Alerts (Data Table)
- Geo-map of Exfiltration Destinations

## Tools Used
- ELK Stack (Elasticsearch, Logstash, Kibana)
- Packetbeat / Filebeat for log ingestion
- Kibana Lens for visualization
