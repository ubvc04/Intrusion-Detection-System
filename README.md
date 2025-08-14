# Windows Intrusion Detection System (IDS)

A comprehensive Intrusion Detection System combining Host-based (HIDS) and Network-based (NIDS) monitoring capabilities for Windows 10/11 environments.

## Architecture Overview

```
+---------------------+    +---------------------+
|                     |    |                     |
|    HIDS Agent       |    |    NIDS Sensor      |
|  +--------------+   |    |  +--------------+   |
|  | Event Log    |   |    |  | Packet       |   |
|  | Monitor      |   |    |  | Capture      |   |
|  +--------------+   |    |  +--------------+   |
|  | File Integrity|   |    |  | Traffic      |   |
|  | Monitor      |   |    |  | Analysis     |   |
|  +--------------+   |    |  +--------------+   |
|  | Registry     |   |    |  | Signature    |   |
|  | Monitor      |   |    |  | Detection    |   |
|  +--------------+   |    |  +--------------+   |
|         |           |    |         |           |
+---------|-----------+    +---------|-----------+
          |                          |
          v                          v
+---------------------------------------------+
|                                             |
|              IDS Manager                    |
|  +----------------+  +------------------+   |
|  | Event          |  | Correlation      |   |
|  | Collection     |  | Engine           |   |
|  +----------------+  +------------------+   |
|  | SQLite         |  | Rule             |   |
|  | Database       |  | Engine           |   |
|  +----------------+  +------------------+   |
|  | Alert          |                        |
|  | Generation     |                        |
|  +----------------+                        |
|           |                                |
+-----------|---------------------------------+
            |
            v
+---------------------------------------------+
|                                             |
|                Web UI                       |
|  +----------------+  +------------------+   |
|  | Dashboard      |  | Alert            |   |
|  | (Charts.js)    |  | Management       |   |
|  +----------------+  +------------------+   |
|  | Event          |  | Configuration    |   |
|  | Viewer         |  | Panel            |   |
|  +----------------+  +------------------+   |
|                                             |
+---------------------------------------------+
```

## Project Structure

```
ids/
├── config/
│   ├── config.ini                # Central configuration file
│   ├── hids_rules.json           # HIDS detection rules
│   └── nids_rules.json           # NIDS detection rules
├── hids/
│   ├── __init__.py
│   ├── agent.py                  # Main HIDS agent
│   ├── event_monitor.py          # Windows Event Log monitoring
│   ├── file_monitor.py           # File integrity monitoring
│   └── registry_monitor.py       # Registry change monitoring
├── nids/
│   ├── __init__.py
│   ├── sensor.py                 # Main NIDS sensor
│   ├── packet_capture.py         # Network packet capture
│   ├── traffic_analyzer.py       # Traffic analysis
│   └── signature_detector.py     # Signature-based detection
├── manager/
│   ├── __init__.py
│   ├── server.py                 # Main manager server
│   ├── database.py               # SQLite database handler
│   ├── correlation_engine.py     # Event correlation
│   ├── rule_engine.py            # Rule processing
│   └── alert_generator.py        # Alert generation
├── web/
│   ├── static/
│   │   ├── css/
│   │   │   └── tailwind.css      # TailwindCSS
│   │   └── js/
│   │       ├── charts.js         # Chart.js for visualizations
│   │       └── htmx.min.js       # HTMX for interactivity
│   ├── templates/
│   │   ├── base.html             # Base template
│   │   ├── dashboard.html        # Main dashboard
│   │   ├── alerts.html           # Alert management
│   │   └── config.html           # Configuration panel
│   └── app.py                    # Flask web application
├── utils/
│   ├── __init__.py
│   ├── logger.py                 # Logging utilities
│   └── helpers.py                # Helper functions
├── tests/
│   ├── test_hids.py              # HIDS tests
│   ├── test_nids.py              # NIDS tests
│   └── test_integration.py       # Integration tests
├── main.py                       # Main entry point
├── requirements.txt              # Python dependencies
└── setup.py                      # Setup script
```

## Setup Instructions

Detailed setup instructions are provided in the [SETUP.md](SETUP.md) file.

## Troubleshooting

### Npcap Installation

If you encounter issues with the NIDS component showing a "No libpcap provider available" warning, please refer to the [NPCAP_INSTALLATION.md](NPCAP_INSTALLATION.md) guide for detailed instructions on resolving this issue.

## Testing Guide

Information on testing the IDS is available in the [TESTING.md](TESTING.md) file.

## Deployment Guide

Deployment instructions can be found in the [DEPLOYMENT.md](DEPLOYMENT.md) file.