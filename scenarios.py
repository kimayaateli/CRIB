"""CRIB Incident Scenarios Engine.

Defines the four foundational cybersecurity incident response training scenarios:
1. Port Scanning (Reconnaissance)
2. Repeated Authentication Failures (Credential Access / Brute Force)
3. ARP Anomalies (Local Network Man-in-the-Middle / Spoofing)
4. Traffic Flooding (Denial of Service)

Each scenario follows the standard 4-stage incident-response lifecycle:
Triage -> Investigation -> Containment -> Recovery.
All exercises clearly indicate simulated evidence origin.
"""

from typing import Dict, Any, List, Optional

STAGE_ORDER = ["triage", "investigation", "containment", "recovery"]

SCENARIOS: Dict[str, Dict[str, Any]] = {
    "port_scan": {
        "id": "port_scan",
        "title": "Port Scanning & Network Reconnaissance",
        "category": "Reconnaissance",
        "severity": "MEDIUM",
        "summary": (
            "An internal host is systematically probing sequential TCP ports across "
            "DMZ application servers in a short time window."
        ),
        "learning_objectives": [
            "Differentiate legitimate administrative scanning from unauthorized adversarial reconnaissance.",
            "Analyze TCP SYN connection frequency and target port distributions.",
            "Apply micro-segmentation or firewall isolation without unnecessarily disrupting business services.",
            "Harden perimeter and host ingress rules to minimize exposure of unneeded services."
        ],
        "evidence_origin": "SIMULATED (Controlled Range Dataset)",
        "simulated_events": [
            {"event_type": "CONNECT", "source_ip": "192.168.1.105", "destination_ip": "192.168.1.20", "destination_port": 21, "details": "SYN flag set; state: SYN_SENT"},
            {"event_type": "CONNECT", "source_ip": "192.168.1.105", "destination_ip": "192.168.1.20", "destination_port": 22, "details": "SYN flag set; state: SYN_SENT"},
            {"event_type": "CONNECT", "source_ip": "192.168.1.105", "destination_ip": "192.168.1.20", "destination_port": 23, "details": "SYN flag set; state: SYN_SENT"},
            {"event_type": "CONNECT", "source_ip": "192.168.1.105", "destination_ip": "192.168.1.20", "destination_port": 25, "details": "SYN flag set; state: SYN_SENT"},
            {"event_type": "CONNECT", "source_ip": "192.168.1.105", "destination_ip": "192.168.1.20", "destination_port": 80, "details": "SYN flag set; state: ESTABLISHED"},
            {"event_type": "CONNECT", "source_ip": "192.168.1.105", "destination_ip": "192.168.1.20", "destination_port": 443, "details": "SYN flag set; state: ESTABLISHED"},
            {"event_type": "CONNECT", "source_ip": "192.168.1.105", "destination_ip": "192.168.1.20", "destination_port": 445, "details": "SYN flag set; state: SYN_SENT"},
            {"event_type": "CONNECT", "source_ip": "192.168.1.105", "destination_ip": "192.168.1.20", "destination_port": 3389, "details": "SYN flag set; state: SYN_SENT"},
            {"event_type": "CONNECT", "source_ip": "192.168.1.105", "destination_ip": "192.168.1.20", "destination_port": 8080, "details": "SYN flag set; state: SYN_SENT"},
            {"event_type": "CONNECT", "source_ip": "192.168.1.105", "destination_ip": "192.168.1.20", "destination_port": 9000, "details": "SYN flag set; state: SYN_SENT"},
        ],
        "stages": {
            "triage": {
                "title": "Stage 1: Triage",
                "prompt": (
                    "Your SOC dashboard flags a high-priority alert: Host 192.168.1.105 has attempted connections "
                    "to 10 distinct TCP ports on DMZ server 192.168.1.20 within 8 seconds. What is your immediate triage determination?"
                ),
                "options": [
                    {
                        "id": "triage_opt_1",
                        "text": "Classify as an active reconnaissance scan targeting core DMZ assets and assign priority for immediate containment.",
                        "points": 25,
                        "is_recommended": True,
                        "explanation": (
                            "Correct. Rapid, sequential SYN connections across common service ports (21, 22, 23, 80, 443, 3389) "
                            "strongly indicate automated port enumeration. Prompt triage preserves audit trails while preparing isolation."
                        )
                    },
                    {
                        "id": "triage_opt_2",
                        "text": "Ignore the alert as normal background network broadcast noise.",
                        "points": 0,
                        "is_recommended": False,
                        "explanation": (
                            "Incorrect. Unicast TCP connection attempts to multiple distinct ports are never broadcast noise. "
                            "Dismissing this allows potential attackers to complete vulnerability discovery unimpeded."
                        )
                    },
                    {
                        "id": "triage_opt_3",
                        "text": "Immediately reboot the entire DMZ subnet to terminate all open sessions.",
                        "points": 5,
                        "is_recommended": False,
                        "explanation": (
                            "Suboptimal and disruptive. Rebooting the entire DMZ subnet destroys volatile volatile forensic memory "
                            "and causes major business disruption before validating the scope of activity."
                        )
                    }
                ]
            },
            "investigation": {
                "title": "Stage 2: Investigation",
                "prompt": (
                    "You begin investigating source host 192.168.1.105. What is the most effective initial investigation step?"
                ),
                "options": [
                    {
                        "id": "invest_opt_1",
                        "text": "Examine local endpoint process trees and user logins on 192.168.1.105 to identify the executable generating the scan.",
                        "points": 25,
                        "is_recommended": True,
                        "explanation": (
                            "Correct. Correlating socket creation events with endpoint process execution trees reveals whether an authorized "
                            "scanner (e.g. Nessus/Nmap run by IT), malware, or an unauthorized shell spawned the activity."
                        )
                    },
                    {
                        "id": "invest_opt_2",
                        "text": "Immediately format the target server hard disk without examining server logs.",
                        "points": 0,
                        "is_recommended": False,
                        "explanation": (
                            "Incorrect. Wiping the target server destroys vital evidence and does not stop the scanning source host."
                        )
                    },
                    {
                        "id": "invest_opt_3",
                        "text": "Wait 24 hours to observe if the scanner attempts additional targets on other subnets.",
                        "points": 5,
                        "is_recommended": False,
                        "explanation": (
                            "Poor practice. Passive waiting during active reconnaissance gives the adversary time to transition "
                            "from scanning to exploitation."
                        )
                    }
                ]
            },
            "containment": {
                "title": "Stage 3: Containment",
                "prompt": (
                    "Investigation reveals an unauthorized Python script running an nmap-like scan on an unmanaged workstation. "
                    "How should you contain this incident?"
                ),
                "options": [
                    {
                        "id": "contain_opt_1",
                        "text": "Isolate workstation 192.168.1.105 from the internal network at the switch port or host firewall while preserving memory state.",
                        "points": 25,
                        "is_recommended": True,
                        "explanation": (
                            "Correct. Quarantining the offending host prevents lateral movement and further scanning while leaving system "
                            "memory intact for digital forensic analysis."
                        )
                    },
                    {
                        "id": "contain_opt_2",
                        "text": "Disable the entire corporate gateway router.",
                        "points": 5,
                        "is_recommended": False,
                        "explanation": (
                            "Excessive. Shutting down the entire corporate Internet gateway causes company-wide downtime for an internal "
                            "workstation incident."
                        )
                    },
                    {
                        "id": "contain_opt_3",
                        "text": "Email the user asking them if they are running a scanner.",
                        "points": 5,
                        "is_recommended": False,
                        "explanation": (
                            "Inadequate containment. If the workstation is compromised, emailing the user does nothing to halt automated "
                            "malware propagation or notify security teams in time."
                        )
                    }
                ]
            },
            "recovery": {
                "title": "Stage 4: Recovery & Post-Incident Action",
                "prompt": (
                    "The scanning host has been sanitized and removed from quarantine. What long-term corrective action prevents recurrence?"
                ),
                "options": [
                    {
                        "id": "recov_opt_1",
                        "text": "Enforce strict egress filtering between user subnets and DMZ servers, disabling unused legacy ports and auditing workstation privileges.",
                        "points": 25,
                        "is_recommended": True,
                        "explanation": (
                            "Correct. Principle of least privilege network access ensures general user workstations cannot probe or connect "
                            "to arbitrary DMZ management ports (Telnet, RDP, SMB)."
                        )
                    },
                    {
                        "id": "recov_opt_2",
                        "text": "Disable all firewall logging to prevent alert fatigue.",
                        "points": 0,
                        "is_recommended": False,
                        "explanation": (
                            "Dangerous. Turning off logging blinds the security team to future intrusions."
                        )
                    },
                    {
                        "id": "recov_opt_3",
                        "text": "Close the incident ticket with no documentation or rule changes.",
                        "points": 5,
                        "is_recommended": False,
                        "explanation": (
                            "Incomplete. Incident response requires post-incident lessons learned and preventative policy adjustments."
                        )
                    }
                ]
            }
        }
    },
    "auth_brute_force": {
        "id": "auth_brute_force",
        "title": "Repeated Authentication Failures (Brute Force)",
        "category": "Credential Access",
        "severity": "HIGH",
        "summary": (
            "A burst of failed authentication attempts against an internal administrative service "
            "originating from an unknown external IP address."
        ),
        "learning_objectives": [
            "Identify password spraying and brute-force patterns from authentication logs.",
            "Assess risk to privileged accounts (Administrator / root).",
            "Implement account lockout, IP rate-limiting, and multi-factor authentication (MFA).",
            "Validate credential security post-attack."
        ],
        "evidence_origin": "SIMULATED (Controlled Range Dataset)",
        "simulated_events": [
            {"event_type": "AUTH_FAILURE", "source_ip": "203.0.113.45", "destination_ip": "10.0.0.15", "destination_port": 22, "details": "user=admin; method=password; result=FAIL"},
            {"event_type": "AUTH_FAILURE", "source_ip": "203.0.113.45", "destination_ip": "10.0.0.15", "destination_port": 22, "details": "user=root; method=password; result=FAIL"},
            {"event_type": "AUTH_FAILURE", "source_ip": "203.0.113.45", "destination_ip": "10.0.0.15", "destination_port": 22, "details": "user=deploy; method=password; result=FAIL"},
            {"event_type": "AUTH_FAILURE", "source_ip": "203.0.113.45", "destination_ip": "10.0.0.15", "destination_port": 22, "details": "user=backup; method=password; result=FAIL"},
            {"event_type": "AUTH_FAILURE", "source_ip": "203.0.113.45", "destination_ip": "10.0.0.15", "destination_port": 22, "details": "user=test; method=password; result=FAIL"},
            {"event_type": "AUTH_FAILURE", "source_ip": "203.0.113.45", "destination_ip": "10.0.0.15", "destination_port": 22, "details": "user=administrator; method=password; result=FAIL"},
        ],
        "stages": {
            "triage": {
                "title": "Stage 1: Triage",
                "prompt": (
                    "Security alerts report over 6 failed SSH login attempts from external IP 203.0.113.45 in under 10 seconds. "
                    "What is your immediate triage response?"
                ),
                "options": [
                    {
                        "id": "triage_opt_1",
                        "text": "Classify as an active credential stuffing / brute-force attack against perimeter SSH and verify whether any login attempt succeeded.",
                        "points": 25,
                        "is_recommended": True,
                        "explanation": (
                            "Correct. Rapid bursts of credential failures against privileged accounts require fast triage to confirm no breach "
                            "succeeded and to block the offending source."
                        )
                    },
                    {
                        "id": "triage_opt_2",
                        "text": "Assume an employee forgot their password and reset the firewall without checking.",
                        "points": 5,
                        "is_recommended": False,
                        "explanation": (
                            "Unlikely and risky. Attempts cycling through generic usernames ('admin', 'root', 'deploy') from an unverified "
                            "external IP indicates automated dictionary attack, not user error."
                        )
                    },
                    {
                        "id": "triage_opt_3",
                        "text": "Delete the authentication log to free up disk space.",
                        "points": 0,
                        "is_recommended": False,
                        "explanation": (
                            "Incorrect and catastrophic. Deleting auth logs destroys criminal evidence and SOC visibility."
                        )
                    }
                ]
            },
            "investigation": {
                "title": "Stage 2: Investigation",
                "prompt": (
                    "You analyze auth.log on the target server. What critical question must your investigation answer?"
                ),
                "options": [
                    {
                        "id": "invest_opt_1",
                        "text": "Did any authentication attempt from 203.0.113.45 return 'Accepted password' or establish a session?",
                        "points": 25,
                        "is_recommended": True,
                        "explanation": (
                            "Correct. Determining if any attempt succeeded establishes whether this is a nuisance reconnaissance event or an "
                            "active system compromise requiring breach protocol."
                        )
                    },
                    {
                        "id": "invest_opt_2",
                        "text": "What monitor model does the attacker have?",
                        "points": 0,
                        "is_recommended": False,
                        "explanation": (
                            "Irrelevant. Network authentication telemetry does not reveal client display hardware."
                        )
                    },
                    {
                        "id": "invest_opt_3",
                        "text": "Check web server image cache size.",
                        "points": 0,
                        "is_recommended": False,
                        "explanation": (
                            "Irrelevant to an SSH authentication attack."
                        )
                    }
                ]
            },
            "containment": {
                "title": "Stage 3: Containment",
                "prompt": (
                    "Logs show all attempts failed, but the source IP continues hammering port 22. What containment action should be applied?"
                ),
                "options": [
                    {
                        "id": "contain_opt_1",
                        "text": "Block IP 203.0.113.45 at the perimeter firewall and temporarily throttle/jail repeated failures using automated rate limiting (fail2ban).",
                        "points": 25,
                        "is_recommended": True,
                        "explanation": (
                            "Correct. Dropping packets at the perimeter stops server resource exhaustion and eliminates risk of password exhaustion."
                        )
                    },
                    {
                        "id": "contain_opt_2",
                        "text": "Change the root password to '12345678'.",
                        "points": 0,
                        "is_recommended": False,
                        "explanation": (
                            "Dangerous. Setting trivial passwords assists the attacker."
                        )
                    },
                    {
                        "id": "contain_opt_3",
                        "text": "Ignore the source since all attempts failed so far.",
                        "points": 5,
                        "is_recommended": False,
                        "explanation": (
                            "Inadequate. Uncontained brute force may eventually succeed or cause denial of service."
                        )
                    }
                ]
            },
            "recovery": {
                "title": "Stage 4: Recovery & Hardening",
                "prompt": (
                    "The IP has been blocked. What long-term architectural controls should be implemented for administrative access?"
                ),
                "options": [
                    {
                        "id": "recov_opt_1",
                        "text": "Disable direct password-based SSH access, enforce public-key authentication with MFA, and restrict SSH to an internal VPN.",
                        "points": 25,
                        "is_recommended": True,
                        "explanation": (
                            "Correct. Removing SSH from public ingress and requiring cryptographic keys plus MFA makes password brute-force "
                            "mathematically impossible."
                        )
                    },
                    {
                        "id": "recov_opt_2",
                        "text": "Switch SSH to port 2222 and leave password authentication enabled.",
                        "points": 10,
                        "is_recommended": False,
                        "explanation": (
                            "Security through obscurity. Port shifting delays simple bots but does not protect against competent adversaries."
                        )
                    },
                    {
                        "id": "recov_opt_3",
                        "text": "Allow all employees to share a single admin password for convenience.",
                        "points": 0,
                        "is_recommended": False,
                        "explanation": (
                            "Severe violation of security hygiene and identity accounting."
                        )
                    }
                ]
            }
        }
    },
    "arp_anomalies": {
        "id": "arp_anomalies",
        "title": "ARP Anomalies & Spoofing Detection",
        "category": "Credential Access & Lateral Movement",
        "severity": "HIGH",
        "summary": (
            "Conflicting ARP replies associating multiple distinct IP addresses (including the default gateway) "
            "with a single suspicious host MAC address on the local LAN."
        ),
        "learning_objectives": [
            "Understand Address Resolution Protocol (ARP) mechanics and spoofing risks.",
            "Detect gratuitous ARP poisoning attempts in switched environments.",
            "Mitigate local Man-in-the-Middle (MitM) attacks.",
            "Deploy Dynamic ARP Inspection (DAI) and static bindings where appropriate."
        ],
        "evidence_origin": "SIMULATED (Controlled Range Dataset)",
        "simulated_events": [
            {"event_type": "ARP_CLAIM", "source_ip": "192.168.1.1", "destination_ip": "192.168.1.255", "destination_port": None, "details": "ip=192.168.1.1;mac=aa:bb:cc:11:22:33"},
            {"event_type": "ARP_CLAIM", "source_ip": "192.168.1.50", "destination_ip": "192.168.1.255", "destination_port": None, "details": "ip=192.168.1.50;mac=aa:bb:cc:11:22:33"},
            {"event_type": "ARP_MAC_CHANGE", "source_ip": "192.168.1.1", "destination_ip": "192.168.1.20", "destination_port": None, "details": "Gateway IP 192.168.1.1 MAC changed from 00:11:22:33:44:55 to aa:bb:cc:11:22:33"},
        ],
        "stages": {
            "triage": {
                "title": "Stage 1: Triage",
                "prompt": (
                    "The detection engine alerts: MAC aa:bb:cc:11:22:33 is claiming both 192.168.1.50 and the default gateway 192.168.1.1. "
                    "What threat does this indicate?"
                ),
                "options": [
                    {
                        "id": "triage_opt_1",
                        "text": "Suspect active ARP cache poisoning attempting a local Man-in-the-Middle (MitM) interception of LAN traffic.",
                        "points": 25,
                        "is_recommended": True,
                        "explanation": (
                            "Correct. Multiple IP addresses mapping to a single non-router workstation MAC is classic ARP spoofing intended "
                            "to hijack or sniff network packets passing to the gateway."
                        )
                    },
                    {
                        "id": "triage_opt_2",
                        "text": "Dismiss as normal DHCP lease renewal behaviour.",
                        "points": 5,
                        "is_recommended": False,
                        "explanation": (
                            "Incorrect. DHCP renewal never reassigns the permanent default gateway IP to an endpoint MAC address."
                        )
                    },
                    {
                        "id": "triage_opt_3",
                        "text": "Assume the router upgraded its wireless firmware automatically.",
                        "points": 0,
                        "is_recommended": False,
                        "explanation": (
                            "Incorrect. Router firmware updates do not cause workstation MACs to impersonate the gateway."
                        )
                    }
                ]
            },
            "investigation": {
                "title": "Stage 2: Investigation",
                "prompt": (
                    "Which switch and host artifacts should you inspect to identify the physical device claiming MAC aa:bb:cc:11:22:33?"
                ),
                "options": [
                    {
                        "id": "invest_opt_1",
                        "text": "Inspect the managed switch CAM/MAC address table to locate the specific physical port associated with MAC aa:bb:cc:11:22:33.",
                        "points": 25,
                        "is_recommended": True,
                        "explanation": (
                            "Correct. Querying the switch CAM table instantly maps the malicious MAC address to its physical switch port, "
                            "identifying the wall jack and connected computer."
                        )
                    },
                    {
                        "id": "invest_opt_2",
                        "text": "Check the DNS TXT records of google.com.",
                        "points": 0,
                        "is_recommended": False,
                        "explanation": (
                            "Irrelevant. External public DNS has no bearing on internal layer 2 MAC resolution."
                        )
                    },
                    {
                        "id": "invest_opt_3",
                        "text": "Broadcast an ICMP ping to 255.255.255.255 and do nothing else.",
                        "points": 5,
                        "is_recommended": False,
                        "explanation": (
                            "Ineffective. Ping does not trace physical switch port provenance."
                        )
                    }
                ]
            },
            "containment": {
                "title": "Stage 3: Containment",
                "prompt": (
                    "The MAC is mapped to switch Port Fa0/14 in Conference Room B. What is the immediate containment action?"
                ),
                "options": [
                    {
                        "id": "contain_opt_1",
                        "text": "Administratively disable switch port Fa0/14 and clear corrupted ARP caches on affected gateway and server nodes.",
                        "points": 25,
                        "is_recommended": True,
                        "explanation": (
                            "Correct. Shutting the port stops the transmission of spoofed ARP frames immediately, and flushing host ARP tables "
                            "restores legitimate traffic flow through the authentic gateway."
                        )
                    },
                    {
                        "id": "contain_opt_2",
                        "text": "Ask everyone in the conference room if they plugged in a rogue device.",
                        "points": 5,
                        "is_recommended": False,
                        "explanation": (
                            "Ineffective containment while active traffic interception continues in real-time."
                        )
                    },
                    {
                        "id": "contain_opt_3",
                        "text": "Reboot the building's electrical circuit breaker.",
                        "points": 0,
                        "is_recommended": False,
                        "explanation": (
                            "Disproportionate, dangerous, and causes physical hardware stress across the facility."
                        )
                    }
                ]
            },
            "recovery": {
                "title": "Stage 4: Recovery & Prevention",
                "prompt": (
                    "What switch security features permanently safeguard against ARP poisoning across the network?"
                ),
                "options": [
                    {
                        "id": "recov_opt_1",
                        "text": "Enable Dynamic ARP Inspection (DAI) and DHCP Snooping across all access switches, with 802.1X port security.",
                        "points": 25,
                        "is_recommended": True,
                        "explanation": (
                            "Correct. DHCP snooping builds a trusted IP-MAC binding database, and DAI intercepts and discards invalid ARP replies "
                            "before they can poison neighboring cache tables."
                        )
                    },
                    {
                        "id": "recov_opt_2",
                        "text": "Instruct users to disable their local firewalls.",
                        "points": 0,
                        "is_recommended": False,
                        "explanation": (
                            "Harmful. Disabling firewalls compounds the vulnerability."
                        )
                    },
                    {
                        "id": "recov_opt_3",
                        "text": "Replace the switch with an unmanaged hub.",
                        "points": 0,
                        "is_recommended": False,
                        "explanation": (
                            "Disastrous. Hubs broadcast all packets to all ports, maximizing interception potential."
                        )
                    }
                ]
            }
        }
    },
    "traffic_flood": {
        "id": "traffic_flood",
        "title": "Traffic Flooding / Denial of Service",
        "category": "Denial of Service",
        "severity": "CRITICAL",
        "summary": (
            "A sudden, abnormal surge of rapid TCP SYN connections targeting an internal web service, "
            "degrading application response times and threatening availability."
        ),
        "learning_objectives": [
            "Differentiate flash crowds from volumetric SYN flood attacks.",
            "Recognize symptoms of TCP socket state starvation (half-open connections).",
            "Implement SYN cookies, rate limiting, and upstream traffic scrubbing.",
            "Verify service restoration and performance SLAs."
        ],
        "evidence_origin": "SIMULATED (Controlled Range Dataset)",
        "simulated_events": [
            {"event_type": "CONNECT", "source_ip": "198.51.100.22", "destination_ip": "10.0.0.80", "destination_port": 80, "details": "High-volume SYN flood, spoofed headers"},
            {"event_type": "CONNECT", "source_ip": "198.51.100.23", "destination_ip": "10.0.0.80", "destination_port": 80, "details": "High-volume SYN flood, spoofed headers"},
            {"event_type": "CONNECT", "source_ip": "198.51.100.24", "destination_ip": "10.0.0.80", "destination_port": 80, "details": "High-volume SYN flood, spoofed headers"},
            {"event_type": "CONNECT", "source_ip": "198.51.100.25", "destination_ip": "10.0.0.80", "destination_port": 80, "details": "High-volume SYN flood, spoofed headers"},
        ],
        "stages": {
            "triage": {
                "title": "Stage 1: Triage",
                "prompt": (
                    "Service monitoring reports HTTP response times jumped from 12ms to 4800ms, and network graphs show over 150 connection "
                    "requests per second targeting port 80. What is your immediate triage priority?"
                ),
                "options": [
                    {
                        "id": "triage_opt_1",
                        "text": "Declare a high-severity Availability incident, confirm server CPU/memory and connection backlog limits, and engage network operations.",
                        "points": 25,
                        "is_recommended": True,
                        "explanation": (
                            "Correct. Rapid degradation of core service availability requires high-severity incident mobilization to prevent "
                            "complete web tier collapse."
                        )
                    },
                    {
                        "id": "triage_opt_2",
                        "text": "Delete the web server database because the site is slow.",
                        "points": 0,
                        "is_recommended": False,
                        "explanation": (
                            "Incorrect and destructive. A traffic flood targets network sockets, not database storage."
                        )
                    },
                    {
                        "id": "triage_opt_3",
                        "text": "Wait for the flood to end on its own.",
                        "points": 5,
                        "is_recommended": False,
                        "explanation": (
                            "Poor triage. DoS attacks can persist for hours or days, causing massive business losses."
                        )
                    }
                ]
            },
            "investigation": {
                "title": "Stage 2: Investigation",
                "prompt": (
                    "Inspecting netstat reveals thousands of sockets in SYN_RECV state from widely dispersed external IPs. What does this indicate?"
                ),
                "options": [
                    {
                        "id": "invest_opt_1",
                        "text": "A distributed TCP SYN Flood designed to exhaust the server's TCP connection backlog queue with half-open connections.",
                        "points": 25,
                        "is_recommended": True,
                        "explanation": (
                            "Correct. Sockets stuck in SYN_RECV without completing the three-way handshake (no final ACK) are the hallmark of "
                            "a classic TCP SYN flood."
                        )
                    },
                    {
                        "id": "invest_opt_2",
                        "text": "Normal user web browsing sessions.",
                        "points": 0,
                        "is_recommended": False,
                        "explanation": (
                            "Incorrect. Legitimate web clients complete the handshake and transition to ESTABLISHED within milliseconds."
                        )
                    },
                    {
                        "id": "invest_opt_3",
                        "text": "Internal DNS server cache timeout.",
                        "points": 5,
                        "is_recommended": False,
                        "explanation": (
                            "Inaccurate. DNS timeouts do not create thousands of SYN_RECV sockets on an HTTP port."
                        )
                    }
                ]
            },
            "containment": {
                "title": "Stage 3: Containment",
                "prompt": (
                    "The web server is dropping legitimate requests due to queue exhaustion. What is the most effective containment mitigation?"
                ),
                "options": [
                    {
                        "id": "contain_opt_1",
                        "text": "Enable TCP SYN Cookies on the kernel/load balancer and activate rate limiting at the upstream reverse proxy/WAF.",
                        "points": 25,
                        "is_recommended": True,
                        "explanation": (
                            "Correct. SYN cookies allow the server to encode state in the sequence number without allocating memory for half-open "
                            "connections, completely neutralizing SYN flood backlog exhaustion."
                        )
                    },
                    {
                        "id": "contain_opt_2",
                        "text": "Unplug the server power cable.",
                        "points": 0,
                        "is_recommended": False,
                        "explanation": (
                            "Counterproductive. Powering off achieves the attacker's goal of taking down the service."
                        )
                    },
                    {
                        "id": "contain_opt_3",
                        "text": "Increase HTTP keepalive timeout to 600 seconds.",
                        "points": 0,
                        "is_recommended": False,
                        "explanation": (
                            "Harmful. Increasing keepalive during a flood ties up server resources even longer."
                        )
                    }
                ]
            },
            "recovery": {
                "title": "Stage 4: Recovery & Resilience",
                "prompt": (
                    "Normal latency is restored. What architectural enhancement ensures resilience against future large-scale volumetric attacks?"
                ),
                "options": [
                    {
                        "id": "recov_opt_1",
                        "text": "Deploy an Anycast DDoS mitigation service / CDN in front of origin servers and tune connection limits and health checks.",
                        "points": 25,
                        "is_recommended": True,
                        "explanation": (
                            "Correct. Cloud DDoS scrubbing networks and Anycast routing absorb volumetric spikes upstream before they hit origin infrastructure."
                        )
                    },
                    {
                        "id": "recov_opt_2",
                        "text": "Disable HTTPS encryption.",
                        "points": 0,
                        "is_recommended": False,
                        "explanation": (
                            "Dangerous. Disabling encryption exposes data confidentiality."
                        )
                    },
                    {
                        "id": "recov_opt_3",
                        "text": "No changes needed since the attack stopped.",
                        "points": 5,
                        "is_recommended": False,
                        "explanation": (
                            "Unacceptable. Without architectural defenses, the next attack will cause another outage."
                        )
                    }
                ]
            }
        }
    }
}


def list_scenarios() -> List[Dict[str, Any]]:
    """Return summary list of all available scenarios for dashboard and catalog."""
    return [
        {
            "id": s["id"],
            "title": s["title"],
            "category": s["category"],
            "severity": s["severity"],
            "summary": s["summary"],
            "learning_objectives": s["learning_objectives"],
            "evidence_origin": s["evidence_origin"],
        }
        for s in SCENARIOS.values()
    ]


def get_scenario(scenario_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve full scenario specification by identifier."""
    return SCENARIOS.get(scenario_id)


def get_stage_info(scenario_id: str, stage_name: str) -> Optional[Dict[str, Any]]:
    """Retrieve details for a specific stage within a scenario."""
    scenario = get_scenario(scenario_id)
    if not scenario:
        return None
    return scenario.get("stages", {}).get(stage_name)


def get_next_stage(current_stage: str) -> Optional[str]:
    """Return the next stage in the incident response lifecycle, or None if finished."""
    try:
        idx = STAGE_ORDER.index(current_stage)
        if idx + 1 < len(STAGE_ORDER):
            return STAGE_ORDER[idx + 1]
    except ValueError:
        pass
    return None


def evaluate_stage_choice(
    scenario_id: str,
    stage_name: str,
    choice_id: str
) -> Optional[Dict[str, Any]]:
    """Evaluate a user's choice for a given stage."""
    stage = get_stage_info(scenario_id, stage_name)
    if not stage:
        return None

    for option in stage.get("options", []):
        if option["id"] == choice_id:
            return {
                "points": option["points"],
                "explanation": option["explanation"],
                "is_recommended": option.get("is_recommended", False),
                "text": option["text"],
            }
    return None
