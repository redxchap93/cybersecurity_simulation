from flask import Flask, render_template_string, request, jsonify, Response
import os, requests, time

app = Flask(__name__)

# -------------------------
# DeepSeek Integration Setup
# -------------------------
def extract_response_text(result):
    return result["choices"][0].get("text", "")

def deepseek_correction(prompt, retries=5, wait_time=10):
    """Calls DeepSeek with a preference for technical and concise style."""
    OLLAMA_API_URL = os.getenv("OLLAMA_API_URL", "http://localhost:11434/v1/completions")
    SECRET_KEY = os.getenv("SECRET_KEY", "your_default_secret_key")
    headers = {"Authorization": f"Bearer {SECRET_KEY}"}
    # We keep the same approach of forcing "strictly technical" output
    payload = {
        "model": "deepseek-r1:1.5b",
        "prompt": prompt + "\n\nPlease respond with strictly technical, concise, direct instructions only.\n",
        "max_tokens": 512,
        "temperature": 0.5,
        "top_p": 0.7
    }
    for attempt in range(retries):
        try:
            response = requests.post(OLLAMA_API_URL, headers=headers, json=payload)
            response.raise_for_status()
            result = response.json()
            choice = result["choices"][0]
            if choice.get("finish_reason") == "load":
                print(f"Model not ready (attempt {attempt+1}/{retries}). Waiting {wait_time} seconds to retry...")
                time.sleep(wait_time)
                continue
            corrected_text = extract_response_text(result)
            return corrected_text
        except Exception as e:
            print("Error in text correction:", e)
            return f"Error during text correction: {e}"
    return "Model is still loading. Please try again later."

# -------------------------
# NEW: Filter function to remove non-technical or filler lines
# -------------------------
def parse_technical_output(text):
    """Remove disclaimers or non-technical language, keeping only commands/scripts."""
    lines = text.split('\n')
    filtered = []
    # Basic example: remove lines with common non-technical disclaimers or filler
    ignore_keywords = [
        "disclaimer", 
        "i am an ai",
        "as an ai",
        "apology",
        "i can only",
        "my knowledge cutoff",
        "as a large language model",
        "i'm just a language model",
        "narration",
        "apologize"
    ]
    for line in lines:
        check_line = line.lower().strip()
        if any(kw in check_line for kw in ignore_keywords):
            continue
        # Also remove lines that are purely polite or filler:
        if check_line.startswith("sure,") or check_line.startswith("certainly,"):
            continue
        filtered.append(line)
    return "\n".join(filtered)

# -------------------------
# Simulation State (Dummy Data)
# -------------------------
simulation_state = {
    "daily_metrics": {
        "attacks": {"total": 100, "successful": 25, "blocked": 75},
        "defenses": {"total": 50, "successful": 40, "failed": 10},
        "incidents": {
            "severity": {"high": 2, "medium": 5, "low": 8},
            "total": 15
        }
    },
    "status": "idle",
    "current_report": "No incidents reported.",
    "team_tasks": {
        "red_team": {
            "progress": 80,
            "daily_tasks": [
                {"name": "Initial Recon", "status": "completed"},
                {"name": "Exploit Vulnerability", "status": "pending"}
            ]
        },
        "blue_team": {
            "progress": 70,
            "daily_tasks": [
                {"name": "Deploy Firewall Rules", "status": "completed"},
                {"name": "Intrusion Prevention", "status": "pending"}
            ]
        },
        "soc_analyst": {
            "progress": 90,
            "daily_tasks": [
                {"name": "Monitor SIEM Alerts", "status": "completed"},
                {"name": "Analyze Log Patterns", "status": "pending"}
            ]
        }
    },
    "virtual_machines": [],
    "logs": {
        "redTeam": [],
        "blueTeam": [],
        "socAnalyst": [],
        "incidentResponse": [],
        "siem": []
    },
    "threat_intel": "No current threats detected.",
    "vuln_scan": "No vulnerabilities found."
}

# -------------------------
# HTML Template (Dashboard) - Same as before
# -------------------------
DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Ultimate Cybersecurity Simulation Platform</title>
  <style>
    @import url('https://cdn.replit.com/agent/bootstrap-agent-dark-theme.min.css');
    @import url('https://cdn.jsdelivr.net/npm/font-awesome@6.4.0/css/all.css');
    body { background: #121212; color: #ddd; }
    .simulation-log { height: 300px; overflow-y: auto; padding: 10px; background: var(--bs-dark); border-radius: 5px; font-family: monospace; }
    .log-entry { margin-bottom: 10px; padding: 8px; border-radius: 4px; background: var(--bs-gray-800); border-left: 4px solid transparent; }
    .log-entry.error { background: var(--bs-danger-bg-subtle); border-left-color: var(--bs-danger); color: var(--bs-danger-text); }
    .metric-card { background: var(--bs-gray-800); border-radius: 8px; padding: 15px; margin-bottom: 15px; }
    .metric-title { font-size: 1.1em; color: var(--bs-gray-500); margin-bottom: 10px; }
    .activity-report { font-family: monospace; background: var(--bs-gray-900); padding: 15px; border-radius: 8px; white-space: pre-wrap; max-height: 200px; overflow-y: auto; }
    .btn-control { min-width: 150px; }
    .nav-bar { margin-bottom: 20px; }
    @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
    .fa-spin { animation: spin 1s linear infinite; }
    .task-list { list-style: none; padding: 0; }
  </style>
</head>
<body>
  <!-- Navigation Bar -->
  <nav class="navbar navbar-dark bg-dark nav-bar">
    <div class="container-fluid">
      <a class="navbar-brand" href="/">CyberSim Platform</a>
      <div>
        <a href="/learn" class="btn btn-outline-light">LEARN</a>
        <a href="/agents" class="btn btn-outline-light">AGENTS</a>
      </div>
    </div>
  </nav>
  
  <div class="container-fluid py-4">
    <h1 class="text-center mb-4">Ultimate Cybersecurity Simulation Platform</h1>

    <!-- Daily Metrics -->
    <div class="row mb-4">
      <div class="col-md-3">
        <div class="metric-card">
          <div class="metric-title"><i class="fas fa-shield-alt"></i> Attack Statistics</div>
          <div class="d-flex justify-content-between mb-2"><span>Total Attacks:</span><span>{{ simulation_state.daily_metrics.attacks.total }}</span></div>
          <div class="d-flex justify-content-between mb-2"><span>Successful:</span><span class="text-danger">{{ simulation_state.daily_metrics.attacks.successful }}</span></div>
          <div class="d-flex justify-content-between"><span>Blocked:</span><span class="text-success">{{ simulation_state.daily_metrics.attacks.blocked }}</span></div>
        </div>
      </div>
      <div class="col-md-3">
        <div class="metric-card">
          <div class="metric-title"><i class="fas fa-shield-alt"></i> Defense Statistics</div>
          <div class="d-flex justify-content-between mb-2"><span>Total Defenses:</span><span>{{ simulation_state.daily_metrics.defenses.total }}</span></div>
          <div class="d-flex justify-content-between mb-2"><span>Successful:</span><span class="text-success">{{ simulation_state.daily_metrics.defenses.successful }}</span></div>
          <div class="d-flex justify-content-between"><span>Failed:</span><span class="text-danger">{{ simulation_state.daily_metrics.defenses.failed }}</span></div>
        </div>
      </div>
      <div class="col-md-3">
        <div class="metric-card">
          <div class="metric-title"><i class="fas fa-exclamation-triangle"></i> Incident Severity</div>
          <div class="d-flex justify-content-between mb-2"><span>High:</span><span class="text-danger">{{ simulation_state.daily_metrics.incidents.severity.high }}</span></div>
          <div class="d-flex justify-content-between mb-2"><span>Medium:</span><span class="text-warning">{{ simulation_state.daily_metrics.incidents.severity.medium }}</span></div>
          <div class="d-flex justify-content-between"><span>Low:</span><span class="text-info">{{ simulation_state.daily_metrics.incidents.severity.low }}</span></div>
        </div>
      </div>
      <div class="col-md-3">
        <div class="metric-card">
          <div class="metric-title"><i class="fas fa-chart-line"></i> Overall Statistics</div>
          <div class="d-flex justify-content-between mb-2"><span>Total Incidents:</span><span>{{ simulation_state.daily_metrics.incidents.total }}</span></div>
          <div class="d-flex justify-content-between">
            <span>Current Status:</span>
            <span class="badge bg-{{ 'success' if simulation_state.status == 'idle' else 'warning' }}">{{ simulation_state.status.replace('_', ' ').title() }}</span>
          </div>
        </div>
      </div>
    </div>

    <!-- Activity Report -->
    <div class="row mb-4">
      <div class="col-12">
        <div class="metric-card">
          <div class="metric-title"><i class="fas fa-file-alt"></i> Activity Report</div>
          <pre id="activityReport" class="activity-report">{{ simulation_state.current_report }}</pre>
        </div>
      </div>
    </div>

    <!-- Team Tasks Overview -->
    <div class="row mb-4">
      <div class="col-md-4">
        <div class="metric-card">
          <div class="metric-title"><i class="fas fa-user-ninja"></i> Red Team Tasks <span class="badge bg-primary float-end">{{ simulation_state.team_tasks.red_team.progress }}%</span></div>
          <div class="task-list">
            {% for task in simulation_state.team_tasks.red_team.daily_tasks %}
              <div class="d-flex justify-content-between align-items-center mb-2">
                <span>{{ task.name }}</span>
                <span class="badge bg-{{ 'success' if task.status == 'completed' else 'warning' }}">{{ task.status.title() }}</span>
              </div>
            {% endfor %}
          </div>
        </div>
      </div>
      <div class="col-md-4">
        <div class="metric-card">
          <div class="metric-title"><i class="fas fa-shield-alt"></i> Blue Team Tasks <span class="badge bg-primary float-end">{{ simulation_state.team_tasks.blue_team.progress }}%</span></div>
          <div class="task-list">
            {% for task in simulation_state.team_tasks.blue_team.daily_tasks %}
              <div class="d-flex justify-content-between align-items-center mb-2">
                <span>{{ task.name }}</span>
                <span class="badge bg-{{ 'success' if task.status == 'completed' else 'warning' }}">{{ task.status.title() }}</span>
              </div>
            {% endfor %}
          </div>
        </div>
      </div>
      <div class="col-md-4">
        <div class="metric-card">
          <div class="metric-title"><i class="fas fa-eye"></i> SOC Analyst Tasks <span class="badge bg-primary float-end">{{ simulation_state.team_tasks.soc_analyst.progress }}%</span></div>
          <div class="task-list">
            {% for task in simulation_state.team_tasks.soc_analyst.daily_tasks %}
              <div class="d-flex justify-content-between align-items-center mb-2">
                <span>{{ task.name }}</span>
                <span class="badge bg-{{ 'success' if task.status == 'completed' else 'warning' }}">{{ task.status.title() }}</span>
              </div>
            {% endfor %}
          </div>
        </div>
      </div>
    </div>

    <!-- Control Buttons -->
    <div class="text-center mb-4">
      <button id="triggerSimulation" class="btn btn-success btn-lg btn-control me-2"><i class="fas fa-play"></i> Start Simulation</button>
      <button id="stopSimulation" class="btn btn-danger btn-lg btn-control" style="display: none;"><i class="fas fa-stop"></i> Stop Simulation</button>
    </div>

    <!-- Team Panels (Logs) -->
    <div class="row">
      <div class="col-md-4">
        <div class="card h-100">
          <div class="card-header bg-danger text-white"><h4><i class="fas fa-user-ninja"></i> Red Team</h4></div>
          <div class="card-body">
            <div id="redTeamLog" class="simulation-log">
              {% for log in simulation_state.logs.redTeam %}
                <div class="log-entry">{{ log }}</div>
              {% endfor %}
            </div>
          </div>
        </div>
      </div>
      <div class="col-md-4">
        <div class="card h-100">
          <div class="card-header bg-primary text-white"><h4><i class="fas fa-shield-alt"></i> Blue Team</h4></div>
          <div class="card-body">
            <div id="blueTeamLog" class="simulation-log">
              {% for log in simulation_state.logs.blueTeam %}
                <div class="log-entry">{{ log }}</div>
              {% endfor %}
            </div>
          </div>
        </div>
      </div>
      <div class="col-md-4">
        <div class="card h-100">
          <div class="card-header bg-info text-white"><h4><i class="fas fa-eye"></i> SOC Analyst</h4></div>
          <div class="card-body">
            <div id="socAnalystLog" class="simulation-log">
              {% for log in simulation_state.logs.socAnalyst %}
                <div class="log-entry">{{ log }}</div>
              {% endfor %}
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Additional Panels -->
    <div class="row mt-4">
      <!-- Virtual Machines Panel -->
      <div class="col-md-6">
        <div class="metric-card">
          <div class="metric-title"><i class="fas fa-server"></i> Virtual Machines</div>
          <div id="vmList">
            {% for vm in simulation_state.virtual_machines %}
              <div class="d-flex justify-content-between align-items-center mb-2">
                <span>{{ vm.name }} - {{ vm.ip }}</span>
              </div>
            {% else %}
              <p>No virtual machines added.</p>
            {% endfor %}
          </div>
          <div class="mt-3">
            <input type="text" id="vmName" placeholder="VM Name" class="form-control mb-2" />
            <input type="text" id="vmIP" placeholder="IP Address" class="form-control mb-2" />
            <button id="addVMButton" class="btn btn-primary">Add Virtual Machine</button>
          </div>
        </div>
      </div>
      <!-- Threat Intelligence & Vulnerability Scan Panel -->
      <div class="col-md-6">
        <div class="metric-card">
          <div class="metric-title"><i class="fas fa-bell"></i> Threat Intelligence</div>
          <div id="threatIntel" class="mb-3">{{ simulation_state.threat_intel }}</div>
          <button id="refreshThreatIntel" class="btn btn-secondary mb-3"><i class="fas fa-sync"></i> Refresh Threat Feed</button>
          <div class="metric-title"><i class="fas fa-search"></i> Vulnerability Scan</div>
          <div id="vulnScan">{{ simulation_state.vuln_scan }}</div>
          <button id="runVulnScan" class="btn btn-secondary mt-2"><i class="fas fa-search-plus"></i> Run Vulnerability Scan</button>
        </div>
      </div>
    </div>

    <!-- Incident Response & SIEM Panel -->
    <div class="row mt-4">
      <div class="col-md-6">
        <div class="metric-card">
          <div class="metric-title"><i class="fas fa-tools"></i> Incident Response</div>
          <div id="incidentResponse" class="simulation-log" style="height:200px;">
            {% for log in simulation_state.logs.incidentResponse %}
              <div class="log-entry">{{ log }}</div>
            {% endfor %}
          </div>
          <button id="refreshIncidentResponse" class="btn btn-secondary mt-2"><i class="fas fa-sync"></i> Refresh Incident Response</button>
        </div>
      </div>
      <div class="col-md-6">
        <div class="metric-card">
          <div class="metric-title"><i class="fas fa-chart-bar"></i> SIEM Integration</div>
          <div id="siemLog" class="simulation-log" style="height:200px;">
            {% for log in simulation_state.logs.siem %}
              <div class="log-entry">{{ log }}</div>
            {% endfor %}
          </div>
          <button id="refreshSIEM" class="btn btn-secondary mt-2"><i class="fas fa-sync"></i> Refresh SIEM Dashboard</button>
        </div>
      </div>
    </div>

    <!-- Live Stream Panel -->
    <div class="row mt-4">
      <div class="col-12">
        <div class="metric-card">
          <div class="metric-title"><i class="fas fa-video"></i> Live Stream</div>
          <div id="liveStream" class="simulation-log" style="height:200px;">
            <p>Live updates will appear here...</p>
          </div>
        </div>
      </div>
    </div>

  </div>

  <!-- Inlined JavaScript for Interactivity -->
  <script>
    // Simulation control logic
    document.getElementById("triggerSimulation").addEventListener("click", function() {
      this.style.display = "none";
      document.getElementById("stopSimulation").style.display = "inline-block";
      fetch("/simulate")
        .then(response => response.json())
        .then(data => {
          document.getElementById("redTeamLog").innerHTML = data.logs.redTeam.map(l => `<div class="log-entry">${l}</div>`).join("");
          document.getElementById("blueTeamLog").innerHTML = data.logs.blueTeam.map(l => `<div class="log-entry">${l}</div>`).join("");
          document.getElementById("socAnalystLog").innerHTML = data.logs.socAnalyst.map(l => `<div class="log-entry">${l}</div>`).join("");
          document.getElementById("activityReport").textContent = data.current_report;
        })
        .catch(error => console.error("Simulation error:", error));
    });
    document.getElementById("stopSimulation").addEventListener("click", function() {
      this.style.display = "none";
      document.getElementById("triggerSimulation").style.display = "inline-block";
    });

    // Periodic polling for live stream
    setInterval(() => {
      fetch("/live_feed")
        .then(res => res.json())
        .then(data => {
          let combined = "";
          data.redTeam.forEach(line => combined += "<div class='log-entry'>[RED] " + line.replace(/\\n/g, '<br>') + "</div>");
          data.blueTeam.forEach(line => combined += "<div class='log-entry'>[BLUE] " + line.replace(/\\n/g, '<br>') + "</div>");
          data.socAnalyst.forEach(line => combined += "<div class='log-entry'>[SOC] " + line.replace(/\\n/g, '<br>') + "</div>");
          document.getElementById("liveStream").innerHTML = combined || "<p>No live logs yet...</p>";
        })
        .catch(err => console.error("Live feed error:", err));
    }, 5000);

    // Virtual Machine addition
    document.getElementById("addVMButton").addEventListener("click", function() {
      const vmName = document.getElementById("vmName").value;
      const vmIP = document.getElementById("vmIP").value;
      fetch("/add_vm", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: vmName, ip: vmIP })
      })
      .then(response => response.json())
      .then(data => {
        let html = "";
        if(data.virtual_machines.length > 0){
          data.virtual_machines.forEach(vm => { html += `<div class="d-flex justify-content-between align-items-center mb-2"><span>${vm.name} - ${vm.ip}</span></div>`; });
        } else { html = "<p>No virtual machines added.</p>"; }
        document.getElementById("vmList").innerHTML = html;
      })
      .catch(error => console.error("Error adding VM:", error));
    });

    // Threat Intelligence refresh
    document.getElementById("refreshThreatIntel").addEventListener("click", function() {
      fetch("/threat_feed")
        .then(response => response.json())
        .then(data => { document.getElementById("threatIntel").textContent = data.threat_intel; })
        .catch(error => console.error("Threat feed error:", error));
    });

    // Vulnerability scan trigger
    document.getElementById("runVulnScan").addEventListener("click", function() {
      fetch("/vuln_scan")
        .then(response => response.json())
        .then(data => { document.getElementById("vulnScan").textContent = data.vuln_scan; })
        .catch(error => console.error("Vulnerability scan error:", error));
    });

    // Incident Response refresh
    document.getElementById("refreshIncidentResponse").addEventListener("click", function() {
      fetch("/incident_response")
        .then(response => response.json())
        .then(data => {
          document.getElementById("incidentResponse").innerHTML = data.incident_response.map(l => `<div class="log-entry">${l}</div>`).join("");
        })
        .catch(error => console.error("Incident Response error:", error));
    });

    // SIEM dashboard refresh
    document.getElementById("refreshSIEM").addEventListener("click", function() {
      fetch("/siem")
        .then(response => response.json())
        .then(data => {
          document.getElementById("siemLog").innerHTML = data.siem.map(l => `<div class="log-entry">${l}</div>`).join("");
        })
        .catch(error => console.error("SIEM error:", error));
    });
  </script>
</body>
</html>
"""

LEARN_HTML = """<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Learn - Cybersecurity Simulation Platform</title>
  <style>
    @import url('https://cdn.replit.com/agent/bootstrap-agent-dark-theme.min.css');
    @import url('https://cdn.jsdelivr.net/npm/font-awesome@6.4.0/css/all.css');
    body { background: #121212; color: #ddd; font-family: sans-serif; }
    .container { margin: 30px auto; max-width: 800px; }
    h1, h2, h3 { color: #fff; }
    pre { background: #222; padding: 15px; border-radius: 5px; }
    .nav-bar { margin-bottom: 20px; }
  </style>
</head>
<body>
  <!-- Navigation Bar -->
  <nav class="navbar navbar-dark bg-dark nav-bar">
    <div class="container-fluid">
      <a class="navbar-brand" href="/">CyberSim Platform</a>
      <div>
        <a href="/learn" class="btn btn-outline-light">LEARN</a>
        <a href="/agents" class="btn btn-outline-light">AGENTS</a>
      </div>
    </div>
  </nav>

  <div class="container">
    <h1>Learn: Real-World Cybersecurity Simulation</h1>
    <p>This document explains how our platform simulates real-world cybersecurity scenarios using AI-driven techniques and virtualized environments.</p>
    
    <h2>Red Team Attack Scenarios</h2>
    <p><strong>Objective:</strong> The Red Team simulates offensive actions to identify vulnerabilities in virtual machines (VMs).</p>
    <h2>Blue Team Defense Strategies</h2>
    <p><strong>Objective:</strong> The Blue Team implements measures like firewalls, intrusion detection, and system hardening to prevent or mitigate attacks.</p>
    <h2>SOC Analyst Response Procedures</h2>
    <p><strong>Objective:</strong> SOC Analysts continuously monitor logs, SIEM, and system alerts to rapidly detect and respond to security incidents.</p>
    
    <h3>Generate Custom Commands & Scripts (DeepSeek)</h3>
    <p>Use the button below to request new AI-generated commands and scripts for training scenarios. The output aims to be strictly technical and concise.</p>
    <div>
      <button id="generateDeepSeek" class="btn btn-primary"><i class="fas fa-brain"></i> Generate from DeepSeek</button>
    </div>
    <div id="deepseekOutput" style="white-space: pre-wrap; background: #222; margin-top: 20px; padding: 10px; border-radius: 5px;"></div>
  </div>

  <script>
    document.getElementById("generateDeepSeek").addEventListener("click", function() {
      fetch("/learn/generate")
        .then(resp => resp.json())
        .then(data => {
          document.getElementById("deepseekOutput").textContent = data.generated;
        })
        .catch(err => console.error("DeepSeek generation error:", err));
    });
  </script>
</body>
</html>
"""

AGENTS_HTML = """<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Agents - Cybersecurity Simulation</title>
  <style>
    @import url('https://cdn.replit.com/agent/bootstrap-agent-dark-theme.min.css');
    @import url('https://cdn.jsdelivr.net/npm/font-awesome@6.4.0/css/all.css');
    body { background: #121212; color: #ddd; font-family: sans-serif; }
    .container { margin: 30px auto; max-width: 800px; }
    h1, h2, h3 { color: #fff; }
    .nav-bar { margin-bottom: 20px; }
    .agent-card {
      background: #222;
      border-radius: 8px;
      padding: 15px;
      margin-bottom: 15px;
    }
  </style>
</head>
<body>
  <nav class="navbar navbar-dark bg-dark nav-bar">
    <div class="container-fluid">
      <a class="navbar-brand" href="/">CyberSim Platform</a>
      <div>
        <a href="/learn" class="btn btn-outline-light">LEARN</a>
        <a href="/agents" class="btn btn-outline-light">AGENTS</a>
      </div>
    </div>
  </nav>

  <div class="container">
    <h1>Agents & Automation</h1>
    <p>Below are automated agents with assigned tasks for advanced operations.</p>

    <div class="agent-card">
      <h3>RedTeamAgent</h3>
      <p>Responsible for advanced network reconnaissance and exploitation tasks. Automatically calls AI to propose new exploits.</p>
      <button class="btn btn-warning" onclick="runAgent('RedTeamAgent')">Run RedTeamAgent</button>
      <div id="agentRedOutput" style="margin-top:10px; white-space: pre-wrap;"></div>
    </div>

    <div class="agent-card">
      <h3>BlueTeamAgent</h3>
      <p>Deploys defensive measures across the environment. Uses AI-driven automation to propose new firewall rules, patches, and system-hardening scripts.</p>
      <button class="btn btn-primary" onclick="runAgent('BlueTeamAgent')">Run BlueTeamAgent</button>
      <div id="agentBlueOutput" style="margin-top:10px; white-space: pre-wrap;"></div>
    </div>

    <div class="agent-card">
      <h3>SocAgent</h3>
      <p>Continuously monitors SIEM alerts and logs, escalating to incident response tasks automatically upon anomaly detection.</p>
      <button class="btn btn-info" onclick="runAgent('SocAgent')">Run SocAgent</button>
      <div id="agentSocOutput" style="margin-top:10px; white-space: pre-wrap;"></div>
    </div>
  </div>

  <script>
    function runAgent(agentName) {
      fetch('/agents/run?name=' + agentName)
        .then(resp => resp.json())
        .then(data => {
          if(agentName === 'RedTeamAgent') {
            document.getElementById("agentRedOutput").textContent = data.agent_output;
          } else if(agentName === 'BlueTeamAgent') {
            document.getElementById("agentBlueOutput").textContent = data.agent_output;
          } else if(agentName === 'SocAgent') {
            document.getElementById("agentSocOutput").textContent = data.agent_output;
          }
        })
        .catch(err => console.error("Agent run error:", err));
    }
  </script>
</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(DASHBOARD_HTML, simulation_state=simulation_state)

@app.route("/learn")
def learn():
    return render_template_string(LEARN_HTML)

@app.route("/agents")
def agents():
    return render_template_string(AGENTS_HTML)

@app.route("/simulate")
def simulate():
    red_log = (
        "=== Red Team Attack Log ===\n"
        "[2025-02-20 14:02:15] Command: nmap -A 192.168.1.10\n"
        "Output: Detected open ports 22, 80, 443; OS: Linux\n"
        "[2025-02-20 14:03:10] Command: msfconsole -q -x \"use exploit/unix/ftp/proftpd_modcopy_exec; set RHOST 192.168.1.10; run\"\n"
        "Output: Exploit successful; remote shell obtained on VM.\n"
    )
    blue_log = (
        "=== Blue Team Defense Log ===\n"
        "[2025-02-20 14:04:05] Command: iptables -A INPUT -s 192.168.1.10 -j DROP\n"
        "Output: Rule added; blocking malicious IP on VM.\n"
        "[2025-02-20 14:05:00] Command: fail2ban-client status sshd\n"
        "Output: 1 active ban; monitoring in place.\n"
    )
    soc_log = (
        "=== SOC Analyst Monitoring Log ===\n"
        "[2025-02-20 14:06:30] Command: splunk search 'index=security sourcetype=wineventlog' -earliest -5m\n"
        "Output: No critical alerts; minor anomalies detected.\n"
        "[2025-02-20 14:07:45] Command: siem check --all\n"
        "Output: All systems operational; no breaches confirmed.\n"
    )
    
    simulation_state["logs"]["redTeam"].append(red_log)
    simulation_state["logs"]["blueTeam"].append(blue_log)
    simulation_state["logs"]["socAnalyst"].append(soc_log)
    
    simulation_state["current_report"] = (
        "***** Cybersecurity Simulation Report *****\n\n" +
        red_log + "\n" +
        blue_log + "\n" +
        soc_log + "\n" +
        "----- End of Report -----"
    )
    
    return jsonify({
        "logs": simulation_state["logs"],
        "current_report": simulation_state["current_report"]
    })

@app.route("/add_vm", methods=["POST"])
def add_vm():
    data = request.get_json()
    vm_name = data.get("name")
    vm_ip = data.get("ip")
    if vm_name and vm_ip:
        simulation_state["virtual_machines"].append({"name": vm_name, "ip": vm_ip})
    return jsonify({"virtual_machines": simulation_state["virtual_machines"]})

@app.route("/threat_feed")
def threat_feed():
    simulation_state["threat_intel"] = "New threat detected: Suspicious outbound traffic from 192.168.1.200 at " + time.strftime("%H:%M:%S")
    return jsonify({"threat_intel": simulation_state["threat_intel"]})

@app.route("/vuln_scan")
def vuln_scan():
    simulation_state["vuln_scan"] = "Vulnerability Scan Complete: No critical vulnerabilities found as of " + time.strftime("%H:%M:%S")
    return jsonify({"vuln_scan": simulation_state["vuln_scan"]})

@app.route("/incident_response")
def incident_response():
    new_ir = "Incident Response Log: Detected lateral movement; command executed: 'netstat -an' at " + time.strftime("%H:%M:%S")
    simulation_state["logs"]["incidentResponse"].append(new_ir)
    return jsonify({"incident_response": simulation_state["logs"]["incidentResponse"]})

@app.route("/siem")
def siem():
    new_siem = "SIEM Update: Aggregated log review completed at " + time.strftime("%H:%M:%S")
    simulation_state["logs"]["siem"].append(new_siem)
    return jsonify({"siem": simulation_state["logs"]["siem"]})

@app.route("/live_feed")
def live_feed():
    return jsonify({
        "redTeam": simulation_state["logs"]["redTeam"][-3:],
        "blueTeam": simulation_state["logs"]["blueTeam"][-3:],
        "socAnalyst": simulation_state["logs"]["socAnalyst"][-3:]
    })

# -------------------------
# UPDATED: /learn/generate with post-processing
# -------------------------
@app.route("/learn/generate")
def learn_generate():
    prompt = (
        "Generate advanced Red Team and Blue Team commands and scripts that could be used "
        "in a realistic cybersecurity exercise, focusing on ephemeral exploits and hardened "
        "defense measures. Provide short code snippets."
    )
    result = deepseek_correction(prompt)
    final_result = parse_technical_output(result)  # filter out non-technical lines
    return jsonify({"generated": final_result})

# -------------------------
# Agents Endpoints with post-processing
# -------------------------
@app.route("/agents/run")
def run_agent():
    agent_name = request.args.get("name", "UnknownAgent")
    if agent_name == "RedTeamAgent":
        prompt = ("You are RedTeamAgent. Provide short, strictly technical commands for advanced exploitation "
                  "and network pivoting in a concise manner.")
    elif agent_name == "BlueTeamAgent":
        prompt = ("You are BlueTeamAgent. Provide short, strictly technical commands for firewall rule updates, "
                  "intrusion prevention, and system-hardening scripts in a concise manner.")
    elif agent_name == "SocAgent":
        prompt = ("You are SocAgent. Provide short, strictly technical commands for continuous SIEM monitoring, "
                  "alert correlation, and incident escalation in a concise manner.")
    else:
        prompt = f"You are {agent_name}. Provide short, strictly technical instructions."

    agent_output = deepseek_correction(prompt)
    final_output = parse_technical_output(agent_output)
    return jsonify({"agent_output": final_output})

# -------------------------
# Main
# -------------------------
if __name__ == "__main__":
    # Runs on 192.168.1.152:5008
    app.run(host="IP", port=5008, debug=True)
