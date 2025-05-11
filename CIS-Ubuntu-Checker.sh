#!/bin/bash

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: Run as root" >&2
    exit 1
fi

UBUNTU_VERSION=$(lsb_release -rs)
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_DIR="/var/log/cis_audit"
HTML_REPORT="$REPORT_DIR/cis_report_$TIMESTAMP.html"
JSON_REPORT="$REPORT_DIR/cis_report_$TIMESTAMP.json"
LOG_FILE="$REPORT_DIR/cis_execution_$TIMESTAMP.log"
SCORE_FILE="$REPORT_DIR/cis_scores.csv"

mkdir -p "$REPORT_DIR"
chmod 700 "$REPORT_DIR"

declare -A RESULTS
TOTAL_CHECKS=0
PASSED=0
FAILED=0
WARNING=0

init_report() {
    cat > "$HTML_REPORT" <<EOF
<!DOCTYPE html>
<html>
<head>
<title>CIS Ubuntu $UBUNTU_VERSION Audit</title>
<style>
body { font-family: Arial, sans-serif; margin: 20px; }
table { border-collapse: collapse; width: 100%; }
th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
th { background-color: #f2f2f2; }
.pass { background-color: #d4edda; }
.fail { background-color: #f8d7da; }
.warning { background-color: #fff3cd; }
</style>
</head>
<body>
<h1>CIS Ubuntu $UBUNTU_VERSION Audit Report</h1>
<p>Generated: $(date)</p>
<table>
<tr><th>Check ID</th><th>Description</th><th>Result</th><th>Remediation</th></tr>
EOF

    echo '{ "report": {' > "$JSON_REPORT"
    echo "\"timestamp\": \"$(date -Is)\"," >> "$JSON_REPORT"
    echo "\"ubuntu_version\": \"$UBUNTU_VERSION\"," >> "$JSON_REPORT"
    echo "\"checks\": [" >> "$JSON_REPORT"
}

add_check() {
    local id="$1"
    local desc="$2"
    local result="$3"
    local remediation="$4"
    
    ((TOTAL_CHECKS++))
    
    case $result in
        PASS) 
            ((PASSED++))
            class="pass"
            ;;
        FAIL) 
            ((FAILED++))
            class="fail"
            ;;
        *) 
            ((WARNING++))
            class="warning"
            ;;
    esac
    
    RESULTS["$id"]="$result"
    
    echo "<tr><td>$id</td><td>$desc</td><td class=\"$class\">$result</td><td>${remediation:-N/A}</td></tr>" >> "$HTML_REPORT"
    
    if [ $TOTAL_CHECKS -gt 1 ]; then
        echo "," >> "$JSON_REPORT"
    fi
    
    cat >> "$JSON_REPORT" <<EOF
    {
        "id": "$id",
        "description": "$desc",
        "result": "$result",
        "remediation": "${remediation:-N/A}"
    }
EOF
}

finalize_report() {
    echo "</table>" >> "$HTML_REPORT"
    
    echo "<h2>Summary</h2>" >> "$HTML_REPORT"
    echo "<p><strong>Passed:</strong> $PASSED</p>" >> "$HTML_REPORT"
    echo "<p><strong>Failed:</strong> $FAILED</p>" >> "$HTML_REPORT"
    echo "<p><strong>Warnings:</strong> $WARNING</p>" >> "$HTML_REPORT"
    echo "<p><strong>Compliance Score:</strong> $(( (PASSED * 100) / TOTAL_CHECKS ))%</p>" >> "$HTML_REPORT"
    
    echo "</body></html>" >> "$HTML_REPORT"
    
    echo "]}}" >> "$JSON_REPORT"
    
    echo "$TIMESTAMP,$PASSED,$FAILED,$WARNING,$(( (PASSED * 100) / TOTAL_CHECKS ))" >> "$SCORE_FILE"
}

check_file_perms() {
    local file="$1"
    local perm="$2"
    local owner="$3"
    local group="$4"
    local id="$5"
    
    if [ ! -e "$file" ]; then
        add_check "$id" "Verify $file permissions" "WARNING" "File does not exist"
        return
    fi
    
    local current_perm=$(stat -c "%a" "$file")
    local current_owner=$(stat -c "%U" "$file")
    local current_group=$(stat -c "%G" "$file")
    
    if [ "$current_perm" = "$perm" ] && [ "$current_owner" = "$owner" ] && [ "$current_group" = "$group" ]; then
        add_check "$id" "Verify $file permissions" "PASS"
    else
        add_check "$id" "Verify $file permissions" "FAIL" \
        "Run: chown $owner:$group $file && chmod $perm $file"
    fi
}

check_service() {
    local service="$1"
    local should_be_enabled="$2"
    local id="$3"
    
    if systemctl is-active "$service" &>/dev/null; then
        if [ "$should_be_enabled" = "yes" ]; then
            add_check "$id" "Check $service status" "PASS"
        else
            add_check "$id" "Check $service status" "FAIL" "Run: systemctl disable --now $service"
        fi
    else
        if [ "$should_be_enabled" = "yes" ]; then
            add_check "$id" "Check $service status" "FAIL" "Run: systemctl enable --now $service"
        else
            add_check "$id" "Check $service status" "PASS"
        fi
    fi
}

check_package() {
    local pkg="$1"
    local should_be_installed="$2"
    local id="$3"
    
    if dpkg -s "$pkg" &>/dev/null; then
        if [ "$should_be_installed" = "yes" ]; then
            add_check "$id" "Check $pkg package" "PASS"
        else
            add_check "$id" "Check $pkg package" "FAIL" "Run: apt remove $pkg"
        fi
    else
        if [ "$should_be_installed" = "yes" ]; then
            add_check "$id" "Check $pkg package" "FAIL" "Run: apt install $pkg"
        else
            add_check "$id" "Check $pkg package" "PASS"
        fi
    fi
}

check_kernel_param() {
    local param="$1"
    local expected_value="$2"
    local id="$3"
    
    local current_value=$(sysctl -n "$param" 2>/dev/null)
    
    if [ "$current_value" = "$expected_value" ]; then
        add_check "$id" "Check kernel parameter $param" "PASS"
    else
        add_check "$id" "Check kernel parameter $param" "FAIL" \
        "Add to /etc/sysctl.conf: $param = $expected_value"
    fi
}

run_audit() {
    init_report
    
    check_file_perms "/etc/passwd" "644" "root" "root" "1.1.1"
    check_file_perms "/etc/shadow" "640" "root" "shadow" "1.1.2"
    check_file_perms "/etc/group" "644" "root" "root" "1.1.3"
    
    check_service "ufw" "yes" "2.1.1"
    check_service "auditd" "yes" "2.2.1"
    
    check_package "openssh-server" "yes" "3.1.1"
    check_package "telnetd" "no" "3.1.2"
    
    check_kernel_param "net.ipv4.ip_forward" "0" "4.1.1"
    check_kernel_param "net.ipv4.conf.all.send_redirects" "0" "4.2.1"
    
    finalize_report
    
    chmod 600 "$HTML_REPORT" "$JSON_REPORT" "$SCORE_FILE"
    
    echo "Report generated: $HTML_REPORT"
    echo "JSON report: $JSON_REPORT"
    echo "Score saved to: $SCORE_FILE"
}

exec > >(tee -a "$LOG_FILE") 2>&1

run_audit
