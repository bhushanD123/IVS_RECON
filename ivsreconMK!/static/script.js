document.addEventListener('DOMContentLoaded', function() {
    const targetInput = document.getElementById('target-ip');
    const scanBtn = document.getElementById('scan-btn');
    const scanResults = document.getElementById('scan-results');
    const downloadBtn = document.getElementById('download-report');
    const spinner = scanBtn.querySelector('.spinner-border');

    let currentScanData = null;

    scanBtn.addEventListener('click', async function() {
        const targetIp = targetInput.value.trim();
        if (!targetIp) {
            alert('Please enter a target IP address');
            return;
        }

        // Show loading state
        scanBtn.disabled = true;
        spinner.classList.remove('d-none');
        scanResults.classList.add('d-none');

        try {
            const response = await fetch('/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: `target_ip=${encodeURIComponent(targetIp)}`
            });

            const data = await response.json();
            if (data.error) {
                throw new Error(data.error);
            }
            currentScanData = data;
            displayResults(data);
        } catch (error) {
            console.error('Scan failed:', error);
            alert('Scan failed: ' + error.message);
        } finally {
            scanBtn.disabled = false;
            spinner.classList.add('d-none');
        }
    });

    downloadBtn.addEventListener('click', function() {
        if (!currentScanData) return;

        const reportContent = generateReport(currentScanData);
        const blob = new Blob([reportContent], { type: 'text/plain' });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `security_scan_${new Date().toISOString().split('T')[0]}.txt`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
    });

    function displayResults(data) {
        // Display OS information
        const osInfo = document.getElementById('os-info');
        if (data.os_info && data.os_info.length > 0) {
            osInfo.innerHTML = data.os_info.map(os => `
                <div class="os-item mb-3">
                    <h5 class="mb-2">${os.name}</h5>
                    <div class="d-flex align-items-center mb-2">
                        <span class="badge bg-info me-2">Accuracy: ${os.accuracy}%</span>
                        ${os.line ? `<small class="text-muted">${os.line}</small>` : ''}
                    </div>
                    ${os.osclass && os.osclass.length > 0 ? `
                        <div class="os-details">
                            ${os.osclass.map(cls => `
                                <div class="mb-1">
                                    <span class="badge bg-secondary me-2">${cls.type || ''}</span>
                                    <span class="badge bg-secondary me-2">${cls.vendor || ''}</span>
                                    <span class="badge bg-secondary">${cls.osfamily || ''}</span>
                                </div>
                            `).join('')}
                        </div>
                    ` : ''}
                </div>
            `).join('');
        } else {
            osInfo.innerHTML = '<p class="text-muted">No OS information detected</p>';
        }

        // Display DNS enumeration results
        const dnsInfo = document.getElementById('dns-info');
        if (data.dns_enum) {
            let dnsHtml = '<div class="dns-section">';
            
            // Display DNS Records
            if (data.dns_enum.records && data.dns_enum.records.length > 0) {
                dnsHtml += `
                    <div class="dns-records mb-4">
                        <h4 class="mb-3">DNS Records</h4>
                        <div class="table-responsive">
                            <table class="table table-dark table-hover">
                                <thead>
                                    <tr>
                                        <th>Type</th>
                                        <th>Name</th>
                                        <th>Value</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    ${data.dns_enum.records.map(record => `
                                        <tr>
                                            <td><span class="badge bg-info">${record.type}</span></td>
                                            <td>${record.name}</td>
                                            <td><code>${record.value}</code></td>
                                        </tr>
                                    `).join('')}
                                </tbody>
                            </table>
                        </div>
                    </div>
                `;
            }
            
            // Display Subdomains
            if (data.dns_enum.subdomains && data.dns_enum.subdomains.length > 0) {
                dnsHtml += `
                    <div class="subdomains mb-4">
                        <h4 class="mb-3">Discovered Subdomains</h4>
                        ${data.dns_enum.subdomains.map(sub => `
                            <div class="subdomain-item mb-3">
                                <h5 class="mb-2">
                                    <span class="badge bg-success me-2">Active</span>
                                    ${sub.subdomain}
                                </h5>
                                <div class="subdomain-details">
                                    <p class="mb-1">
                                        <strong>IP Addresses:</strong>
                                        ${sub.ip.map(ip => `
                                            <code class="ms-2">${ip}</code>
                                        `).join('')}
                                    </p>
                                </div>
                            </div>
                        `).join('')}
                    </div>
                `;
            }
            
            // Display Service Records
            if (data.dns_enum.services && data.dns_enum.services.length > 0) {
                dnsHtml += `
                    <div class="dns-services mb-4">
                        <h4 class="mb-3">Service Records</h4>
                        <div class="table-responsive">
                            <table class="table table-dark table-hover">
                                <thead>
                                    <tr>
                                        <th>Service</th>
                                        <th>Port</th>
                                        <th>Priority</th>
                                        <th>Weight</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    ${data.dns_enum.services.map(service => `
                                        <tr>
                                            <td>${service.service}</td>
                                            <td><span class="badge bg-primary">${service.port}</span></td>
                                            <td>${service.priority}</td>
                                            <td>${service.weight}</td>
                                        </tr>
                                    `).join('')}
                                </tbody>
                            </table>
                        </div>
                    </div>
                `;
            }
            
            dnsHtml += '</div>';
            dnsInfo.innerHTML = dnsHtml;
        } else {
            dnsInfo.innerHTML = '<p class="text-muted">No DNS information available</p>';
        }

        // Display ports and services
        const portsTable = document.getElementById('ports-table');
        portsTable.innerHTML = '';
        data.ports.forEach(port => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${port.port}</td>
                <td>${port.service}</td>
                <td>${port.version || 'Unknown'}</td>
                <td><span class="badge ${port.state === 'open' ? 'badge-open' : 'badge-closed'}">${port.state}</span></td>
            `;
            portsTable.appendChild(row);
        });

        // Display API endpoints
        const apisInfo = document.getElementById('apis-info');
        if (data.api_endpoints && data.api_endpoints.length > 0) {
            apisInfo.innerHTML = data.api_endpoints.map(endpoint => `
                <div class="api-item mb-3">
                    <h5 class="mb-2">
                        <span class="badge ${getApiTypeClass(endpoint.type)}">${endpoint.type}</span>
                    </h5>
                    <div class="api-details">
                        <p class="mb-1">
                            <strong>URL:</strong> 
                            <a href="${endpoint.url}" target="_blank" class="text-info">${endpoint.url}</a>
                        </p>
                        ${endpoint.status_code ? `
                            <p class="mb-1">
                                <strong>Status:</strong> 
                                <span class="badge bg-${getStatusCodeClass(endpoint.status_code)}">
                                    ${endpoint.status_code}
                                </span>
                            </p>
                        ` : ''}
                        ${endpoint.server ? `
                            <p class="mb-1"><strong>Server:</strong> ${endpoint.server}</p>
                        ` : ''}
                        ${endpoint.powered_by ? `
                            <p class="mb-1"><strong>Powered By:</strong> ${endpoint.powered_by}</p>
                        ` : ''}
                        ${endpoint.content_type ? `
                            <p class="mb-1"><strong>Content Type:</strong> ${endpoint.content_type}</p>
                        ` : ''}
                    </div>
                </div>
            `).join('');
        } else {
            apisInfo.innerHTML = '<p class="text-muted">No APIs detected</p>';
        }

        // Display CVEs
        const vulnsInfo = document.getElementById('vulns-info');
        if (data.cves && data.cves.length > 0) {
            vulnsInfo.innerHTML = data.cves.map(service => `
                <div class="vulnerability-item mb-4">
                    <h4 class="mb-3">
                        <span class="service-badge">${service.service}</span>
                        ${service.version ? `<span class="version-badge">v${service.version}</span>` : ''}
                        <span class="badge bg-secondary">Port ${service.port}</span>
                    </h4>
                    <div class="cve-list">
                        ${service.vulnerabilities.map(cve => `
                            <div class="cve-item mb-3">
                                <h5 class="d-flex justify-content-between">
                                    <span>${cve.id}</span>
                                    <span class="badge ${getSeverityClass(cve.severity)}">
                                        Severity: ${cve.severity}
                                    </span>
                                </h5>
                                <p class="text-muted mb-0">${cve.description}</p>
                            </div>
                        `).join('')}
                    </div>
                </div>
            `).join('');
        } else {
            vulnsInfo.innerHTML = '<p class="text-muted">No CVEs detected for the running services</p>';
        }

        // Display web vulnerabilities
        const webVulnsInfo = document.getElementById('web-vulns-info');
        if (data.xss_vulns && data.xss_vulns.length > 0) {
            webVulnsInfo.innerHTML = `
                <div class="vulnerability-section mb-4">
                    <h4 class="mb-3">Cross-Site Scripting (XSS) Vulnerabilities</h4>
                    ${data.xss_vulns.map(vuln => `
                        <div class="vulnerability-item mb-3">
                            <div class="d-flex justify-content-between align-items-center mb-2">
                                <h5 class="mb-0">
                                    <span class="badge bg-danger me-2">${vuln.type}</span>
                                    <span class="badge bg-secondary">${vuln.location}</span>
                                </h5>
                            </div>
                            <div class="vuln-details">
                                <p class="mb-1"><strong>URL:</strong> <code>${vuln.url}</code></p>
                                ${vuln.parameter ? `
                                    <p class="mb-1"><strong>Parameter:</strong> <code>${vuln.parameter}</code></p>
                                ` : ''}
                                ${vuln.payload ? `
                                    <p class="mb-1"><strong>Payload:</strong> <code>${escapeHtml(vuln.payload)}</code></p>
                                ` : ''}
                                ${vuln.evidence ? `
                                    <p class="mb-1"><strong>Evidence:</strong> <code>${vuln.evidence}</code></p>
                                ` : ''}
                                ${vuln.method ? `
                                    <p class="mb-1"><strong>Method:</strong> <code>${vuln.method.toUpperCase()}</code></p>
                                ` : ''}
                            </div>
                        </div>
                    `).join('')}
                </div>
            `;
            
            if (data.vulns && data.vulns.length > 0) {
                webVulnsInfo.innerHTML += data.vulns.map(vuln => `
                    <div class="vulnerability-item">
                        <h4>${vuln.type}</h4>
                        <pre class="mt-2"><code>${JSON.stringify(vuln.details, null, 2)}</code></pre>
                    </div>
                `).join('');
            }
        } else if (data.vulns && data.vulns.length > 0) {
            webVulnsInfo.innerHTML = data.vulns.map(vuln => `
                <div class="vulnerability-item">
                    <h4>${vuln.type}</h4>
                    <pre class="mt-2"><code>${JSON.stringify(vuln.details, null, 2)}</code></pre>
                </div>
            `).join('');
        } else {
            webVulnsInfo.innerHTML = '<p class="text-muted">No web vulnerabilities detected</p>';
        }

        // Display suggested exploits
        const exploitsInfo = document.getElementById('exploits-info');
        if (data.suggested_exploits && data.suggested_exploits.length > 0) {
            exploitsInfo.innerHTML = data.suggested_exploits.map(exploit => `
                <div class="exploit-item">
                    <h5><i class="bi bi-lightning-charge"></i> ${exploit}</h5>
                    <span class="badge service-badge">service-based</span>
                </div>
            `).join('');
        } else {
            exploitsInfo.innerHTML = '<p class="text-muted">No suggested exploits available</p>';
        }

        // Show results
        scanResults.classList.remove('d-none');
    }

    function getSeverityClass(severity) {
        const score = parseFloat(severity);
        if (isNaN(score)) return 'bg-secondary';
        if (score >= 9.0) return 'bg-danger';
        if (score >= 7.0) return 'bg-warning text-dark';
        if (score >= 4.0) return 'bg-info';
        return 'bg-success';
    }

    function getApiTypeClass(type) {
        switch (type.toLowerCase()) {
            case 'openapi/swagger':
                return 'bg-success';
            case 'graphql':
                return 'bg-primary';
            case 'rest api':
                return 'bg-info';
            case 'wordpress rest api':
                return 'bg-warning text-dark';
            case 'web server':
                return 'bg-secondary';
            default:
                return 'bg-secondary';
        }
    }

    function getStatusCodeClass(code) {
        if (code >= 500) return 'danger';
        if (code >= 400) return 'warning';
        if (code >= 300) return 'info';
        if (code >= 200) return 'success';
        return 'secondary';
    }

    function escapeHtml(unsafe) {
        return unsafe
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    function generateReport(data) {
        const lines = [
            '=== Security Assessment Report ===',
            `Scan Date: ${new Date().toISOString()}`,
            '',
            '=== DNS Enumeration Results ===',
            '--- DNS Records ---',
            ...(data.dns_enum && data.dns_enum.records.length ? data.dns_enum.records.map(record =>
                `${record.type}: ${record.name} -> ${record.value}`
            ) : ['No DNS records found']),
            '',
            '--- Discovered Subdomains ---',
            ...(data.dns_enum && data.dns_enum.subdomains.length ? data.dns_enum.subdomains.map(sub => [
                `Subdomain: ${sub.subdomain}`,
                `IP Addresses: ${sub.ip.join(', ')}`,
                ''
            ]).flat() : ['No subdomains discovered']),
            '',
            '--- Service Records ---',
            ...(data.dns_enum && data.dns_enum.services.length ? data.dns_enum.services.map(service =>
                `Service: ${service.service} (Port: ${service.port}, Priority: ${service.priority}, Weight: ${service.weight})`
            ) : ['No service records found']),
            '',
            '=== Operating System Detection ===',
            ...(data.os_info.length ? data.os_info.map(os => 
                `${os.name} (Accuracy: ${os.accuracy}%)\n${os.line || ''}`
            ) : ['No OS detected']),
            '',
            '=== Detected APIs and Web Services ===',
            ...(data.api_endpoints.length ? data.api_endpoints.map(endpoint => [
                `Type: ${endpoint.type}`,
                `URL: ${endpoint.url}`,
                endpoint.status_code ? `Status: ${endpoint.status_code}` : '',
                endpoint.server ? `Server: ${endpoint.server}` : '',
                endpoint.powered_by ? `Powered By: ${endpoint.powered_by}` : '',
                endpoint.content_type ? `Content Type: ${endpoint.content_type}` : '',
                ''
            ].filter(Boolean)) : ['No APIs detected']).flat(),
            '',
            '=== Open Ports and Services ===',
            ...data.ports.map(port => 
                `Port ${port.port} (${port.state}): ${port.service} ${port.version ? '- ' + port.version : ''}`
            ),
            '',
            '=== CVEs ===',
            ...(data.cves.length ? data.cves.map(service => [
                `\nService: ${service.service} ${service.version ? 'v' + service.version : ''} (Port ${service.port})`,
                ...service.vulnerabilities.map(cve =>
                    `${cve.id} (Severity: ${cve.severity})\n${cve.description}`
                )
            ]).flat() : ['No CVEs detected']),
            '',
            '=== Nmap Vulnerability Scripts ===',
            ...(data.vulns.length ? data.vulns.map(vuln => 
                `${vuln.type}:\n${JSON.stringify(vuln.details, null, 2)}`
            ) : ['No vulnerabilities detected']),
            '',
            '=== Suggested Exploits ===',
            ...(data.suggested_exploits.length ? data.suggested_exploits : ['No suggested exploits']),
            '',
            '=== Web Application Vulnerabilities ===',
            '--- XSS Vulnerabilities ---',
            ...(data.xss_vulns && data.xss_vulns.length ? data.xss_vulns.map(vuln => [
                `Type: ${vuln.type}`,
                `Location: ${vuln.location}`,
                `URL: ${vuln.url}`,
                vuln.parameter ? `Parameter: ${vuln.parameter}` : '',
                vuln.payload ? `Payload: ${vuln.payload}` : '',
                vuln.evidence ? `Evidence: ${vuln.evidence}` : '',
                vuln.method ? `Method: ${vuln.method.toUpperCase()}` : '',
                ''
            ].filter(Boolean)) : ['No XSS vulnerabilities detected']).flat(),
        ];

        return lines.join('\n');
    }
}); 