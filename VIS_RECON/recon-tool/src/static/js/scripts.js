// This file contains JavaScript code for client-side functionality, such as handling form submissions and dynamically updating the results displayed on the web page.

document.addEventListener('DOMContentLoaded', function() {
    const form = document.getElementById('target-form');
    const resultsContainer = document.getElementById('results');

    form.addEventListener('submit', function(event) {
        event.preventDefault();
        const targetIP = document.getElementById('target-ip').value;

        fetch(`/scan?target=${targetIP}`, {
            method: 'GET'
        })
        .then(response => response.json())
        .then(data => {
            updateResults(data);
        })
        .catch(error => {
            console.error('Error:', error);
            resultsContainer.innerHTML = '<p>Error fetching results. Please try again.</p>';
        });
    });

    function updateResults(data) {
        resultsContainer.innerHTML = ''; // Clear previous results

        if (data.error) {
            resultsContainer.innerHTML = `<p>${data.error}</p>`;
            return;
        }

        const table = document.createElement('table');
        const headerRow = document.createElement('tr');
        headerRow.innerHTML = '<th>Service</th><th>Version</th><th>State</th>';
        table.appendChild(headerRow);

        data.results.forEach(result => {
            const row = document.createElement('tr');
            row.innerHTML = `<td>${result.service}</td><td>${result.version}</td><td>${result.state}</td>`;
            table.appendChild(row);
        });

        resultsContainer.appendChild(table);
    }
});