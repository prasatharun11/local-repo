<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dynamic Actuator Health Check</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        body {
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        
        header {
            text-align: center;
            margin-bottom: 30px;
            padding: 20px;
            background: white;
            border-radius: 10px;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1);
        }
        
        h1 {
            color: #2c3e50;
            margin-bottom: 10px;
        }
        
        .description {
            color: #7f8c8d;
            max-width: 800px;
            margin: 0 auto;
        }
        
        .controls {
            background: white;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 30px;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1);
        }
        
        .form-title {
            margin-bottom: 15px;
            color: #2c3e50;
            padding-bottom: 10px;
            border-bottom: 1px solid #eee;
        }
        
        .input-group {
            display: flex;
            gap: 15px;
            margin-bottom: 15px;
            flex-wrap: wrap;
        }
        
        .input-field {
            flex: 1;
            min-width: 250px;
        }
        
        .input-field label {
            display: block;
            margin-bottom: 5px;
            font-weight: 600;
            color: #2c3e50;
        }
        
        .input-field input {
            width: 100%;
            padding: 10px 15px;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-size: 16px;
        }
        
        .btn {
            padding: 10px 20px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-weight: 600;
            transition: all 0.3s ease;
        }
        
        .btn-primary {
            background: #3498db;
            color: white;
        }
        
        .btn-primary:hover {
            background: #2980b9;
        }
        
        .btn-danger {
            background: #e74c3c;
            color: white;
        }
        
        .btn-danger:hover {
            background: #c0392b;
        }
        
        .btn-refresh-all {
            background: #2c3e50;
            color: white;
            display: block;
            width: 100%;
            padding: 12px;
            font-size: 16px;
        }
        
        .btn-refresh-all:hover {
            background: #1a252f;
        }
        
        .dashboard {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .card {
            background: white;
            border-radius: 10px;
            padding: 20px;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1);
            transition: transform 0.3s ease;
        }
        
        .card:hover {
            transform: translateY(-5px);
        }
        
        .card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
            padding-bottom: 15px;
            border-bottom: 1px solid #f1f1f1;
        }
        
        .service-name {
            font-weight: 600;
            color: #2c3e50;
            font-size: 18px;
        }
        
        .endpoint-url {
            font-size: 12px;
            color: #7f8c8d;
            word-break: break-all;
            margin-top: 5px;
        }
        
        .status-indicator {
            display: inline-block;
            padding: 5px 10px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
        }
        
        .status-up {
            background-color: #e8f7ef;
            color: #27ae60;
        }
        
        .status-down {
            background-color: #ffe9e9;
            color: #e74c3c;
        }
        
        .status-unknown {
            background-color: #f3f3f3;
            color: #7f8c8d;
        }
        
        .card-body {
            margin-bottom: 15px;
        }
        
        .info-row {
            display: flex;
            justify-content: space-between;
            margin-bottom: 10px;
        }
        
        .info-label {
            color: #7f8c8d;
        }
        
        .info-value {
            font-weight: 500;
            color: #2c3e50;
        }
        
        .card-footer {
            display: flex;
            justify-content: space-between;
        }
        
        .btn-refresh {
            background: #3498db;
            color: white;
        }
        
        .btn-refresh:hover {
            background: #2980b9;
        }
        
        .btn-remove {
            background: #f8f9fa;
            color: #e74c3c;
            border: 1px solid #eaecef;
        }
        
        .btn-remove:hover {
            background: #ffe9e9;
        }
        
        .last-updated {
            text-align: center;
            margin-top: 20px;
            color: #7f8c8d;
            font-size: 14px;
        }
        
        .empty-state {
            text-align: center;
            padding: 40px;
            background: white;
            border-radius: 10px;
            grid-column: 1 / -1;
        }
        
        .empty-state i {
            font-size: 48px;
            color: #bdc3c7;
            margin-bottom: 15px;
        }
        
        .empty-state p {
            color: #7f8c8d;
            margin-bottom: 20px;
        }
        
        @media (max-width: 768px) {
            .dashboard {
                grid-template-columns: 1fr;
            }
            
            .input-group {
                flex-direction: column;
            }
            
            .input-field {
                min-width: 100%;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Dynamic Actuator Health Check Dashboard</h1>
            <p class="description">Add your actuator endpoints with custom names and monitor their health status in real-time.</p>
        </header>
        
        <div class="controls">
            <h2 class="form-title">Add New Endpoint</h2>
            <div class="input-group">
                <div class="input-field">
                    <label for="service-name">Service Name</label>
                    <input type="text" id="service-name" placeholder="e.g., User Service">
                </div>
                <div class="input-field">
                    <label for="endpoint-url">Endpoint URL</label>
                    <input type="text" id="endpoint-url" placeholder="e.g., https://api.example.com/actuator/health">
                </div>
                <div class="input-field" style="display: flex; align-items: flex-end;">
                    <button id="add-endpoint" class="btn btn-primary">Add Endpoint</button>
                </div>
            </div>
            
            <button id="refresh-all" class="btn btn-refresh-all">Refresh All Checks</button>
        </div>
        
        <div class="dashboard" id="endpoints-container">
            <!-- Endpoint cards will be added here dynamically -->
            <div class="empty-state" id="empty-state">
                <i class="fas fa-plus-circle"></i>
                <p>No endpoints added yet. Add your first endpoint to begin monitoring.</p>
            </div>
        </div>
        
        <div class="last-updated">
            Last updated: <span id="current-time">Just now</span>
        </div>
    </div>

    <script>
        // Store endpoints
        let endpoints = [];
        
        // DOM elements
        const serviceNameInput = document.getElementById('service-name');
        const endpointUrlInput = document.getElementById('endpoint-url');
        const addEndpointBtn = document.getElementById('add-endpoint');
        const refreshAllBtn = document.getElementById('refresh-all');
        const endpointsContainer = document.getElementById('endpoints-container');
        const emptyState = document.getElementById('empty-state');
        const currentTimeElement = document.getElementById('current-time');
        
        // Initialize from localStorage if available
        function loadEndpoints() {
            const savedEndpoints = localStorage.getItem('actuatorEndpoints');
            if (savedEndpoints) {
                endpoints = JSON.parse(savedEndpoints);
                renderEndpoints();
            }
        }
        
        // Save endpoints to localStorage
        function saveEndpoints() {
            localStorage.setItem('actuatorEndpoints', JSON.stringify(endpoints));
        }
        
        // Add new endpoint
        function addEndpoint() {
            const name = serviceNameInput.value.trim();
            const url = endpointUrlInput.value.trim();
            
            if (!name || !url) {
                alert('Please enter both a service name and endpoint URL');
                return;
            }
            
            // Simple URL validation
            if (!url.startsWith('http://') && !url.startsWith('https://')) {
                alert('Please enter a valid URL starting with http:// or https://');
                return;
            }
            
            const newEndpoint = {
                id: Date.now(), // unique ID
                name,
                url,
                status: 'unknown',
                responseTime: 'N/A',
                lastChecked: 'Never'
            };
            
            endpoints.push(newEndpoint);
            saveEndpoints();
            renderEndpoints();
            
            // Clear input fields
            serviceNameInput.value = '';
            endpointUrlInput.value = '';
            
            // Check the new endpoint
            checkEndpoint(newEndpoint.id);
        }
        
        // Remove endpoint
        function removeEndpoint(id) {
            endpoints = endpoints.filter(endpoint => endpoint.id !== id);
            saveEndpoints();
            renderEndpoints();
        }
        
        // Check a single endpoint
        function checkEndpoint(id) {
            const endpoint = endpoints.find(e => e.id === id);
            if (!endpoint) return;
            
            const card = document.getElementById(`endpoint-${id}`);
            const refreshBtn = card.querySelector('.btn-refresh');
            const statusIndicator = card.querySelector('.status-indicator');
            const responseTimeElement = card.querySelector('.response-time');
            const lastCheckedElement = card.querySelector('.last-checked');
            
            // Update UI to show checking state
            refreshBtn.textContent = 'Checking...';
            refreshBtn.disabled = true;
            statusIndicator.textContent = 'CHECKING';
            statusIndicator.className = 'status-indicator status-unknown';
            
            // Simulate API call (replace with actual fetch in real implementation)
            setTimeout(() => {
                // Simulate different responses
                const isSuccess = Math.random() > 0.3;
                const responseTime = isSuccess ? Math.floor(Math.random() * 300) + 50 : null;
                
                // Update endpoint data
                endpoint.status = isSuccess ? 'up' : 'down';
                endpoint.responseTime = isSuccess ? `${responseTime} ms` : 'Timeout';
                endpoint.lastChecked = 'Just now';
                
                // Update UI
                statusIndicator.textContent = endpoint.status.toUpperCase();
                statusIndicator.className = `status-indicator status-${endpoint.status}`;
                responseTimeElement.textContent = endpoint.responseTime;
                lastCheckedElement.textContent = endpoint.lastChecked;
                
                refreshBtn.textContent = 'Refresh';
                refreshBtn.disabled = false;
                
                // Update the main last updated time
                updateCurrentTime();
                
                // Save the updated status
                saveEndpoints();
            }, 1000 + Math.random() * 1000); // Random delay between 1-2 seconds
        }
        
        // Check all endpoints
        function checkAllEndpoints() {
            endpoints.forEach(endpoint => checkEndpoint(endpoint.id));
        }
        
        // Render endpoints in the UI
        function renderEndpoints() {
            if (endpoints.length === 0) {
                emptyState.style.display = 'block';
                return;
            }
            
            emptyState.style.display = 'none';
            
            endpointsContainer.innerHTML = endpoints.map(endpoint => `
                <div class="card" id="endpoint-${endpoint.id}">
                    <div class="card-header">
                        <div>
                            <div class="service-name">${endpoint.name}</div>
                            <div class="endpoint-url">${endpoint.url}</div>
                        </div>
                        <span class="status-indicator status-${endpoint.status}">${endpoint.status.toUpperCase()}</span>
                    </div>
                    <div class="card-body">
                        <div class="info-row">
                            <span class="info-label">Response Time:</span>
                            <span class="info-value response-time">${endpoint.responseTime}</span>
                        </div>
                        <div class="info-row">
                            <span class="info-label">Last Checked:</span>
                            <span class="info-value last-checked">${endpoint.lastChecked}</span>
                        </div>
                    </div>
                    <div class="card-footer">
                        <button class="btn btn-remove" onclick="removeEndpoint(${endpoint.id})">Remove</button>
                        <button class="btn btn-refresh" onclick="checkEndpoint(${endpoint.id})">Refresh</button>
                    </div>
                </div>
            `).join('');
        }
        
        // Function to update the current time display
        function updateCurrentTime() {
            const now = new Date();
            const options = { 
                year: 'numeric', 
                month: 'short', 
                day: 'numeric',
                hour: '2-digit', 
                minute: '2-digit', 
                second: '2-digit'
            };
            currentTimeElement.textContent = now.toLocaleDateString('en-US', options);
        }
        
        // Set up event listeners
        addEndpointBtn.addEventListener('click', addEndpoint);
        refreshAllBtn.addEventListener('click', checkAllEndpoints);
        
        // Allow adding endpoint with Enter key
        endpointUrlInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                addEndpoint();
            }
        });
        
        // Initialize the dashboard
        loadEndpoints();
        updateCurrentTime();
        
        // Check all endpoints on load
        if (endpoints.length > 0) {
            setTimeout(checkAllEndpoints, 1000);
        }
    </script>
</body>
</html>