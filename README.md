# UDM WAN Monitor - Deployment Instructions

This guide explains how to compile, deploy, and configure the WAN interface monitor on your UniFi Dream Machine (SE/PRO/MAX).

## Prerequisites

- Go installed on your development machine (Mac, Linux, or Windows)
- SSH access to your UDM-SE/PRO/MAX
- UniFi account with administrative privileges
- You'll want to create a new UDM console user for the service to authenticate via. Ideally with least privileges

## Step 1: Compile the Application

### On macOS ARM (M1/M2/M3)

```bash
# Create a directory for your project
mkdir -p ~/udm-wan-monitor
cd ~/udm-wan-monitor

# Copy both main.go and config.json files into this directory
# [Copy the files from the artifacts]

# Set the environment variables for cross-compilation
export GOOS=linux
export GOARCH=arm64
export CGO_ENABLED=0

# Compile the script
go build -o udm-wan-monitor main.go

# The compiled binary will be created in the current directory
```

### On Windows or Intel Mac

The process is similar, just make sure to set the correct environment variables:

```bash
export GOOS=linux
export GOARCH=arm64
export CGO_ENABLED=0
```

## Step 2: Transfer Files to UDM

```bash
# Create a directory on the UDM
ssh root@[your-udm-ip] "mkdir -p /root/udm-wan-monitor"

# Transfer the compiled binary and config file
scp udm-wan-monitor config.json root@[your-udm-ip]:/root/udm-wan-monitor/
```

## Step 3: Configure the Application

SSH into your UDM and edit the configuration file:

```bash
ssh root@[your-udm-ip]
cd /root/udm-wan-monitor

# Edit the config file with your preferred editor
vi config.json
```

Update the following values in the config file:

- `username`: Your UniFi admin username
- `password`: Your UniFi admin password
- Adjust any other settings as needed

Note: Given this needs "admin" credentials, I'd suggest you create a "View" user. 
Network-> Setting-> Admins & Users -> Create New Admin
On the box on the right, select the checkbox for "Restrict to Local Access Only".
Uncheck "Use a Predefined Role"
Next to the Target icon, select View Only (the default is Full Management, which is bad)
Next to the User icon, select "None" (anything else is bad)

## Step 4: Test the Application

Run the monitor manually first to ensure it works correctly:

```bash
# Make the binary executable
chmod +x /root/udm-wan-monitor/udm-wan-monitor

# Run the monitor with the config file
/root/udm-wan-monitor/udm-wan-monitor -config /root/udm-wan-monitor/config.json
```

Verify that the application starts without errors and can correctly detect your WAN interfaces.

## Step 5: Setup as a Service

Create a systemd service file to run the monitor as a background service:

```bash
cat > /etc/systemd/system/udm-wan-monitor.service << 'EOF'
[Unit]
Description=UDM WAN Interface Monitor
After=network.target

[Service]
ExecStart=/root/udm-wan-monitor/udm-wan-monitor -config /root/udm-wan-monitor/config.json
WorkingDirectory=/root/udm-wan-monitor
Restart=always
RestartSec=10
KillMode=process

[Install]
WantedBy=multi-user.target
EOF

# Enable and start the service
systemctl enable udm-wan-monitor.service
systemctl start udm-wan-monitor.service

# Check the status
systemctl status udm-wan-monitor.service
```

## Step 6: Verify Notifications

To verify the notifications are working:

1. Disconnect one of your WAN connections briefly
2. Check the UniFi notifications in the web UI or mobile app
3. You should see alerts for the WAN interface status change
4. Check the log file at the configured path (default is `/var/log/udm-wan-monitor.log`)

## Troubleshooting

If you encounter issues:

1. Check the logs: `tail -f /var/log/udm-wan-monitor.log`
2. Verify the service is running: `systemctl status udm-wan-monitor.service`
3. Try running the application manually with `-config` flag
4. Check if your UniFi credentials are correct
5. Ensure your UDM-SE firmware is up to date

## Making Updates

If you need to update the configuration:

1. Edit the `config.json` file on the UDM
2. Restart the service: `systemctl restart udm-wan-monitor.service`

If you need to update the application itself:

1. Compile a new version on your development machine
2. Transfer the new binary to the UDM
3. Make it executable: `chmod +x /root/udm-wan-monitor/wan-monitor`
4. Restart the service: `systemctl restart udm-wan-monitor.service`
