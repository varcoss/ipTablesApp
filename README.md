# IPTablesApp

A graphical firewall manager for Linux systems using iptables, built with Python and Tkinter.

## Features

- View, add, edit, and remove iptables firewall rules in a user-friendly GUI.
- Load rules from the current system or from a JSON file.
- Save rules to a file and optionally apply them to the system.
- View active network connections (using `ss` or `netstat`).
- Instantly allow or deny traffic for any current connection with one click.
- Color-coded rules for easy distinction between ACCEPT and DROP actions.

## Requirements

- Python 3.x
- Tkinter (usually included with Python)
- iptables (installed and accessible, typically at `/usr/sbin/iptables`)
- `ss` or `netstat` for viewing active connections

## Installation

1. Clone or download this repository.
2. Ensure you have the required dependencies:
   ```sh
   sudo apt-get install python3-tk iptables iproute2 net-tools
   ```

## Usage

1. **Run as root:**

   ```sh
   sudo python3 main.py
   ```

   Root privileges are required to view and modify firewall rules.

2. **Main Features:**

   - **Load Rules:** Load current iptables rules or import from a JSON file.
   - **Save Rules:** Save your current rules to a file and optionally apply them to the system.
   - **Show Connections:** View all active TCP/UDP connections. Select any and instantly allow or deny them by adding a rule.
   - **Edit Rules:** Select a rule and use the Allow/Deny buttons to change its action.

3. **Demo:**
   - Use the provided `demo_rules.json` file to load sample rules for demonstration.

## Notes

- This app is designed for educational and demonstration purposes. Use caution when applying firewall rules on production systems.
- The app is tested on Ubuntu (including WSL). Some features may require adaptation for other Linux distributions.

## License

MIT License
