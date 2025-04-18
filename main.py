import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import subprocess
import re
import os
import json
import sys

class IPTablesApp:
    def __init__(self, root):
        # Check for root privileges at startup
        if os.geteuid() != 0:
            messagebox.showerror("Root Required", "This application must be run as root. Please restart it with: sudo python3 main.py")
            sys.exit(1)

        self.root = root
        self.root.title("IPTables Firewall Manager")
        self.root.geometry("900x600")
        
        self.rules = []
        self.modified = False
        
        # Create main frame
        self.main_frame = ttk.Frame(root, padding="10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create top control panel
        self.control_frame = ttk.Frame(self.main_frame)
        self.control_frame.pack(fill=tk.X, pady=5)
        
        # Load button
        self.load_btn = ttk.Button(self.control_frame, text="Load Rules", command=self.load_rules)
        self.load_btn.pack(side=tk.LEFT, padx=5)
        
        # Save button
        self.save_btn = ttk.Button(self.control_frame, text="Save Rules", command=self.save_rules, state=tk.DISABLED)
        self.save_btn.pack(side=tk.LEFT, padx=5)
        
        # Show Connections button
        self.conn_btn = ttk.Button(self.control_frame, text="Show Connections", command=self.show_connections)
        self.conn_btn.pack(side=tk.LEFT, padx=5)
        
        # Exit button
        self.exit_btn = ttk.Button(self.control_frame, text="Exit", command=self.exit_app)
        self.exit_btn.pack(side=tk.RIGHT, padx=5)
        
        # Create rules table
        self.create_rules_table()
        
        # Create bottom panel for rule editing
        self.edit_frame = ttk.LabelFrame(self.main_frame, text="Rule Editor", padding="10")
        self.edit_frame.pack(fill=tk.X, pady=10)
        
        # Action buttons
        self.allow_btn = ttk.Button(self.edit_frame, text="Allow Traffic", command=lambda: self.change_rule_action("ACCEPT"))
        self.allow_btn.grid(row=0, column=0, padx=5, pady=5)
        
        self.deny_btn = ttk.Button(self.edit_frame, text="Deny Traffic", command=lambda: self.change_rule_action("DROP"))
        self.deny_btn.grid(row=0, column=1, padx=5, pady=5)
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        self.status_bar = ttk.Label(self.main_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(fill=tk.X, side=tk.BOTTOM, pady=5)

    def create_rules_table(self):
        # Create frame for the table
        self.table_frame = ttk.Frame(self.main_frame)
        self.table_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Scrollbar
        self.scrollbar = ttk.Scrollbar(self.table_frame)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Rules treeview
        columns = ("chain", "action", "protocol", "source", "destination", "port", "comment")
        self.tree = ttk.Treeview(self.table_frame, columns=columns, show="headings", yscrollcommand=self.scrollbar.set)
        
        # Define column headings
        self.tree.heading("chain", text="Chain")
        self.tree.heading("action", text="Action")
        self.tree.heading("protocol", text="Protocol")
        self.tree.heading("source", text="Source")
        self.tree.heading("destination", text="Destination")
        self.tree.heading("port", text="Port")
        self.tree.heading("comment", text="Comment")
        
        # Set column widths
        self.tree.column("chain", width=80)
        self.tree.column("action", width=80)
        self.tree.column("protocol", width=80)
        self.tree.column("source", width=120)
        self.tree.column("destination", width=120)
        self.tree.column("port", width=80)
        self.tree.column("comment", width=200)
        
        # Pack the treeview
        self.tree.pack(fill=tk.BOTH, expand=True)
        self.scrollbar.config(command=self.tree.yview)
        
        # Bind selection event
        self.tree.bind("<<TreeviewSelect>>", self.on_rule_select)
        
        # Add tags for coloring rows
        self.tree.tag_configure("accept", background="#d4edda")  # Green for ACCEPT
        self.tree.tag_configure("drop", background="#f8d7da")    # Red for DROP

    def load_rules(self):
        """Load iptables rules either from system or from a saved file"""
        option = messagebox.askyesno("Load Rules", "Do you want to load rules from the system?\nSelecting 'No' will allow you to load from a file.")
        
        if option:  # Load from system
            self.status_var.set("Loading rules from system...")
            iptables_path = "/usr/sbin/iptables"
            try:
                result = subprocess.run([iptables_path, "-L", "-n", "--line-numbers"], capture_output=True, text=True, check=True)
                self.parse_iptables_output(result.stdout)
                self.display_rules()
                self.status_var.set(f"Loaded {len(self.rules)} rules from system")
                self.save_btn.config(state=tk.NORMAL)
            except subprocess.CalledProcessError as e:
                error_msg = e.stderr if e.stderr else str(e)
                messagebox.showerror("Error", f"Failed to load iptables rules: {error_msg}\n\nPlease make sure you have appropriate permissions to run iptables commands.")
                self.status_var.set("Failed to load rules")
        else:  # Load from file
            filepath = filedialog.askopenfilename(
                title="Load Rules File",
                filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")]
            )
            if filepath:
                try:
                    with open(filepath, 'r') as f:
                        self.rules = json.load(f)
                    self.display_rules()
                    self.status_var.set(f"Loaded {len(self.rules)} rules from file")
                    self.save_btn.config(state=tk.NORMAL)
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to load rules from file: {e}")
                    self.status_var.set("Failed to load rules")

    def parse_iptables_output(self, output):
        """Parse the iptables output into structured rule data"""
        self.rules = []
        current_chain = ""
        
        lines = output.strip().split('\n')
        for line in lines:
            # Detect chain headers
            chain_match = re.match(r'^Chain (\w+)', line)
            if chain_match:
                current_chain = chain_match.group(1)
                continue
            
            # Skip header lines
            if re.match(r'^num|^$|target', line, re.IGNORECASE):
                continue
            
            # Parse rule lines
            parts = re.split(r'\s+', line.strip())
            if len(parts) >= 3:  # Simple validation
                rule_num = parts[0]
                target = parts[1]  # ACCEPT, DROP, etc.
                proto = parts[2]
                
                # Extract source and destination (simplified)
                source = parts[3] if len(parts) > 3 else "any"
                destination = parts[4] if len(parts) > 4 else "any"
                
                # Extract port and comment info (simplified)
                port = "any"
                comment = ""
                
                for i in range(5, len(parts)):
                    if "dpt:" in parts[i]:
                        port = parts[i].replace("dpt:", "")
                    elif "/* " in line:
                        # Extract comment if present
                        comment_match = re.search(r'/\*\s*(.+?)\s*\*/', line)
                        if comment_match:
                            comment = comment_match.group(1)
                
                self.rules.append({
                    "num": rule_num,
                    "chain": current_chain,
                    "action": target,
                    "protocol": proto,
                    "source": source,
                    "destination": destination,
                    "port": port,
                    "comment": comment
                })

    def display_rules(self):
        """Display the loaded rules in the treeview"""
        # Clear existing items
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # Add rules to treeview
        for rule in self.rules:
            tag = "accept" if rule["action"].upper() == "ACCEPT" else "drop"
            
            self.tree.insert(
                "", "end",
                values=(
                    rule["chain"],
                    rule["action"],
                    rule["protocol"],
                    rule["source"],
                    rule["destination"],
                    rule["port"],
                    rule["comment"]
                ),
                tags=(tag,)
            )

    def on_rule_select(self, event):
        """Handle rule selection in the treeview"""
        selected_items = self.tree.selection()
        if selected_items:
            # Enable action buttons
            self.allow_btn.config(state=tk.NORMAL)
            self.deny_btn.config(state=tk.NORMAL)
        else:
            # Disable action buttons if nothing selected
            self.allow_btn.config(state=tk.DISABLED)
            self.deny_btn.config(state=tk.DISABLED)

    def change_rule_action(self, new_action):
        """Change the action of the selected rule"""
        selected_items = self.tree.selection()
        if not selected_items:
            return
        
        for item_id in selected_items:
            # Get the item's values
            values = self.tree.item(item_id, "values")
            
            # Create new values with changed action
            new_values = list(values)
            new_values[1] = new_action
            
            # Update treeview
            tag = "accept" if new_action == "ACCEPT" else "drop"
            self.tree.item(item_id, values=new_values, tags=(tag,))
            
            # Update rules data structure
            item_idx = self.tree.index(item_id)
            if 0 <= item_idx < len(self.rules):
                self.rules[item_idx]["action"] = new_action
        
        self.modified = True
        self.status_var.set("Rules modified (not saved)")

    def save_rules(self):
        """Save the current rules to a file and optionally apply to system"""
        if not self.modified and not self.rules:
            messagebox.showinfo("Info", "No changes to save")
            return
        
        # Ask if user wants to apply to system
        apply_to_system = messagebox.askyesno("Save Rules", 
                                             "Do you want to apply these rules to the system?\n"
                                             "Warning: This will replace your current firewall rules.")
        
        # First save to a file
        filepath = filedialog.asksaveasfilename(
            title="Save Rules",
            defaultextension=".json",
            filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")]
        )
        
        if filepath:
            try:
                with open(filepath, 'w') as f:
                    json.dump(self.rules, f, indent=4)
                
                self.status_var.set(f"Rules saved to {filepath}")
                self.modified = False
                
                # If user wants to apply rules to system
                if apply_to_system:
                    self.apply_rules_to_system()
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save rules: {e}")
                self.status_var.set("Failed to save rules")

    def apply_rules_to_system(self):
        """Apply the current rules to the system"""
        iptables_path = "/usr/sbin/iptables"
        try:
            # Flush existing rules
            subprocess.run([iptables_path, "-F"], check=True)
            # Apply each rule
            for rule in self.rules:
                cmd = [iptables_path, "-A", rule['chain']]
                if rule['protocol'] != "all":
                    cmd += ["-p", rule['protocol']]
                if rule['source'] != "any" and rule['source'] != "0.0.0.0/0":
                    cmd += ["-s", rule['source']]
                if rule['destination'] != "any" and rule['destination'] != "0.0.0.0/0":
                    cmd += ["-d", rule['destination']]
                if rule['port'] != "any":
                    cmd += ["--dport", rule['port']]
                if rule['comment']:
                    cmd += ["-m", "comment", "--comment", rule['comment']]
                cmd += ["-j", rule['action']]
                subprocess.run(cmd, check=True)
            messagebox.showinfo("Success", "Firewall rules applied successfully to system")
            self.status_var.set("Rules saved and applied to system")
        except subprocess.CalledProcessError as e:
            error_msg = e.stderr if hasattr(e, 'stderr') and e.stderr else str(e)
            messagebox.showerror("Error", f"Failed to apply rules to system: {error_msg}")
            self.status_var.set("Failed to apply rules to system")

    def show_connections(self):
        """Show active system network connections in a popup window with allow/deny actions"""
        # Try ss first, fallback to netstat
        try:
            result = subprocess.run(["ss", "-tunap"], capture_output=True, text=True, check=True)
            output = result.stdout
        except Exception:
            try:
                result = subprocess.run(["netstat", "-tunap"], capture_output=True, text=True, check=True)
                output = result.stdout
            except Exception as e:
                messagebox.showerror("Error", f"Failed to get system connections: {e}")
                return
        # Parse connections for table display
        connections = self.parse_connections_output(output)
        # Popup window
        conn_win = tk.Toplevel(self.root)
        conn_win.title("Active System Connections")
        conn_win.geometry("1100x500")
        # Treeview for connections
        columns = ("proto", "local_addr", "local_port", "remote_addr", "remote_port", "state", "pid", "program")
        tree = ttk.Treeview(conn_win, columns=columns, show="headings")
        for col in columns:
            tree.heading(col, text=col.replace('_', ' ').title())
            tree.column(col, width=120)
        tree.pack(fill=tk.BOTH, expand=True)
        # Insert connections
        for conn in connections:
            tree.insert("", "end", values=(conn["proto"], conn["local_addr"], conn["local_port"], conn["remote_addr"], conn["remote_port"], conn["state"], conn["pid"], conn["program"]))
        # Action buttons
        btn_frame = ttk.Frame(conn_win)
        btn_frame.pack(fill=tk.X, pady=5)
        allow_btn = ttk.Button(btn_frame, text="Allow Selected", command=lambda: self.add_rule_from_connection(tree, "ACCEPT"))
        allow_btn.pack(side=tk.LEFT, padx=5)
        deny_btn = ttk.Button(btn_frame, text="Deny Selected", command=lambda: self.add_rule_from_connection(tree, "DROP"))
        deny_btn.pack(side=tk.LEFT, padx=5)

    def parse_connections_output(self, output):
        """Parse ss/netstat output into a list of connection dicts"""
        connections = []
        lines = output.strip().split('\n')
        # Find header
        header_idx = 0
        for i, line in enumerate(lines):
            if line.lower().startswith("proto"):
                header_idx = i
                break
        headers = re.split(r'\s+', lines[header_idx].strip())
        for line in lines[header_idx+1:]:
            if not line.strip():
                continue
            parts = re.split(r'\s+', line.strip(), maxsplit=len(headers)-1)
            if len(parts) < 5:
                continue
            proto = parts[0]
            state = parts[1] if proto in ("tcp", "udp") else ""
            local = parts[3] if proto == "tcp" else parts[4]
            remote = parts[4] if proto == "tcp" else parts[5] if len(parts) > 5 else ""
            pid, program = "", ""
            if len(parts) > 5:
                # Try to extract pid/program from last column
                m = re.search(r'pid=(\d+),?\s*fd=\d*\s*\(([^)]+)\)', parts[-1])
                if m:
                    pid, program = m.group(1), m.group(2)
                else:
                    # Try netstat format
                    m2 = re.search(r'^(\d+)/(\S+)', parts[-1])
                    if m2:
                        pid, program = m2.group(1), m2.group(2)
            # Split address/port
            def split_addr_port(s):
                if ':' in s:
                    addr, port = s.rsplit(':', 1)
                    return addr, port
                return s, ""
            local_addr, local_port = split_addr_port(local)
            remote_addr, remote_port = split_addr_port(remote)
            connections.append({
                "proto": proto,
                "local_addr": local_addr,
                "local_port": local_port,
                "remote_addr": remote_addr,
                "remote_port": remote_port,
                "state": state,
                "pid": pid,
                "program": program
            })
        return connections

    def add_rule_from_connection(self, tree, action):
        """Add an iptables rule for the selected connection"""
        selected = tree.selection()
        if not selected:
            messagebox.showinfo("Info", "No connection selected.")
            return
        for item in selected:
            values = tree.item(item, "values")
            proto, local_addr, local_port, remote_addr, remote_port, state, pid, program = values
            # For incoming connections, remote_addr is the source
            rule = {
                "num": str(len(self.rules)+1),
                "chain": "INPUT" if proto.lower() == "tcp" else "FORWARD",
                "action": action,
                "protocol": proto.lower(),
                "source": remote_addr if remote_addr else "0.0.0.0/0",
                "destination": local_addr if local_addr else "0.0.0.0/0",
                "port": local_port if local_port else "any",
                "comment": f"{action} {proto} from {remote_addr}:{remote_port} to {local_addr}:{local_port} ({program})"
            }
            self.rules.append(rule)
        self.display_rules()
        self.status_var.set(f"Added {action} rule(s) for selected connection(s)")
        self.save_btn.config(state=tk.NORMAL)

    def exit_app(self):
        """Exit the application with confirmation if unsaved changes"""
        if self.modified:
            save_before_exit = messagebox.askyesnocancel(
                "Unsaved Changes",
                "You have unsaved changes. Do you want to save before exiting?",
                default=messagebox.YES
            )
            
            if save_before_exit is None:  # User cancelled
                return
                
            if save_before_exit:  # User wants to save
                self.save_rules()
        
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = IPTablesApp(root)
    root.mainloop()