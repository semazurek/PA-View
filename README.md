# PA-View: Palo Alto XML Config Viewer

PA-View is a Python-based utility designed to parse and audit massive Palo Alto Networks XML configuration files (`running-config.xml`). It generates a highly interactive, beautifully formatted, single-file HTML dashboard that allows network and security engineers to visually analyze firewall rules, network interfaces, VPN setups, object usage, and system statistics without logging into the physical device or Panorama.

**Key Features:**
*   **Offline Parsing:** Process raw XML config files locally without API keys or live connectivity.
*   **Security Auditing:** Automatically flags high-risk security rules (e.g., `any-any allow` without logging or profiles) and identifies orphaned/unused address objects.
*   **Interactive HTML Dashboard:** Tabbed interface separating System, Network, VPNs, Objects, Policies, and Security Profiles.
*   **Live Search & Export:** Real-time text filtering within tabs and 1-click export of active tables to CSV.
*   **Visual Statistics:** Integrated Chart.js for quick visualization of Allow vs. Drop/Deny policies.
*   **Secure HTML Generation:** Built-in XSS protection and layout stabilization for massive datasets.
<img width="3072" height="1664" alt="image" src="https://github.com/user-attachments/assets/eefcc0e7-6baa-4cad-a8c5-27302f9ddb33" />

## Requirements

*   Python 3.6 or higher.
*   No external Python libraries are required (uses built-in `xml.etree.ElementTree`, `argparse`, etc.).
*   *Note: The generated HTML dashboard requires an active internet connection to load the `Chart.js` library via CDN for the dashboard graphs.*

## Usage

1.  **Export Configuration:** Export the `running-config.xml` or a saved config from your Palo Alto firewall (Device > Setup > Operations > Export).
2.  **Run the Script:** Execute PA-View via the command line, providing the path to your XML file as an argument.

```bash
python PA-View.py /path/to/your/running-config.xml
```

3.  **View the Output:** The script will process the configuration and generate a new HTML file in the exact same directory as your input file, appended with `_xml_view.html`.
    *   *Example Output:* `/path/to/your/running-config_xml_view.html`
4.  **Analyze:** Open the generated HTML file in any modern web browser. Use the top navigation tabs to switch contexts, the search bar to filter rows instantly, and the Export button to save the current view as a CSV spreadsheet.
