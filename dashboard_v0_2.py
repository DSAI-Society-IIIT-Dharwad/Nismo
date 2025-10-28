import dash
from dash import dcc, html, dash_table
from dash.dependencies import Input, Output
import pandas as pd
import sqlite3

LOG_FILE = "network_traffic.log"
DB_FILE = "sentinel.db"

app = dash.Dash(__name__, suppress_callback_exceptions=True)

app.layout = html.Div([
    html.H1("Home Network Monitor - v0.2"),
    
    dcc.Interval(
        id='interval-component',
        interval=5*1000,  # 5 seconds
        n_intervals=0
    ),
    
    dcc.Tabs(id="tabs-main", value='tab-traffic', children=[
        dcc.Tab(label='Live Traffic', value='tab-traffic'),
        dcc.Tab(label='Discovered Devices', value='tab-devices'),
    ]),
    
    # This Div's content will be updated by the tab callback
    html.Div(id='tabs-content')
])

# --- Callback for Tabs ---
@app.callback(
    Output('tabs-content', 'children'),
    Input('tabs-main', 'value')
)
def render_tab_content(tab):
    if tab == 'tab-traffic':
        return html.Div([
            html.H3('Real-time Network Traffic Log'),
            dash_table.DataTable(
                id='live-traffic-table',
                columns=[
                    {"name": "Timestamp", "id": "timestamp"},
                    {"name": "Protocol", "id": "protocol"},
                    {"name": "Source IP", "id": "src_ip"},
                    {"name": "Destination IP", "id": "dst_ip"},
                    {"name": "Dest Port", "id": "dst_port"},
                ],
                sort_action="native",
                page_size=15,
            )
        ])
    elif tab == 'tab-devices':
        return html.Div([
            html.H3('Discovered Network Devices'),
            dash_table.DataTable(
                id='device-table',
                columns=[
                    {"name": "MAC Address", "id": "mac"},
                    {"name": "Manufacturer", "id": "manufacturer"},
                    {"name": "First Seen", "id": "first_seen"},
                    {"name": "Last Seen", "id": "last_seen"},
                ],
                sort_action="native",
                page_size=15,
            )
        ])

# --- Callback for Live Traffic Table (tab-traffic) ---
@app.callback(
    Output('live-traffic-table', 'data'),
    Input('interval-component', 'n_intervals'),
    Input('tabs-main', 'value')
)
def update_traffic_table(n, tab):
    if tab != 'tab-traffic':
        return dash.no_update # Don't update if tab isn't active
    
    try:
        df = pd.read_csv(LOG_FILE)
        df_display = df.tail(50).iloc[::-1] # Newest on top
        return df_display.to_dict('records')
    except (FileNotFoundError, pd.errors.EmptyDataError):
        return []
    except Exception as e:
        print(f"Error reading log: {e}")
        return []

# --- NEW Callback for Device Table (tab-devices) ---
@app.callback(
    Output('device-table', 'data'),
    Input('interval-component', 'n_intervals'),
    Input('tabs-main', 'value')
)
def update_device_table(n, tab):
    if tab != 'tab-devices':
        return dash.no_update # Don't update if tab isn't active
        
    try:
        conn = sqlite3.connect(DB_FILE)
        # Read all devices from the database
        df = pd.read_sql_query("SELECT * FROM devices ORDER BY last_seen DESC", conn)
        conn.close()
        return df.to_dict('records')
    except Exception as e:
        print(f"Error reading device DB: {e}")
        return []

# --- Main part of the script ---
if __name__ == '__main__':
    print("🚀 Starting dashboard v0.2...")
    print("View at http://127.0.0.1:8050")
    app.run(debug=True)