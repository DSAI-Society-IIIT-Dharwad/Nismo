import dash
from dash import dcc, html, dash_table
from dash.dependencies import Input, Output
import dash_cytoscape as cyto
import pandas as pd
import sqlite3

LOG_FILE = "network_traffic.log"
DB_FILE = "sentinel.db"

# Load extra layouts for Cytoscape
cyto.load_extra_layouts()

# Link external stylesheet
app = dash.Dash(__name__, 
    suppress_callback_exceptions=True,
    external_stylesheets=['/assets/style.css']
)

# Cytoscape stylesheet
cyto_stylesheet = [
    {
        'selector': 'node',
        'style': {
            'label': 'data(label)',
            'font-size': '12px',
            'color': '#EAEAEA',
            'text-valign': 'bottom',
            'text-halign': 'center',
            'text-margin-y': '5px',
            'background-color': '#00AFFF',
            'border-width': 1,
            'border-color': '#0077B5',
            'shape': 'ellipse',
            'width': '30px',
            'height': '30px',
        }
    },
    {
        'selector': '[type = "internal"]',
        'style': {
            'background-color': '#00AFFF',
            'border-color': '#0077B5',
            'shape': 'ellipse',
            'width': '50px',
            'height': '50px',
            'font-weight': 'bold',
        }
    },
    {
        'selector': '[type = "external"]',
        'style': {
            'background-color': '#666666',
            'border-color': '#444444',
            'shape': 'rectangle',
            'width': '25px',
            'height': '25px',
            'font-size': '10px',
            'text-margin-y': '3px',
        }
    },
    {
        'selector': 'edge',
        'style': {
            'width': 1,
            'line-color': '#555555',
            'target-arrow-shape': 'triangle',
            'target-arrow-color': '#555555',
            'curve-style': 'bezier',
        }
    }
]

app.layout = html.Div([
    html.H1("Network Monitor", className="app-title"), 
    
    dcc.Interval(
        id='interval-component',
        interval=5*1000,
        n_intervals=0
    ),
    
    dcc.Tabs(id="tabs-main", value='tab-map', className="main-tabs", children=[
        dcc.Tab(label='Network Map', value='tab-map', className="tab-item"),
        dcc.Tab(label='Security Alerts', value='tab-alerts', className="tab-item"),
        dcc.Tab(label='Discovered Devices', value='tab-devices', className="tab-item"),
        dcc.Tab(label='Live Traffic', value='tab-traffic', className="tab-item"),
    ]),
    
    html.Div(id='tabs-content')
])

# Callback for Tabs
@app.callback(
    Output('tabs-content', 'children'),
    Input('tabs-main', 'value')
)
def render_tab_content(tab):
    # Base styles for all tables
    base_style_header = {
        'backgroundColor': '#00AFFF',
        'color': '#0D0D0D',
        'fontWeight': 'bold',
        'fontSize': '1.0em',
        'border': 'none',
        'padding': '12px'
    }
    
    base_style_cell = {
        'backgroundColor': '#1E1E1E',
        'color': '#EAEAEA',
        'border': 'none',
        'padding': '10px 12px',
        'fontFamily': 'Consolas, monospace',
        'fontSize': '13px'
    }

    if tab == 'tab-map':
        return html.Div([
            html.H3('Live Device Communication Map (Most Recent 30 Connections)', className="section-title"),
            cyto.Cytoscape(
                id='network-map', 
                layout={'name': 'concentric'}, 
                style={'width': '100%', 'height': '700px'},
                stylesheet=cyto_stylesheet, 
                elements=[]
            )
        ])
    
    elif tab == 'tab-alerts':
        return html.Div([
            html.H3('Security Alerts (Newest First)', className="section-title"),
            dash_table.DataTable(
                id='alerts-table',
                columns=[
                    {"name": "Timestamp", "id": "timestamp"},
                    {"name": "Severity", "id": "severity"},
                    {"name": "Description", "id": "description"},
                    {"name": "Source IP", "id": "src_ip"},
                    {"name": "Dest IP", "id": "dst_ip"},
                    {"name": "Dest Port", "id": "dst_port"},
                ],
                sort_action="native",
                page_size=20,
                style_header=base_style_header,
                style_cell=base_style_cell,
                style_data_conditional=[
                    {
                        'if': {'filter_query': '{severity} = "CRITICAL"'},
                        'backgroundColor': '#6B0000',
                        'color': 'white',
                        'fontWeight': 'bold',
                        'textShadow': '0 0 4px #FF0000'
                    },
                    {
                        'if': {'filter_query': '{severity} = "HIGH"'},
                        'backgroundColor': '#9B4E00',
                        'color': 'white'
                    },
                    {
                        'if': {'filter_query': '{severity} = "Info"'},
                        'backgroundColor': '#1A3A50',
                        'color': '#00AFFF'
                    },
                    {
                        'if': {'column_id': 'severity'}, 
                        'textAlign': 'center', 
                        'fontWeight': 'bolder'
                    },
                    {
                        'if': {'filter_query': '{severity} = "CRITICAL"', 'column_id': 'severity'},
                        'backgroundColor': '#FF0000',
                        'color': '#0D0D0D',
                        'border': '2px solid #EAEAEA'
                    },
                    {
                        'if': {'filter_query': '{severity} = "HIGH"', 'column_id': 'severity'},
                        'backgroundColor': '#FF9900',
                        'color': '#0D0D0D',
                    },
                    {
                        'if': {'filter_query': '{severity} = "Info"', 'column_id': 'severity'},
                        'backgroundColor': '#00AFFF',
                        'color': '#0D0D0D',
                    }
                ]
            )
        ])
    
    elif tab == 'tab-devices':
        return html.Div([
            html.H3('Discovered Network Devices', className="section-title"),
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
                style_header=base_style_header,
                style_cell=base_style_cell
            )
        ])
        
    elif tab == 'tab-traffic':
        return html.Div([
            html.H3('Real-time Network Traffic Log', className="section-title"),
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
                style_header=base_style_header,
                style_cell=base_style_cell
            )
        ])

@app.callback(
    Output('live-traffic-table', 'data'),
    Input('interval-component', 'n_intervals'), 
    Input('tabs-main', 'value')
)
def update_traffic_table(n, tab):
    if tab != 'tab-traffic': 
        return dash.no_update
    try:
        df = pd.read_csv(LOG_FILE)
        return df.tail(50).iloc[::-1].to_dict('records')
    except Exception: 
        return []

@app.callback(
    Output('device-table', 'data'),
    Input('interval-component', 'n_intervals'), 
    Input('tabs-main', 'value')
)
def update_device_table(n, tab):
    if tab != 'tab-devices': 
        return dash.no_update
    try:
        conn = sqlite3.connect(DB_FILE)
        df = pd.read_sql_query("SELECT * FROM devices ORDER BY last_seen DESC", conn)
        conn.close()
        return df.to_dict('records')
    except Exception: 
        return []

@app.callback(
    Output('alerts-table', 'data'),
    Input('interval-component', 'n_intervals'), 
    Input('tabs-main', 'value')
)
def update_alerts_table(n, tab):
    if tab != 'tab-alerts': 
        return dash.no_update
    try:
        conn = sqlite3.connect(DB_FILE)
        df = pd.read_sql_query("SELECT * FROM alerts ORDER BY timestamp DESC", conn)
        conn.close()
        return df.to_dict('records')
    except Exception as e: 
        return []

@app.callback(
    Output('network-map', 'elements'),
    Input('interval-component', 'n_intervals'),
    Input('tabs-main', 'value')
)
def update_network_map(n, tab):
    if tab != 'tab-map':
        return dash.no_update
        
    elements = []
    external_ips = set()
    
    try:
        conn = sqlite3.connect(DB_FILE)
        
        devices_df = pd.read_sql_query("SELECT mac, manufacturer FROM devices", conn)
        for _, row in devices_df.iterrows():
            elements.append({
                'data': {
                    'id': row['mac'], 
                    'label': row['manufacturer'],
                    'type': 'internal'
                }
            })
        
        profiles_df = pd.read_sql_query(
            "SELECT mac, dst_ip, first_seen FROM device_profiles ORDER BY first_seen DESC", 
            conn
        )
        conn.close()
        
        recent_unique_profiles = profiles_df.drop_duplicates(subset=['mac', 'dst_ip']).head(30)

        for _, row in recent_unique_profiles.iterrows():
            if row['dst_ip'] not in external_ips:
                elements.append({
                    'data': {
                        'id': row['dst_ip'],
                        'label': row['dst_ip'],
                        'type': 'external'
                    }
                })
                external_ips.add(row['dst_ip'])
            
            elements.append({
                'data': {
                    'id': f"{row['mac']}-{row['dst_ip']}",
                    'source': row['mac'],
                    'target': row['dst_ip']
                }
            })
            
        return elements
        
    except Exception as e:
        print(f"Error reading DB for map: {e}")
        return []

if __name__ == '__main__':
    print("🚀 Starting dashboard v0.5...")
    print("View at http://127.0.0.1:8050")
    app.run(debug=True)