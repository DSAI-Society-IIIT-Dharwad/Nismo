import dash
from dash import dcc, html, dash_table
from dash.dependencies import Input, Output, State
import dash_cytoscape as cyto
import pandas as pd
import sqlite3
import dash.exceptions

LOG_FILE = "network_traffic.log"
DB_FILE = "sentinel.db"

cyto.load_extra_layouts()
app = dash.Dash(__name__, 
    suppress_callback_exceptions=True,
    external_stylesheets=['/assets/style.css']
)

# --- Cytoscape stylesheet ---
cyto_stylesheet = [
    {'selector': 'node','style': {'label': 'data(label)','font-size': '12px','color': '#EAEAEA','text-valign': 'bottom','text-halign': 'center','text-margin-y': '5px','background-color': '#00AFFF','border-width': 2,'border-color': '#0077B5','shape': 'ellipse','width': '30px','height': '30px',}},
    {'selector': '[type = "internal"]','style': {'background-color': '#00AFFF','border-color': '#0077B5','shape': 'ellipse','width': '50px','height': '50px','font-weight': 'bold',}},
    {'selector': '[type = "external"]','style': {'background-color': '#666666','border-color': '#444444','shape': 'rectangle','width': '25px','height': '25px','font-size': '10px','text-margin-y': '3px',}},
    {'selector': '[severity = "CRITICAL"]','style': {'background-color': '#FF0000','border-color': '#FFFFFF','border-width': 3,'box-shadow': '0 0 20px #FF0000','width': '35px','height': '35px',}},
    {'selector': '[severity = "HIGH"]','style': {'background-color': '#FF9900','border-color': '#FF6600','border-width': 3,'box-shadow': '0 0 15px #FF9900','width': '32px','height': '32px',}},
    {'selector': '[severity = "NORMAL"]','style': {'background-color': '#00AFFF','border-color': '#0077B5','border-width': 2,}},
    {'selector': 'edge','style': {'width': 1,'line-color': '#555555','target-arrow-shape': 'triangle','target-arrow-color': '#555555','curve-style': 'bezier',}},
    {'selector': '[edge_severity = "CRITICAL"]','style': {'width': 3,'line-color': '#FF0000','target-arrow-color': '#FF0000','line-style': 'solid',}},
    {'selector': '[edge_severity = "HIGH"]','style': {'width': 2,'line-color': '#FF9900','target-arrow-color': '#FF9900',}}
]

# --- Layout ---
app.layout = html.Div([
    dcc.Store(id='alert-count-memory', data=0),

    html.Div(
        id='notification-popup',
        style={
            'display': 'none',
            'position': 'fixed',
            'top': '20px',
            'right': '20px',
            'padding': '20px',
            'backgroundColor': '#FF9900',
            'color': '#0D0D0D',
            'border': '2px solid #FFFFFF',
            'borderRadius': '8px',
            'zIndex': '9999',
            'boxShadow': '0 0 15px #FF9900',
            'fontWeight': 'bold'
        },
        children=[
            html.H4('🚨 Alert! Suspicious Activity Detected!'),
            html.P("A new CRITICAL or HIGH severity event has been logged."),
            html.Button(
                'Check Logs', 
                id='notification-dismiss-btn',
                style={
                    'backgroundColor': '#0D0D0D',
                    'color': '#FFFFFF',
                    'border': 'none',
                    'padding': '10px 15px',
                    'cursor': 'pointer'
                }
            )
        ]
    ),

    html.H1("NETWORK TRAFFIC ANALYZER", className="app-title"), 
    dcc.Interval(id='interval-component', interval=5*1000, n_intervals=0),
    dcc.Tabs(id="tabs-main", value='tab-map', className="main-tabs", children=[
        dcc.Tab(label='Network Map', value='tab-map', className="tab-item"),
        dcc.Tab(label='Security Alerts', value='tab-alerts', className="tab-item"),
        dcc.Tab(label='Discovered Devices', value='tab-devices', className="tab-item"),
        dcc.Tab(label='DNS Logs', value='tab-dns', className="tab-item"),
        dcc.Tab(label='Live Traffic', value='tab-traffic', className="tab-item"),
    ]),
    html.Div(id='tabs-content')
])

# --- Tab content callback ---
@app.callback(
    Output('tabs-content', 'children'),
    Input('tabs-main', 'value')
)
def render_tab_content(tab):
    base_style_header = {
        'backgroundColor': '#00AFFF','color': '#0D0D0D','fontWeight': 'bold',
        'fontSize': '1.0em','border': 'none','padding': '12px'
    }
    base_style_cell = {
        'backgroundColor': '#1E1E1E','color': '#EAEAEA','border': 'none',
        'padding': '10px 12px','fontFamily': 'Consolas, monospace','fontSize': '13px'
    }
    if tab == 'tab-map':
        return html.Div([
            html.H3('Live Device Communication Map', className="section-title"),
            html.Div([
                html.Span('🔴 CRITICAL', style={'color': '#FF0000', 'marginRight': '20px', 'fontWeight': 'bold'}),
                html.Span('🟠 HIGH', style={'color': '#FF9900', 'marginRight': '20px', 'fontWeight': 'bold'}),
                html.Span('🔵 NORMAL', style={'color': '#00AFFF', 'fontWeight': 'bold'}),
            ], style={'marginBottom': '15px', 'fontSize': '14px'}),
            cyto.Cytoscape(id='network-map', layout={'name': 'concentric'}, style={'width': '100%', 'height': '700px'}, stylesheet=cyto_stylesheet, elements=[])
        ])
    elif tab == 'tab-alerts':
        return html.Div([
            html.H3('Security Alerts (Newest First)', className="section-title"),
            dcc.Dropdown(
                id='severity-dropdown',
                options=[
                    {'label': 'Show All Severities', 'value': 'All'},
                    {'label': '🔴 CRITICAL', 'value': 'CRITICAL'},
                    {'label': '🟠 HIGH', 'value': 'HIGH'},
                    {'label': '🔵 NORMAL', 'value': 'NORMAL'}
                ],
                value='All', clearable=False,
                style={'width': '50%', 'marginBottom': '15px', 'color': '#000000'}
            ),
            dash_table.DataTable(
                id='alerts-table',
                columns=[
                    {"name": "Timestamp", "id": "timestamp"}, {"name": "Severity", "id": "severity"},
                    {"name": "Description", "id": "description"}, {"name": "Source IP", "id": "src_ip"},
                    {"name": "Dest IP", "id": "dst_ip"}, {"name": "Dest Port", "id": "dst_port"},
                ],
                sort_action="native", page_size=20, style_header=base_style_header,
                style_cell=base_style_cell, style_data_conditional=[
                    {'if': {'filter_query': '{severity} = "CRITICAL"'},'backgroundColor': '#6B0000','color': 'white','fontWeight': 'bold','textShadow': '0 0 4px #FF0000'},
                    {'if': {'filter_query': '{severity} = "HIGH"'},'backgroundColor': '#9B4E00','color': 'white'},
                    {'if': {'filter_query': '{severity} = "NORMAL"'},'backgroundColor': '#1A3A50','color': '#00AFFF'},
                    {'if': {'column_id': 'severity'}, 'textAlign': 'center', 'fontWeight': 'bolder'},
                    {'if': {'filter_query': '{severity} = "CRITICAL"', 'column_id': 'severity'},'backgroundColor': '#FF0000','color': '#0D0D0D','border': '2px solid #EAEAEA'},
                    {'if': {'filter_query': '{severity} = "HIGH"', 'column_id': 'severity'},'backgroundColor': '#FF9900','color': '#0D0D0D',},
                    {'if': {'filter_query': '{severity} = "NORMAL"', 'column_id': 'severity'},'backgroundColor': '#00AFFF','color': '#0D0D0D',}
                ]
            )
        ])
    elif tab == 'tab-devices':
        return html.Div([
            html.H3('Discovered Network Devices', className="section-title"),
            dash_table.DataTable(
                id='device-table',
                columns=[
                    {"name": "Hostname", "id": "hostname"}, {"name": "MAC Address", "id": "mac"}, 
                    {"name": "Manufacturer", "id": "manufacturer"}, {"name": "First Seen", "id": "first_seen"}, 
                    {"name": "Last Seen", "id": "last_seen"},
                ],
                sort_action="native", page_size=15, style_header=base_style_header,
                style_cell=base_style_cell, style_cell_conditional=[
                    {'if': {'column_id': 'hostname'}, 'fontWeight': 'bold', 'color': '#00AFFF', 'textAlign': 'left'}
                ]
            )
        ])
    elif tab == 'tab-dns':
        return html.Div([
            html.H3('Live DNS Query Log', className="section-title"),
            dash_table.DataTable(
                id='dns-logs-table',
                columns=[
                    {"name": "Timestamp", "id": "timestamp"}, {"name": "Source IP", "id": "src_ip"},
                    {"name": "MAC Address", "id": "mac"}, {"name": "Queried Domain", "id": "queried_domain"},
                ],
                sort_action="native", page_size=20, style_header=base_style_header,
                style_cell=base_style_cell, style_cell_conditional=[
                    {'if': {'column_id': 'queried_domain'}, 'fontWeight': 'bold', 'color': '#EAEAEA'}
                ]
            )
        ])
    elif tab == 'tab-traffic':
        return html.Div([
            html.H3('Real-time Network Traffic Log', className="section-title"),
            dash_table.DataTable(
                id='live-traffic-table',
                columns=[
                    {"name": "Timestamp", "id": "timestamp"}, {"name": "Protocol", "id": "protocol"},
                    {"name": "Source IP", "id": "src_ip"}, {"name": "Destination IP", "id": "dst_ip"},
                    {"name": "Dest Port", "id": "dst_port"},
                ],
                sort_action="native", page_size=15, style_header=base_style_header,
                style_cell=base_style_cell
            )
        ])

# --- Database-driven callbacks (unchanged except for severity name) ---
@app.callback(Output('live-traffic-table', 'data'),
              [Input('interval-component', 'n_intervals'), Input('tabs-main', 'value')])
def update_traffic_table(n, tab):
    if tab != 'tab-traffic': return dash.no_update
    try:
        df = pd.read_csv(LOG_FILE)
        return df.tail(50).iloc[::-1].to_dict('records')
    except Exception: return []

@app.callback(Output('device-table', 'data'),
              [Input('interval-component', 'n_intervals'), Input('tabs-main', 'value')])
def update_device_table(n, tab):
    if tab != 'tab-devices': return dash.no_update
    try:
        conn = sqlite3.connect(DB_FILE)
        df = pd.read_sql_query("SELECT * FROM devices ORDER BY last_seen DESC", conn)
        conn.close()
        return df.to_dict('records')
    except Exception: return []

@app.callback(Output('alerts-table', 'data'),
              [Input('interval-component', 'n_intervals'), 
               Input('tabs-main', 'value'),
               Input('severity-dropdown', 'value')])
def update_alerts_table(n, tab, severity_value):
    if tab != 'tab-alerts': return dash.no_update
    try:
        conn = sqlite3.connect(DB_FILE)
        if severity_value and severity_value != 'All':
            query = "SELECT * FROM alerts WHERE severity = ? ORDER BY timestamp DESC"
            params = (severity_value,)
            df = pd.read_sql_query(query, conn, params=params)
        else:
            query = "SELECT * FROM alerts ORDER BY timestamp DESC"
            df = pd.read_sql_query(query, conn)
        conn.close()
        return df.to_dict('records')
    except Exception as e: 
        print(f"Error reading alerts: {e}")
        return []

@app.callback(Output('dns-logs-table', 'data'),
              [Input('interval-component', 'n_intervals'), Input('tabs-main', 'value')])
def update_dns_table(n, tab):
    if tab != 'tab-dns': return dash.no_update
    try:
        conn = sqlite3.connect(DB_FILE)
        df = pd.read_sql_query("SELECT * FROM dns_logs ORDER BY timestamp DESC LIMIT 50", conn)
        conn.close()
        return df.to_dict('records')
    except Exception as e: print(f"Error reading DNS logs: {e}"); return []

@app.callback(Output('network-map', 'elements'),
              [Input('interval-component', 'n_intervals'), Input('tabs-main', 'value')])
def update_network_map(n, tab):
    if tab != 'tab-map': return dash.no_update
    elements = []; external_ips = set()
    try:
        conn = sqlite3.connect(DB_FILE)
        devices_df = pd.read_sql_query("SELECT mac, hostname, manufacturer FROM devices", conn)
        for _, row in devices_df.iterrows():
            label = row['hostname'] if (row['hostname'] and row['hostname'] != 'Unknown') else row['manufacturer']
            elements.append({'data': {'id': row['mac'], 'label': label, 'type': 'internal'}})
        profiles_df = pd.read_sql_query(
            "SELECT mac, dst_ip, first_seen FROM device_profiles ORDER BY first_seen DESC", conn
        )
        alerts_df = pd.read_sql_query(
            """SELECT dst_ip, severity, MAX(timestamp) as last_alert 
               FROM alerts GROUP BY dst_ip ORDER BY last_alert DESC""", conn
        )
        conn.close()
        ip_severity_map = {}
        for _, alert in alerts_df.iterrows(): ip_severity_map[alert['dst_ip']] = alert['severity']
        recent_unique_profiles = profiles_df.drop_duplicates(subset=['mac', 'dst_ip']).head(30)
        for _, row in recent_unique_profiles.iterrows():
            dst_ip = row['dst_ip']
            severity = ip_severity_map.get(dst_ip, 'NORMAL')
            if dst_ip not in external_ips:
                elements.append({'data': {'id': dst_ip, 'label': dst_ip, 'type': 'external', 'severity': severity}})
                external_ips.add(dst_ip)
            elements.append({'data': {'id': f"{row['mac']}-{dst_ip}",'source': row['mac'],'target': dst_ip,'edge_severity': severity}})
        return elements
    except Exception as e:
        print(f"Error reading DB for map: {e}")
        return []

# --- Notification check callback ---
@app.callback(
    Output('notification-popup', 'style', allow_duplicate=True),
    Input('interval-component', 'n_intervals'),
    State('alert-count-memory', 'data'),
    prevent_initial_call=True
)
def check_for_new_alerts(n, last_seen_alert_count):
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM alerts WHERE severity IN ('CRITICAL', 'HIGH')")
        current_alert_count = cursor.fetchone()[0]
        conn.close()

        if current_alert_count > last_seen_alert_count:
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute("SELECT severity FROM alerts ORDER BY timestamp DESC LIMIT 1")
            last_severity = cursor.fetchone()[0]
            conn.close()
            
            color = '#FF9900'
            if last_severity == 'CRITICAL':
                color = '#FF0000'

            return {
                'display': 'block',
                'position': 'fixed', 'top': '20px', 'right': '20px',
                'padding': '20px', 'backgroundColor': color,
                'color': '#FFFFFF', 'border': '2px solid #FFFFFF',
                'borderRadius': '8px', 'zIndex': '9999',
                'boxShadow': f'0 0 15px {color}', 'fontWeight': 'bold'
            }
        else:
            return {'display': 'none'}
    except Exception as e:
        print(f"Error checking for new alerts: {e}")
        return {'display': 'none'}

# --- Notification dismiss callback ---
@app.callback(
    Output('alert-count-memory', 'data'),
    Output('notification-popup', 'style', allow_duplicate=True),
    Output('tabs-main', 'value'),
    Input('notification-dismiss-btn', 'n_clicks'),
    prevent_initial_call=True
)
def dismiss_notification(n_clicks):
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM alerts WHERE severity IN ('CRITICAL', 'HIGH')")
        current_alert_count = cursor.fetchone()[0]
        conn.close()
        return current_alert_count, {'display': 'none'}, 'tab-alerts'
    except Exception as e:
        print(f"Error dismissing notification: {e}")
        return dash.no_update, {'display': 'none'}, 'tab-alerts'


if __name__ == '__main__':
    print("🚀 Starting dashboard v1.3 - Enhanced with Notifications and NORMAL severity...")
    print("View at http://127.0.0.1:8050")
    app.run(debug=True)