//! HTML Templates for CoreVPN Web UI
//!
//! Uses Tailwind CSS via CDN for styling with a distinctive cyberpunk aesthetic.

/// Base HTML template with Tailwind CSS CDN and shared styles
pub fn base(title: &str, content: &str) -> String {
    format!(
        r##"<!DOCTYPE html>
<html lang="en" class="h-full">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title} | CoreVPN</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Outfit:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <script>
        tailwind.config = {{
            theme: {{
                extend: {{
                    colors: {{
                        'cyber': {{
                            50: '#f0fdf9',
                            100: '#ccfbef',
                            200: '#99f6df',
                            300: '#5eeacb',
                            400: '#2dd4b3',
                            500: '#14b89a',
                            600: '#0d947d',
                            700: '#0f7666',
                            800: '#115e53',
                            900: '#134e45',
                            950: '#042f2a',
                        }},
                        'void': {{
                            50: '#f6f6f7',
                            100: '#e2e3e5',
                            200: '#c4c5ca',
                            300: '#a0a1a8',
                            400: '#7c7d85',
                            500: '#616269',
                            600: '#4d4e54',
                            700: '#3f4044',
                            800: '#27282b',
                            900: '#1a1b1e',
                            950: '#0d0e10',
                        }},
                        'neon': {{
                            pink: '#ff2d92',
                            blue: '#00d4ff',
                            green: '#00ff88',
                            yellow: '#ffd60a',
                            purple: '#a855f7',
                        }},
                    }},
                    fontFamily: {{
                        'display': ['Outfit', 'system-ui', 'sans-serif'],
                        'mono': ['JetBrains Mono', 'monospace'],
                    }},
                    animation: {{
                        'pulse-slow': 'pulse 3s ease-in-out infinite',
                        'glow': 'glow 2s ease-in-out infinite alternate',
                    }},
                }},
            }},
        }}
    </script>
    <style>
        body {{
            font-family: 'Outfit', system-ui, sans-serif;
            background: linear-gradient(135deg, #0d0e10 0%, #1a1b1e 50%, #0d0e10 100%);
        }}
        .glass {{
            background: rgba(26, 27, 30, 0.7);
            backdrop-filter: blur(20px);
            border: 1px solid rgba(255, 255, 255, 0.05);
        }}
        .glow-green {{
            box-shadow: 0 0 20px rgba(0, 255, 136, 0.3), 0 0 40px rgba(0, 255, 136, 0.1);
        }}
        .glow-blue {{
            box-shadow: 0 0 20px rgba(0, 212, 255, 0.3), 0 0 40px rgba(0, 212, 255, 0.1);
        }}
        .glow-pink {{
            box-shadow: 0 0 20px rgba(255, 45, 146, 0.3), 0 0 40px rgba(255, 45, 146, 0.1);
        }}
        .text-glow {{
            text-shadow: 0 0 10px currentColor, 0 0 20px currentColor;
        }}
        .grid-bg {{
            background-image:
                linear-gradient(rgba(0, 255, 136, 0.03) 1px, transparent 1px),
                linear-gradient(90deg, rgba(0, 255, 136, 0.03) 1px, transparent 1px);
            background-size: 50px 50px;
        }}
        .stat-card {{
            transition: all 0.3s ease;
        }}
        .stat-card:hover {{
            transform: translateY(-4px);
        }}
        @keyframes scanline {{
            0% {{ transform: translateY(-100%); }}
            100% {{ transform: translateY(100vh); }}
        }}
        .scanline::before {{
            content: '';
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(transparent, rgba(0, 255, 136, 0.1), transparent);
            animation: scanline 8s linear infinite;
            pointer-events: none;
            z-index: 1000;
        }}
    </style>
</head>
<body class="h-full text-void-100 antialiased scanline grid-bg">
    <div class="min-h-full">
        {content}
    </div>
</body>
</html>"##,
        title = title,
        content = content
    )
}

/// Navigation component
pub fn nav(active: &str) -> String {
    let nav_items = [
        (
            "dashboard",
            "Dashboard",
            "/admin",
            r#"<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 5a1 1 0 011-1h14a1 1 0 011 1v2a1 1 0 01-1 1H5a1 1 0 01-1-1V5zM4 13a1 1 0 011-1h6a1 1 0 011 1v6a1 1 0 01-1 1H5a1 1 0 01-1-1v-6zM16 13a1 1 0 011-1h2a1 1 0 011 1v6a1 1 0 01-1 1h-2a1 1 0 01-1-1v-6z"/>"#,
        ),
        (
            "clients",
            "Clients",
            "/admin/clients",
            r#"<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z"/>"#,
        ),
        (
            "sessions",
            "Sessions",
            "/admin/sessions",
            r#"<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8.111 16.404a5.5 5.5 0 017.778 0M12 20h.01m-7.08-7.071c3.904-3.905 10.236-3.905 14.141 0M1.394 9.393c5.857-5.857 15.355-5.857 21.213 0"/>"#,
        ),
        (
            "settings",
            "Settings",
            "/admin/settings",
            r#"<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/>"#,
        ),
    ];

    let mut items_html = String::new();
    for (id, label, href, icon) in nav_items {
        let is_active = active == id;
        let active_class = if is_active {
            "bg-neon-green/10 text-neon-green border-l-2 border-neon-green"
        } else {
            "text-void-400 hover:text-void-100 hover:bg-void-800/50 border-l-2 border-transparent"
        };

        items_html.push_str(&format!(
            r#"<a href="{href}" class="flex items-center gap-3 px-4 py-3 {active_class} transition-all">
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">{icon}</svg>
                <span class="font-medium">{label}</span>
            </a>"#,
            href=href, active_class=active_class, icon=icon, label=label
        ));
    }

    format!(
        r#"
        <aside class="fixed left-0 top-0 h-full w-64 glass border-r border-void-700/30 z-40">
            <div class="p-6 border-b border-void-700/30">
                <div class="flex items-center gap-3">
                    <div class="w-10 h-10 rounded-lg bg-gradient-to-br from-neon-green to-cyber-600 flex items-center justify-center glow-green">
                        <svg class="w-6 h-6 text-void-950" fill="currentColor" viewBox="0 0 24 24">
                            <path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/>
                        </svg>
                    </div>
                    <div>
                        <h1 class="text-lg font-bold text-neon-green text-glow">CoreVPN</h1>
                        <p class="text-xs text-void-500 font-mono">v0.1.0</p>
                    </div>
                </div>
            </div>
            <nav class="py-4 space-y-1">
                {items_html}
            </nav>
            <div class="absolute bottom-0 left-0 right-0 p-4 border-t border-void-700/30">
                <div class="flex items-center gap-2 text-xs text-void-500">
                    <span class="w-2 h-2 rounded-full bg-neon-green animate-pulse"></span>
                    <span>Server Online</span>
                </div>
            </div>
        </aside>
    "#,
        items_html = items_html
    )
}

/// Dashboard page
#[allow(clippy::too_many_arguments)] // Template render fn; args mirror template fields.
pub fn dashboard(
    uptime: &str,
    active_clients: u32,
    total_connections: u64,
    bytes_rx: u64,
    bytes_tx: u64,
    public_host: &str,
    port: u16,
    protocol: &str,
    subnet: &str,
) -> String {
    let content = format!(
        r##"
        {nav}
        <main class="ml-64 p-8">
            <header class="mb-8">
                <h1 class="text-3xl font-bold text-void-50">Dashboard</h1>
                <p class="text-void-400 mt-1">Server overview and real-time statistics</p>
            </header>

            <!-- Stats Grid -->
            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
                <div class="stat-card glass rounded-xl p-6 glow-green">
                    <div class="flex items-center justify-between">
                        <div>
                            <p class="text-void-400 text-sm font-medium">Active Clients</p>
                            <p class="text-3xl font-bold text-neon-green mt-1">{active_clients}</p>
                        </div>
                        <div class="w-12 h-12 rounded-lg bg-neon-green/10 flex items-center justify-center">
                            <svg class="w-6 h-6 text-neon-green" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z"/>
                            </svg>
                        </div>
                    </div>
                    <p class="text-xs text-void-500 mt-3">Connected right now</p>
                </div>

                <div class="stat-card glass rounded-xl p-6 glow-blue">
                    <div class="flex items-center justify-between">
                        <div>
                            <p class="text-void-400 text-sm font-medium">Total Connections</p>
                            <p class="text-3xl font-bold text-neon-blue mt-1">{total_connections}</p>
                        </div>
                        <div class="w-12 h-12 rounded-lg bg-neon-blue/10 flex items-center justify-center">
                            <svg class="w-6 h-6 text-neon-blue" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/>
                            </svg>
                        </div>
                    </div>
                    <p class="text-xs text-void-500 mt-3">Since server start</p>
                </div>

                <div class="stat-card glass rounded-xl p-6">
                    <div class="flex items-center justify-between">
                        <div>
                            <p class="text-void-400 text-sm font-medium">Data Received</p>
                            <p class="text-3xl font-bold text-void-100 mt-1">{bytes_rx}</p>
                        </div>
                        <div class="w-12 h-12 rounded-lg bg-neon-purple/10 flex items-center justify-center">
                            <svg class="w-6 h-6 text-neon-purple" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 14l-7 7m0 0l-7-7m7 7V3"/>
                            </svg>
                        </div>
                    </div>
                    <p class="text-xs text-void-500 mt-3">Total bytes downloaded</p>
                </div>

                <div class="stat-card glass rounded-xl p-6">
                    <div class="flex items-center justify-between">
                        <div>
                            <p class="text-void-400 text-sm font-medium">Data Sent</p>
                            <p class="text-3xl font-bold text-void-100 mt-1">{bytes_tx}</p>
                        </div>
                        <div class="w-12 h-12 rounded-lg bg-neon-yellow/10 flex items-center justify-center">
                            <svg class="w-6 h-6 text-neon-yellow" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 10l7-7m0 0l7 7m-7-7v18"/>
                            </svg>
                        </div>
                    </div>
                    <p class="text-xs text-void-500 mt-3">Total bytes uploaded</p>
                </div>
            </div>

            <!-- Server Info & Quick Actions -->
            <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
                <!-- Server Info -->
                <div class="lg:col-span-2 glass rounded-xl p-6">
                    <h2 class="text-lg font-semibold text-void-50 mb-4">Server Configuration</h2>
                    <div class="grid grid-cols-2 gap-4">
                        <div class="bg-void-900/50 rounded-lg p-4">
                            <p class="text-void-500 text-xs uppercase tracking-wider mb-1">Public Host</p>
                            <p class="text-void-100 font-mono">{public_host}</p>
                        </div>
                        <div class="bg-void-900/50 rounded-lg p-4">
                            <p class="text-void-500 text-xs uppercase tracking-wider mb-1">Port / Protocol</p>
                            <p class="text-void-100 font-mono">{port}/{protocol}</p>
                        </div>
                        <div class="bg-void-900/50 rounded-lg p-4">
                            <p class="text-void-500 text-xs uppercase tracking-wider mb-1">VPN Subnet</p>
                            <p class="text-void-100 font-mono">{subnet}</p>
                        </div>
                        <div class="bg-void-900/50 rounded-lg p-4">
                            <p class="text-void-500 text-xs uppercase tracking-wider mb-1">Uptime</p>
                            <p class="text-neon-green font-mono">{uptime}</p>
                        </div>
                    </div>
                </div>

                <!-- Quick Actions -->
                <div class="glass rounded-xl p-6">
                    <h2 class="text-lg font-semibold text-void-50 mb-4">Quick Actions</h2>
                    <div class="space-y-3">
                        <a href="/admin/clients/quick-generate" class="flex items-center gap-3 p-3 rounded-lg bg-neon-green/10 text-neon-green hover:bg-neon-green/20 transition-all group">
                            <svg class="w-5 h-5 group-hover:scale-110 transition-transform" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/>
                            </svg>
                            <span class="font-medium">Quick Generate .ovpn</span>
                        </a>
                        <a href="/admin/clients/new" class="flex items-center gap-3 p-3 rounded-lg bg-void-800/50 text-void-300 hover:bg-void-700/50 hover:text-void-100 transition-all group">
                            <svg class="w-5 h-5 group-hover:scale-110 transition-transform" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M18 9v3m0 0v3m0-3h3m-3 0h-3m-2-5a4 4 0 11-8 0 4 4 0 018 0zM3 20a6 6 0 0112 0v1H3v-1z"/>
                            </svg>
                            <span class="font-medium">Add Tracked Client</span>
                        </a>
                        <a href="/admin/sessions" class="flex items-center gap-3 p-3 rounded-lg bg-void-800/50 text-void-300 hover:bg-void-700/50 hover:text-void-100 transition-all group">
                            <svg class="w-5 h-5 group-hover:scale-110 transition-transform" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8.111 16.404a5.5 5.5 0 017.778 0M12 20h.01m-7.08-7.071c3.904-3.905 10.236-3.905 14.141 0M1.394 9.393c5.857-5.857 15.355-5.857 21.213 0"/>
                            </svg>
                            <span class="font-medium">View Sessions</span>
                        </a>
                        <a href="/admin/settings" class="flex items-center gap-3 p-3 rounded-lg bg-void-800/50 text-void-300 hover:bg-void-700/50 hover:text-void-100 transition-all group">
                            <svg class="w-5 h-5 group-hover:scale-110 transition-transform" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6V4m0 2a2 2 0 100 4m0-4a2 2 0 110 4m-6 8a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4m6 6v10m6-2a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4"/>
                            </svg>
                            <span class="font-medium">Server Settings</span>
                        </a>
                    </div>
                </div>
            </div>
        </main>
    "##,
        nav = nav("dashboard"),
        active_clients = active_clients,
        total_connections = total_connections,
        bytes_rx = format_bytes(bytes_rx),
        bytes_tx = format_bytes(bytes_tx),
        public_host = public_host,
        port = port,
        protocol = protocol.to_uppercase(),
        subnet = subnet,
        uptime = uptime,
    );

    base("Dashboard", &content)
}

/// Clients list page
pub fn clients_list(clients: &[ClientInfo], csrf_token: &str) -> String {
    let mut rows = String::new();

    if clients.is_empty() {
        rows = r#"
            <tr>
                <td colspan="5" class="px-6 py-12 text-center text-void-500">
                    <svg class="w-12 h-12 mx-auto mb-4 text-void-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z"/>
                    </svg>
                    <p class="font-medium">No clients configured</p>
                    <p class="text-sm mt-1">Add your first client to get started</p>
                </td>
            </tr>
        "#.to_string();
    } else {
        for client in clients {
            let status_class = if client.connected {
                "bg-neon-green/10 text-neon-green"
            } else {
                "bg-void-700/50 text-void-400"
            };
            let status_text = if client.connected {
                "Online"
            } else {
                "Offline"
            };

            rows.push_str(&format!(r#"
                <tr class="border-b border-void-800/50 hover:bg-void-800/30 transition-colors">
                    <td class="px-6 py-4">
                        <div class="flex items-center gap-3">
                            <div class="w-10 h-10 rounded-full bg-gradient-to-br from-neon-blue to-neon-purple flex items-center justify-center text-void-950 font-bold">
                                {initial}
                            </div>
                            <div>
                                <p class="font-medium text-void-100">{name}</p>
                                <p class="text-sm text-void-500">{email}</p>
                            </div>
                        </div>
                    </td>
                    <td class="px-6 py-4">
                        <span class="px-2 py-1 rounded-full text-xs font-medium {status_class}">{status_text}</span>
                    </td>
                    <td class="px-6 py-4 text-void-400 font-mono text-sm">{vpn_ip}</td>
                    <td class="px-6 py-4 text-void-400 text-sm">{last_seen}</td>
                    <td class="px-6 py-4">
                        <div class="flex items-center gap-2">
                            <a href="/admin/clients/{id}/download" class="p-2 rounded-lg hover:bg-void-700/50 text-void-400 hover:text-neon-green transition-colors" title="Download Config">
                                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/>
                                </svg>
                            </a>
                            <a href="/admin/clients/{id}/edit" class="p-2 rounded-lg hover:bg-void-700/50 text-void-400 hover:text-neon-blue transition-colors" title="Edit">
                                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"/>
                                </svg>
                            </a>
                            <form action="/admin/clients/{id}/revoke" method="POST" class="inline" onsubmit="return confirm('Revoke this client?')">
                                <input type="hidden" name="csrf_token" value="{csrf_token}">
                                <button type="submit" class="p-2 rounded-lg hover:bg-neon-pink/10 text-void-400 hover:text-neon-pink transition-colors" title="Revoke">
                                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636"/>
                                    </svg>
                                </button>
                            </form>
                        </div>
                    </td>
                </tr>
            "#,
                initial = html_escape(&client.name.chars().next().unwrap_or('?').to_uppercase().to_string()),
                name = html_escape(&client.name),
                email = html_escape(&client.email),
                status_class = status_class,
                status_text = status_text,
                vpn_ip = html_escape(client.vpn_ip.as_deref().unwrap_or("-")),
                last_seen = html_escape(client.last_seen.as_deref().unwrap_or("Never")),
                id = html_escape(&client.id),
            ));
        }
    }

    let content = format!(
        r##"
        {nav}
        <main class="ml-64 p-8">
            <header class="mb-8 flex items-center justify-between">
                <div>
                    <h1 class="text-3xl font-bold text-void-50">Clients</h1>
                    <p class="text-void-400 mt-1">Manage VPN client configurations</p>
                </div>
                <div class="flex items-center gap-3">
                    <a href="/admin/clients/quick-generate" class="flex items-center gap-2 px-4 py-2 bg-neon-blue/10 text-neon-blue rounded-lg font-medium hover:bg-neon-blue/20 transition-colors">
                        <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/>
                        </svg>
                        Quick .ovpn
                    </a>
                    <a href="/admin/clients/new" class="flex items-center gap-2 px-4 py-2 bg-neon-green text-void-950 rounded-lg font-medium hover:bg-neon-green/90 transition-colors glow-green">
                        <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6v6m0 0v6m0-6h6m-6 0H6"/>
                        </svg>
                        Add Client
                    </a>
                </div>
            </header>

            <div class="glass rounded-xl overflow-hidden">
                <table class="w-full">
                    <thead class="bg-void-900/50 border-b border-void-700/30">
                        <tr>
                            <th class="px-6 py-4 text-left text-xs font-semibold text-void-400 uppercase tracking-wider">Client</th>
                            <th class="px-6 py-4 text-left text-xs font-semibold text-void-400 uppercase tracking-wider">Status</th>
                            <th class="px-6 py-4 text-left text-xs font-semibold text-void-400 uppercase tracking-wider">VPN IP</th>
                            <th class="px-6 py-4 text-left text-xs font-semibold text-void-400 uppercase tracking-wider">Last Seen</th>
                            <th class="px-6 py-4 text-left text-xs font-semibold text-void-400 uppercase tracking-wider">Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {rows}
                    </tbody>
                </table>
            </div>
        </main>
    "##,
        nav = nav("clients"),
        rows = rows,
    );

    // Note: csrf_token available for future use in forms
    let _ = csrf_token;
    base("Clients", &content)
}

/// New client form
pub fn new_client(csrf_token: &str) -> String {
    let content = format!(
        r##"
        {nav}
        <main class="ml-64 p-8">
            <header class="mb-8">
                <a href="/admin/clients" class="inline-flex items-center gap-2 text-void-400 hover:text-void-100 transition-colors mb-4">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 19l-7-7 7-7"/>
                    </svg>
                    Back to Clients
                </a>
                <h1 class="text-3xl font-bold text-void-50">Add New Client</h1>
                <p class="text-void-400 mt-1">Generate a new VPN client configuration</p>
            </header>

            <div class="max-w-2xl">
                <form action="/admin/clients" method="POST" class="glass rounded-xl p-8 space-y-6">
                    <input type="hidden" name="csrf_token" value="{csrf_token}">
                    <div>
                        <label for="name" class="block text-sm font-medium text-void-300 mb-2">Client Name</label>
                        <input type="text" id="name" name="name" required
                            class="w-full px-4 py-3 bg-void-900/50 border border-void-700/50 rounded-lg text-void-100 placeholder-void-500 focus:outline-none focus:border-neon-green focus:ring-1 focus:ring-neon-green transition-colors"
                            placeholder="e.g., johns-laptop">
                        <p class="text-xs text-void-500 mt-1">Used in the certificate common name</p>
                    </div>

                    <div>
                        <label for="email" class="block text-sm font-medium text-void-300 mb-2">Email Address</label>
                        <input type="email" id="email" name="email" required
                            class="w-full px-4 py-3 bg-void-900/50 border border-void-700/50 rounded-lg text-void-100 placeholder-void-500 focus:outline-none focus:border-neon-green focus:ring-1 focus:ring-neon-green transition-colors"
                            placeholder="user@example.com">
                        <p class="text-xs text-void-500 mt-1">For identification and OAuth2 linking</p>
                    </div>

                    <div>
                        <label class="block text-sm font-medium text-void-300 mb-2">Expiration</label>
                        <select name="expires" class="w-full px-4 py-3 bg-void-900/50 border border-void-700/50 rounded-lg text-void-100 focus:outline-none focus:border-neon-green focus:ring-1 focus:ring-neon-green transition-colors">
                            <option value="365">1 Year</option>
                            <option value="180">6 Months</option>
                            <option value="90">3 Months</option>
                            <option value="30">30 Days</option>
                            <option value="7">7 Days</option>
                        </select>
                    </div>

                    <div class="pt-4 flex items-center gap-4">
                        <button type="submit" class="flex-1 px-6 py-3 bg-neon-green text-void-950 rounded-lg font-semibold hover:bg-neon-green/90 transition-colors glow-green">
                            Create Client
                        </button>
                        <a href="/admin/clients" class="px-6 py-3 bg-void-800/50 text-void-300 rounded-lg font-medium hover:bg-void-700/50 hover:text-void-100 transition-colors">
                            Cancel
                        </a>
                    </div>
                </form>
            </div>
        </main>
    "##,
        nav = nav("clients"),
    );

    base("Add Client", &content)
}

/// Sessions list page
pub fn sessions_list(sessions: &[SessionInfo], csrf_token: &str) -> String {
    let mut rows = String::new();

    if sessions.is_empty() {
        rows = r#"
            <tr>
                <td colspan="6" class="px-6 py-12 text-center text-void-500">
                    <svg class="w-12 h-12 mx-auto mb-4 text-void-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8.111 16.404a5.5 5.5 0 017.778 0M12 20h.01m-7.08-7.071c3.904-3.905 10.236-3.905 14.141 0M1.394 9.393c5.857-5.857 15.355-5.857 21.213 0"/>
                    </svg>
                    <p class="font-medium">No active sessions</p>
                    <p class="text-sm mt-1">Sessions will appear when clients connect</p>
                </td>
            </tr>
        "#.to_string();
    } else {
        for session in sessions {
            rows.push_str(&format!(r#"
                <tr class="border-b border-void-800/50 hover:bg-void-800/30 transition-colors">
                    <td class="px-6 py-4">
                        <div class="flex items-center gap-3">
                            <span class="w-2 h-2 rounded-full bg-neon-green animate-pulse"></span>
                            <span class="font-medium text-void-100">{client}</span>
                        </div>
                    </td>
                    <td class="px-6 py-4 text-void-400 font-mono text-sm">{vpn_ip}</td>
                    <td class="px-6 py-4 text-void-400 font-mono text-sm">{real_ip}</td>
                    <td class="px-6 py-4 text-void-400 text-sm">{connected_at}</td>
                    <td class="px-6 py-4 text-void-400 text-sm">{data_usage}</td>
                    <td class="px-6 py-4">
                        <form action="/admin/sessions/{id}/disconnect" method="POST" class="inline" onsubmit="return confirm('Disconnect this session?')">
                            <input type="hidden" name="csrf_token" value="{csrf_token}">
                            <button type="submit" class="px-3 py-1 rounded-lg bg-neon-pink/10 text-neon-pink text-sm font-medium hover:bg-neon-pink/20 transition-colors">
                                Disconnect
                            </button>
                        </form>
                    </td>
                </tr>
            "#,
                client = html_escape(&session.client_name),
                vpn_ip = html_escape(&session.vpn_ip),
                real_ip = html_escape(&session.real_ip),
                connected_at = html_escape(&session.connected_at),
                data_usage = html_escape(&session.data_usage),
                id = html_escape(&session.id),
            ));
        }
    }

    let content = format!(
        r##"
        {nav}
        <main class="ml-64 p-8">
            <header class="mb-8">
                <h1 class="text-3xl font-bold text-void-50">Active Sessions</h1>
                <p class="text-void-400 mt-1">Currently connected VPN clients</p>
            </header>

            <div class="glass rounded-xl overflow-hidden">
                <table class="w-full">
                    <thead class="bg-void-900/50 border-b border-void-700/30">
                        <tr>
                            <th class="px-6 py-4 text-left text-xs font-semibold text-void-400 uppercase tracking-wider">Client</th>
                            <th class="px-6 py-4 text-left text-xs font-semibold text-void-400 uppercase tracking-wider">VPN IP</th>
                            <th class="px-6 py-4 text-left text-xs font-semibold text-void-400 uppercase tracking-wider">Real IP</th>
                            <th class="px-6 py-4 text-left text-xs font-semibold text-void-400 uppercase tracking-wider">Connected</th>
                            <th class="px-6 py-4 text-left text-xs font-semibold text-void-400 uppercase tracking-wider">Data Usage</th>
                            <th class="px-6 py-4 text-left text-xs font-semibold text-void-400 uppercase tracking-wider">Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {rows}
                    </tbody>
                </table>
            </div>
        </main>
    "##,
        nav = nav("sessions"),
        rows = rows,
    );

    // Note: csrf_token available for future use in forms
    let _ = csrf_token;
    base("Sessions", &content)
}

/// Settings page
#[allow(clippy::too_many_arguments)] // Template render fn; args mirror template fields.
pub fn settings(
    public_host: &str,
    port: u16,
    protocol: &str,
    subnet: &str,
    max_clients: u32,
    oauth_enabled: bool,
    oauth_provider: Option<&str>,
    csrf_token: &str,
) -> String {
    let oauth_status = if oauth_enabled {
        format!(
            r#"<span class="text-neon-green">Enabled ({provider})</span>"#,
            provider = oauth_provider.unwrap_or("unknown")
        )
    } else {
        r#"<span class="text-void-400">Disabled</span>"#.to_string()
    };

    let content = format!(
        r##"
        {nav}
        <main class="ml-64 p-8">
            <header class="mb-8">
                <h1 class="text-3xl font-bold text-void-50">Settings</h1>
                <p class="text-void-400 mt-1">Server configuration and options</p>
            </header>

            <div class="grid gap-6 max-w-4xl">
                <!-- Server Settings -->
                <div class="glass rounded-xl p-6">
                    <h2 class="text-lg font-semibold text-void-50 mb-6 flex items-center gap-2">
                        <svg class="w-5 h-5 text-neon-green" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01"/>
                        </svg>
                        Server Configuration
                    </h2>
                    <div class="grid grid-cols-2 gap-4">
                        <div class="bg-void-900/50 rounded-lg p-4">
                            <p class="text-void-500 text-xs uppercase tracking-wider mb-1">Public Host</p>
                            <p class="text-void-100 font-mono">{public_host}</p>
                        </div>
                        <div class="bg-void-900/50 rounded-lg p-4">
                            <p class="text-void-500 text-xs uppercase tracking-wider mb-1">Port / Protocol</p>
                            <p class="text-void-100 font-mono">{port}/{protocol}</p>
                        </div>
                        <div class="bg-void-900/50 rounded-lg p-4">
                            <p class="text-void-500 text-xs uppercase tracking-wider mb-1">VPN Subnet</p>
                            <p class="text-void-100 font-mono">{subnet}</p>
                        </div>
                        <div class="bg-void-900/50 rounded-lg p-4">
                            <p class="text-void-500 text-xs uppercase tracking-wider mb-1">Max Clients</p>
                            <p class="text-void-100 font-mono">{max_clients}</p>
                        </div>
                    </div>
                </div>

                <!-- Security Settings -->
                <div class="glass rounded-xl p-6">
                    <h2 class="text-lg font-semibold text-void-50 mb-6 flex items-center gap-2">
                        <svg class="w-5 h-5 text-neon-blue" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
                        </svg>
                        Security & Authentication
                    </h2>
                    <div class="space-y-4">
                        <div class="flex items-center justify-between p-4 bg-void-900/50 rounded-lg">
                            <div>
                                <p class="font-medium text-void-100">OAuth2 / SSO</p>
                                <p class="text-sm text-void-500">Single Sign-On authentication</p>
                            </div>
                            {oauth_status}
                        </div>
                        <div class="flex items-center justify-between p-4 bg-void-900/50 rounded-lg">
                            <div>
                                <p class="font-medium text-void-100">TLS Auth</p>
                                <p class="text-sm text-void-500">Additional HMAC authentication</p>
                            </div>
                            <span class="text-neon-green">Enabled</span>
                        </div>
                        <div class="flex items-center justify-between p-4 bg-void-900/50 rounded-lg">
                            <div>
                                <p class="font-medium text-void-100">Perfect Forward Secrecy</p>
                                <p class="text-sm text-void-500">ECDHE key exchange</p>
                            </div>
                            <span class="text-neon-green">Enabled</span>
                        </div>
                    </div>
                </div>

                <!-- Danger Zone -->
                <div class="glass rounded-xl p-6 border border-neon-pink/20">
                    <h2 class="text-lg font-semibold text-neon-pink mb-6 flex items-center gap-2">
                        <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
                        </svg>
                        Danger Zone
                    </h2>
                    <div class="space-y-4">
                        <div class="flex items-center justify-between p-4 bg-neon-pink/5 rounded-lg border border-neon-pink/10">
                            <div>
                                <p class="font-medium text-void-100">Regenerate CA</p>
                                <p class="text-sm text-void-500">Invalidates all existing client certificates</p>
                            </div>
                            <button class="px-4 py-2 bg-neon-pink/10 text-neon-pink rounded-lg text-sm font-medium hover:bg-neon-pink/20 transition-colors" onclick="alert('This would regenerate the CA in production')">
                                Regenerate
                            </button>
                        </div>
                        <div class="flex items-center justify-between p-4 bg-neon-pink/5 rounded-lg border border-neon-pink/10">
                            <div>
                                <p class="font-medium text-void-100">Disconnect All</p>
                                <p class="text-sm text-void-500">Force disconnect all active sessions</p>
                            </div>
                            <form action="/admin/sessions/disconnect-all" method="POST" onsubmit="return confirm('Disconnect all sessions?')">
                                <input type="hidden" name="csrf_token" value="{csrf_token}">
                                <button type="submit" class="px-4 py-2 bg-neon-pink/10 text-neon-pink rounded-lg text-sm font-medium hover:bg-neon-pink/20 transition-colors">
                                    Disconnect All
                                </button>
                            </form>
                        </div>
                    </div>
                </div>
            </div>
        </main>
    "##,
        nav = nav("settings"),
        public_host = public_host,
        port = port,
        protocol = protocol.to_uppercase(),
        subnet = subnet,
        max_clients = max_clients,
        oauth_status = oauth_status,
        csrf_token = html_escape(csrf_token),
    );

    base("Settings", &content)
}

/// Client download success page with auto-download
pub fn client_download(client_name: &str, filename: &str, ovpn_content: &str) -> String {
    // Base64 encode the content for data URL download
    let encoded = base64_encode(ovpn_content.as_bytes());

    let content = format!(
        r##"
        {nav}
        <main class="ml-64 p-8">
            <div class="max-w-xl mx-auto text-center py-12">
                <div class="w-20 h-20 mx-auto mb-6 rounded-full bg-neon-green/10 flex items-center justify-center glow-green">
                    <svg class="w-10 h-10 text-neon-green" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/>
                    </svg>
                </div>
                <h1 class="text-2xl font-bold text-void-50 mb-2">Client Created Successfully</h1>
                <p class="text-void-400 mb-8">Configuration for <strong class="text-neon-green">{client_name}</strong> is ready</p>

                <div class="glass rounded-xl p-6 mb-8">
                    <p class="text-void-500 text-sm mb-4">Your download should start automatically. If not, click below:</p>
                    <a id="download-link" download="{filename}" href="data:application/x-openvpn-profile;base64,{encoded}" class="inline-flex items-center gap-2 px-6 py-3 bg-neon-green text-void-950 rounded-lg font-semibold hover:bg-neon-green/90 transition-colors glow-green">
                        <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/>
                        </svg>
                        Download {filename}
                    </a>
                </div>

                <div class="text-left glass rounded-xl p-6 mb-6">
                    <h2 class="font-semibold text-void-100 mb-4">Next Steps</h2>
                    <ol class="space-y-3 text-void-400 text-sm">
                        <li class="flex items-start gap-3">
                            <span class="flex-shrink-0 w-6 h-6 rounded-full bg-neon-blue/10 text-neon-blue text-xs flex items-center justify-center font-bold">1</span>
                            <span>Transfer the .ovpn file to your device</span>
                        </li>
                        <li class="flex items-start gap-3">
                            <span class="flex-shrink-0 w-6 h-6 rounded-full bg-neon-blue/10 text-neon-blue text-xs flex items-center justify-center font-bold">2</span>
                            <span>Import into your OpenVPN client (OpenVPN Connect, Tunnelblick, etc.)</span>
                        </li>
                        <li class="flex items-start gap-3">
                            <span class="flex-shrink-0 w-6 h-6 rounded-full bg-neon-blue/10 text-neon-blue text-xs flex items-center justify-center font-bold">3</span>
                            <span>Connect and enjoy secure browsing!</span>
                        </li>
                    </ol>
                </div>

                <!-- Config Preview (collapsed by default) -->
                <details class="text-left glass rounded-xl p-6 mb-8">
                    <summary class="font-semibold text-void-100 cursor-pointer flex items-center gap-2">
                        <svg class="w-5 h-5 text-void-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"/>
                        </svg>
                        View Configuration
                    </summary>
                    <pre class="mt-4 p-4 bg-void-900/50 rounded-lg text-xs text-void-300 font-mono overflow-x-auto max-h-64 overflow-y-auto">{ovpn_preview}</pre>
                </details>

                <a href="/admin/clients" class="inline-flex items-center gap-2 text-void-400 hover:text-void-100 transition-colors">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 19l-7-7 7-7"/>
                    </svg>
                    Back to Clients
                </a>
            </div>
        </main>
        <script>
            // Auto-download the file on page load
            document.addEventListener('DOMContentLoaded', function() {{
                setTimeout(function() {{
                    document.getElementById('download-link').click();
                }}, 500);
            }});
        </script>
    "##,
        nav = nav("clients"),
        client_name = html_escape(client_name),
        filename = html_escape(filename),
        encoded = encoded,
        ovpn_preview = html_escape(ovpn_content),
    );

    base("Download Config", &content)
}

/// Base64 encode bytes
fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();

    for chunk in data.chunks(3) {
        let n = match chunk.len() {
            3 => ((chunk[0] as u32) << 16) | ((chunk[1] as u32) << 8) | (chunk[2] as u32),
            2 => ((chunk[0] as u32) << 16) | ((chunk[1] as u32) << 8),
            1 => (chunk[0] as u32) << 16,
            _ => continue,
        };

        result.push(ALPHABET[((n >> 18) & 0x3F) as usize] as char);
        result.push(ALPHABET[((n >> 12) & 0x3F) as usize] as char);

        if chunk.len() > 1 {
            result.push(ALPHABET[((n >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }

        if chunk.len() > 2 {
            result.push(ALPHABET[(n & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }

    result
}

/// HTML escape for displaying in pre tags
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Quick generate page - simple form for fast config generation
pub fn quick_generate(csrf_token: &str) -> String {
    let content = format!(
        r##"
        {nav}
        <main class="ml-64 p-8">
            <header class="mb-8">
                <a href="/admin/clients" class="inline-flex items-center gap-2 text-void-400 hover:text-void-100 transition-colors mb-4">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 19l-7-7 7-7"/>
                    </svg>
                    Back to Clients
                </a>
                <h1 class="text-3xl font-bold text-void-50">Quick Generate .ovpn</h1>
                <p class="text-void-400 mt-1">Generate and download a VPN configuration instantly</p>
            </header>

            <div class="max-w-xl">
                <div class="glass rounded-xl p-8">
                    <form action="/admin/clients/quick-generate" method="POST" class="space-y-6">
                        <input type="hidden" name="csrf_token" value="{csrf_token}">
                        <div>
                            <label for="name" class="block text-sm font-medium text-void-300 mb-2">Client Name</label>
                            <input type="text" id="name" name="name" required
                                class="w-full px-4 py-3 bg-void-900/50 border border-void-700/50 rounded-lg text-void-100 placeholder-void-500 focus:outline-none focus:border-neon-green focus:ring-1 focus:ring-neon-green transition-colors"
                                placeholder="e.g., johns-laptop, mobile-phone">
                            <p class="text-xs text-void-500 mt-1">Used in the certificate and filename</p>
                        </div>

                        <div class="flex items-center gap-3 p-4 bg-void-900/50 rounded-lg">
                            <input type="checkbox" id="mobile" name="mobile" value="true"
                                class="w-4 h-4 text-neon-green bg-void-900 border-void-600 rounded focus:ring-neon-green focus:ring-2">
                            <label for="mobile" class="text-void-300">
                                <span class="font-medium">Mobile optimized</span>
                                <span class="block text-xs text-void-500">Includes settings for mobile networks (reconnection, retry)</span>
                            </label>
                        </div>

                        <button type="submit" class="w-full flex items-center justify-center gap-2 px-6 py-3 bg-neon-green text-void-950 rounded-lg font-semibold hover:bg-neon-green/90 transition-colors glow-green">
                            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/>
                            </svg>
                            Generate & Download .ovpn
                        </button>
                    </form>
                </div>

                <div class="mt-8 glass rounded-xl p-6">
                    <h3 class="font-semibold text-void-100 mb-4 flex items-center gap-2">
                        <svg class="w-5 h-5 text-neon-blue" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
                        </svg>
                        About Quick Generate
                    </h3>
                    <ul class="space-y-2 text-void-400 text-sm">
                        <li class="flex items-start gap-2">
                            <span class="text-neon-green">✓</span>
                            Generates a fresh certificate and private key
                        </li>
                        <li class="flex items-start gap-2">
                            <span class="text-neon-green">✓</span>
                            Downloads immediately without saving to database
                        </li>
                        <li class="flex items-start gap-2">
                            <span class="text-neon-green">✓</span>
                            Configuration is ready to import into OpenVPN clients
                        </li>
                        <li class="flex items-start gap-2">
                            <span class="text-neon-yellow">⚠</span>
                            For tracked clients with revocation, use "Add Client" instead
                        </li>
                    </ul>
                </div>
            </div>
        </main>
    "##,
        nav = nav("clients"),
    );

    base("Quick Generate", &content)
}

/// Error page
pub fn error_page(status: u16, message: &str) -> String {
    let (title, emoji) = match status {
        404 => ("Not Found", "🔍"),
        403 => ("Forbidden", "🚫"),
        500 => ("Server Error", "💥"),
        _ => ("Error", "⚠️"),
    };

    let content = format!(
        r##"
        <div class="min-h-screen flex items-center justify-center p-8">
            <div class="text-center">
                <div class="text-6xl mb-6">{emoji}</div>
                <h1 class="text-6xl font-bold text-neon-pink text-glow mb-4">{status}</h1>
                <h2 class="text-2xl font-semibold text-void-100 mb-2">{title}</h2>
                <p class="text-void-400 mb-8 max-w-md">{message}</p>
                <a href="/admin" class="inline-flex items-center gap-2 px-6 py-3 bg-neon-green text-void-950 rounded-lg font-semibold hover:bg-neon-green/90 transition-colors glow-green">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6"/>
                    </svg>
                    Back to Dashboard
                </a>
            </div>
        </div>
    "##,
        emoji = emoji,
        status = status,
        title = html_escape(title),
        message = html_escape(message),
    );

    base("Error", &content)
}

// ============================================================================
// Helper types and functions
// ============================================================================

/// Client info for templates
pub struct ClientInfo {
    pub id: String,
    pub name: String,
    pub email: String,
    pub connected: bool,
    pub vpn_ip: Option<String>,
    pub last_seen: Option<String>,
}

/// Session info for templates
pub struct SessionInfo {
    pub id: String,
    pub client_name: String,
    pub vpn_ip: String,
    pub real_ip: String,
    pub connected_at: String,
    pub data_usage: String,
}

/// Format bytes into human readable format
fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    const TB: u64 = GB * 1024;

    if bytes >= TB {
        format!("{:.2} TB", bytes as f64 / TB as f64)
    } else if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}
