defmodule KraitWeb.Layouts do
  @moduledoc "Layout components for LiveView"

  use Phoenix.Component

  def app(assigns) do
    ~H"""
    <!DOCTYPE html>
    <html lang="en">
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <meta name="csrf-token" content={Phoenix.Controller.get_csrf_token()} />
        <title><%= assigns[:page_title] || "KRAIT" %></title>
        <style>
          @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600;700&display=swap');

          :root {
            --bg-deep: #07080d;
            --bg-surface: #0d0f16;
            --bg-card: #111320;
            --bg-card-hover: #161a2a;
            --border: #1a1e30;
            --border-glow: #10b98122;
            --green-400: #34d399;
            --green-500: #10b981;
            --green-600: #059669;
            --green-700: #047857;
            --green-glow: rgba(16, 185, 129, 0.15);
            --amber-400: #fbbf24;
            --amber-500: #f59e0b;
            --red-400: #f87171;
            --red-500: #ef4444;
            --text-primary: #e2e8f0;
            --text-secondary: #8892a8;
            --text-muted: #4a5568;
            --font: 'JetBrains Mono', 'SF Mono', 'Fira Code', monospace;
          }

          *, *::before, *::after { box-sizing: border-box; }

          html { scroll-behavior: smooth; }

          body {
            margin: 0;
            padding: 0;
            background: var(--bg-deep);
            color: var(--text-primary);
            font-family: var(--font);
            font-size: 14px;
            line-height: 1.6;
            -webkit-font-smoothing: antialiased;
            -moz-osx-font-smoothing: grayscale;
            min-height: 100vh;
          }

          body::before {
            content: '';
            position: fixed;
            inset: 0;
            background-image:
              radial-gradient(circle at 20% 20%, var(--green-glow) 0%, transparent 50%),
              radial-gradient(circle at 80% 80%, rgba(16, 185, 129, 0.05) 0%, transparent 50%);
            pointer-events: none;
            z-index: 0;
          }

          body > * { position: relative; z-index: 1; }

          ::selection { background: var(--green-600); color: white; }
          a { color: var(--green-400); text-decoration: none; transition: color 0.2s; }
          a:hover { color: var(--green-500); }

          ::-webkit-scrollbar { width: 5px; }
          ::-webkit-scrollbar-track { background: transparent; }
          ::-webkit-scrollbar-thumb {
            background: rgba(16, 185, 129, 0.15);
            border-radius: 3px;
          }
          ::-webkit-scrollbar-thumb:hover {
            background: rgba(16, 185, 129, 0.3);
          }
        </style>
      </head>
      <body>
        <%= @inner_content %>
        <script src="https://cdn.jsdelivr.net/npm/phoenix@1.8.3/priv/static/phoenix.min.js"></script>
        <script src="https://cdn.jsdelivr.net/npm/phoenix_live_view@1.1.22/priv/static/phoenix_live_view.min.js"></script>
        <script>
          let csrfToken = document.querySelector("meta[name='csrf-token']").getAttribute("content");
          let liveSocket = new window.LiveView.LiveSocket("/live", window.Phoenix.Socket, {
            params: {_csrf_token: csrfToken}
          });
          liveSocket.connect();
        </script>
      </body>
    </html>
    """
  end
end
