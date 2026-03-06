defmodule KraitWeb.EvolutionLive do
  @moduledoc "LiveView dashboard for the evolution feed"
  use Phoenix.LiveView

  require Logger

  @impl true
  def mount(_params, session, socket) do
    # Defense-in-depth: verify session in mount (primary auth is RequireAdminAuth plug).
    # Bypass only in test env with disable_auth: true (matches plug behavior).
    if bypass_auth?() do
      do_mount(socket, nil)
    else
      # v22 SEC-12: Use KraitWeb.Auth.verify_admin_session (nonce-based Phoenix.Token)
      session_signed = Map.get(session, "krait_admin_token")

      case KraitWeb.Auth.verify_admin_session(session_signed) do
        # v24 F-12: Store session_signed for periodic re-verification
        :ok -> do_mount(socket, session_signed)
        :error -> {:ok, redirect(socket, to: "/admin/login")}
      end
    end
  end

  defp bypass_auth? do
    Application.get_env(:krait, :env, :dev) == :test and
      Application.get_env(:krait, :disable_auth, false)
  end

  defp do_mount(socket, session_signed) do
    if connected?(socket) do
      Phoenix.PubSub.subscribe(Krait.PubSub, "evolution:feed")
      Phoenix.PubSub.subscribe(Krait.PubSub, "kill_switch")
      # v23 M-6: Periodic session re-verification (every 5 minutes)
      Phoenix.PubSub.subscribe(Krait.PubSub, "admin:session_invalidated")
      :timer.send_interval(300_000, self(), :verify_session)
    end

    events = fetch_events()

    {:ok,
     assign(socket,
       events: events,
       stats: compute_stats(events),
       expanded: MapSet.new(),
       page_title: "KRAIT Evolution Feed",
       # v24 F-12: Store for periodic full session re-verification
       session_signed: session_signed,
       # Evolution trigger form state
       evolving: false,
       evolution_error: nil,
       evolution_success: nil,
       kill_switch_active: kill_switch_halted?()
     )}
  end

  @impl true
  def handle_info({:evolution_event, event}, socket) do
    events = [event | socket.assigns.events]

    {:noreply,
     assign(socket,
       events: events,
       stats: compute_stats(events)
     )}
  end

  # v24 F-12: Full session re-verification — checks hash validity, not just existence
  def handle_info(:verify_session, socket) do
    if bypass_auth?() do
      {:noreply, socket}
    else
      case KraitWeb.Auth.verify_admin_session(socket.assigns[:session_signed]) do
        :ok -> {:noreply, socket}
        :error -> {:noreply, redirect(socket, to: "/admin/login")}
      end
    end
  end

  # Evolution completion callback
  def handle_info({:evolution_complete, _skill_name, :ok}, socket) do
    {:noreply,
     assign(socket,
       evolving: false,
       evolution_success: "Evolution completed successfully",
       evolution_error: nil
     )}
  end

  def handle_info({:evolution_complete, _skill_name, {:error, reason}}, socket) do
    safe_reason =
      reason
      |> inspect(limit: 200, printable_limit: 200)
      |> String.slice(0, 200)

    {:noreply,
     assign(socket,
       evolving: false,
       evolution_error: "Evolution failed: #{safe_reason}",
       evolution_success: nil
     )}
  end

  # Kill switch state changes (PubSub broadcasts from KillSwitch GenServer)
  def handle_info({:kill_switch_engaged, _reason}, socket) do
    {:noreply, assign(socket, kill_switch_active: true)}
  end

  def handle_info(:kill_switch_disengaged, socket) do
    {:noreply, assign(socket, kill_switch_active: false)}
  end

  # v23 M-6: Immediate disconnection on explicit logout
  def handle_info(:session_invalidated, socket) do
    {:noreply, redirect(socket, to: "/admin/login")}
  end

  def handle_info(_msg, socket), do: {:noreply, socket}

  @impl true
  def handle_event("trigger_evolution", params, socket) do
    skill_name = String.trim(Map.get(params, "skill_name", ""))
    description = String.trim(Map.get(params, "description", ""))

    with :ok <- validate_trigger_params(skill_name, description),
         false <- socket.assigns.kill_switch_active,
         false <- socket.assigns.evolving do
      case start_evolution(skill_name, description) do
        :ok ->
          {:noreply,
           assign(socket,
             evolving: true,
             evolution_error: nil,
             evolution_success: nil
           )}

        {:error, reason} ->
          {:noreply, assign(socket, evolution_error: reason)}
      end
    else
      {:error, reason} ->
        {:noreply, assign(socket, evolution_error: reason)}

      true ->
        reason =
          cond do
            socket.assigns.kill_switch_active -> "Kill switch is active"
            socket.assigns.evolving -> "Evolution already in progress"
            true -> "Cannot trigger evolution"
          end

        {:noreply, assign(socket, evolution_error: reason)}
    end
  end

  def handle_event("toggle_event", %{"id" => id}, socket) do
    expanded =
      if MapSet.member?(socket.assigns.expanded, id) do
        MapSet.delete(socket.assigns.expanded, id)
      else
        MapSet.put(socket.assigns.expanded, id)
      end

    {:noreply, assign(socket, expanded: expanded)}
  end

  @impl true
  def render(assigns) do
    ~H"""
    <style>
      /* ═══ Background ═══ */
      .bg-grid {
        position: fixed;
        inset: 0;
        background-image: radial-gradient(circle, rgba(16,185,129,0.05) 1px, transparent 1px);
        background-size: 30px 30px;
        pointer-events: none;
        z-index: 0;
      }

      .bg-orb {
        position: fixed;
        border-radius: 50%;
        pointer-events: none;
        z-index: 0;
      }

      .bg-orb--1 {
        width: 600px;
        height: 600px;
        top: -200px;
        left: -150px;
        background: radial-gradient(circle, rgba(16,185,129,0.07), transparent 70%);
        animation: drift-1 30s ease-in-out infinite alternate;
      }

      .bg-orb--2 {
        width: 450px;
        height: 450px;
        bottom: -150px;
        right: -100px;
        background: radial-gradient(circle, rgba(16,185,129,0.04), transparent 70%);
        animation: drift-2 25s ease-in-out infinite alternate;
      }

      @keyframes drift-1 {
        from { transform: translate(0, 0); }
        to { transform: translate(80px, 60px); }
      }

      @keyframes drift-2 {
        from { transform: translate(0, 0); }
        to { transform: translate(-60px, -50px); }
      }

      .scanline {
        position: fixed;
        left: 0;
        right: 0;
        height: 1px;
        background: linear-gradient(90deg, transparent 0%, rgba(16,185,129,0.1) 40%, rgba(16,185,129,0.1) 60%, transparent 100%);
        pointer-events: none;
        z-index: 100;
        animation: scan 10s linear infinite;
      }

      @keyframes scan {
        0% { top: -1px; opacity: 0; }
        3% { opacity: 1; }
        97% { opacity: 1; }
        100% { top: 100vh; opacity: 0; }
      }

      /* ═══ Layout ═══ */
      .krait-dash {
        min-height: 100vh;
        position: relative;
        z-index: 1;
      }

      /* ═══ Hero ═══ */
      .krait-hero {
        text-align: center;
        padding: 48px 24px 36px;
        border-bottom: 1px solid var(--border);
        background:
          radial-gradient(ellipse at 50% 80%, rgba(16,185,129,0.07) 0%, transparent 60%),
          linear-gradient(180deg, rgba(13,15,22,0.95), rgba(7,8,13,0.98));
        position: relative;
      }

      .krait-hero::after {
        content: '';
        position: absolute;
        bottom: -1px;
        left: 10%;
        right: 10%;
        height: 1px;
        background: linear-gradient(90deg, transparent, rgba(16,185,129,0.25), transparent);
      }

      .krait-title {
        font-size: 42px;
        font-weight: 700;
        letter-spacing: 18px;
        text-transform: uppercase;
        margin: 24px 0 6px;
        text-indent: 18px;
        background: linear-gradient(135deg, #6ee7b7, #34d399 30%, #10b981 70%, #059669);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
        filter: drop-shadow(0 0 30px rgba(16,185,129,0.2));
      }

      .subtitle {
        color: var(--text-muted);
        font-size: 11px;
        letter-spacing: 4px;
        text-transform: uppercase;
        margin: 0;
      }

      .tagline {
        color: var(--text-secondary);
        font-size: 13px;
        margin: 14px 0 0;
        font-weight: 300;
        font-style: italic;
        opacity: 0.7;
      }

      .krait-main {
        max-width: 800px;
        margin: 0 auto;
        padding: 32px 24px 80px;
        position: relative;
        z-index: 1;
      }

      /* ═══ Stats ═══ */
      .stats-row {
        display: grid;
        grid-template-columns: repeat(4, 1fr);
        gap: 12px;
        margin-bottom: 40px;
      }

      .stat {
        background: rgba(17, 19, 32, 0.5);
        backdrop-filter: blur(12px);
        -webkit-backdrop-filter: blur(12px);
        border: 1px solid rgba(26, 30, 48, 0.8);
        border-radius: 12px;
        padding: 20px 14px;
        text-align: center;
        transition: all 0.3s ease;
        position: relative;
        overflow: hidden;
      }

      .stat::before {
        content: '';
        position: absolute;
        inset: -1px;
        border-radius: inherit;
        padding: 1px;
        background: linear-gradient(135deg, rgba(16,185,129,0.2), transparent 60%);
        -webkit-mask: linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0);
        -webkit-mask-composite: xor;
        mask-composite: exclude;
        opacity: 0;
        transition: opacity 0.3s;
        pointer-events: none;
      }

      .stat:hover {
        transform: translateY(-2px);
        box-shadow: 0 8px 24px rgba(0,0,0,0.3), 0 0 16px rgba(16,185,129,0.06);
      }

      .stat:hover::before { opacity: 1; }

      .stat-val {
        font-size: 32px;
        font-weight: 700;
        color: var(--green-400);
        line-height: 1;
      }

      .stat-val--amber { color: var(--amber-400); }

      .stat-lbl {
        font-size: 10px;
        color: var(--text-muted);
        text-transform: uppercase;
        letter-spacing: 2px;
        margin-top: 8px;
      }

      .stat-accent {
        display: block;
        width: 20px;
        height: 2px;
        background: var(--green-700);
        margin: 10px auto 0;
        border-radius: 1px;
        opacity: 0.5;
      }

      /* ═══ Feed Header ═══ */
      .feed-hdr {
        font-size: 11px;
        color: var(--text-muted);
        text-transform: uppercase;
        letter-spacing: 4px;
        margin-bottom: 24px;
        padding-bottom: 12px;
        border-bottom: 1px solid var(--border);
        display: flex;
        align-items: center;
        gap: 10px;
      }

      .feed-dot {
        width: 6px;
        height: 6px;
        border-radius: 50%;
        background: var(--green-500);
        box-shadow: 0 0 8px var(--green-500), 0 0 16px rgba(16,185,129,0.2);
        animation: blink 2s ease-in-out infinite;
        flex-shrink: 0;
      }

      @keyframes blink {
        0%, 100% { opacity: 1; box-shadow: 0 0 8px var(--green-500), 0 0 16px rgba(16,185,129,0.3); }
        50% { opacity: 0.3; box-shadow: 0 0 4px var(--green-500); }
      }

      /* ═══ Timeline ═══ */
      .timeline {
        position: relative;
        padding-left: 30px;
      }

      .tl-line {
        position: absolute;
        left: 7px;
        top: 0;
        bottom: 0;
        width: 1px;
        background: linear-gradient(
          to bottom,
          var(--green-500) 0%,
          var(--green-700) 40%,
          rgba(4,120,87,0.15) 100%
        );
      }

      .ev-wrap {
        position: relative;
        margin-bottom: 12px;
        animation: card-enter 0.5s ease-out both;
      }

      @keyframes card-enter {
        from { opacity: 0; transform: translateX(12px); }
        to { opacity: 1; transform: translateX(0); }
      }

      .tl-dot {
        position: absolute;
        left: -26px;
        top: 22px;
        width: 9px;
        height: 9px;
        border-radius: 50%;
        background: var(--green-500);
        border: 2px solid var(--bg-deep);
        box-shadow: 0 0 8px rgba(16,185,129,0.3);
        z-index: 2;
      }

      .tl-dot--amber {
        background: var(--amber-500);
        box-shadow: 0 0 8px rgba(245,158,11,0.3);
      }

      /* ═══ Event Card ═══ */
      .ev {
        background: rgba(17, 19, 32, 0.55);
        backdrop-filter: blur(10px);
        -webkit-backdrop-filter: blur(10px);
        border: 1px solid var(--border);
        border-radius: 12px;
        padding: 20px 22px 18px;
        transition: all 0.3s ease;
        position: relative;
        overflow: hidden;
      }

      .ev::before {
        content: '';
        position: absolute;
        left: 0;
        top: 0;
        bottom: 0;
        width: 3px;
        background: linear-gradient(to bottom, var(--green-400), var(--green-600));
        border-radius: 0 2px 2px 0;
      }

      .ev--draft::before {
        background: linear-gradient(to bottom, var(--amber-400), var(--amber-500));
      }

      .ev:hover {
        background: rgba(22, 26, 42, 0.7);
        border-color: rgba(16,185,129,0.18);
        transform: translateY(-3px) translateX(2px);
        box-shadow:
          0 12px 40px rgba(0,0,0,0.4),
          0 0 24px rgba(16,185,129,0.06),
          inset 0 1px 0 rgba(255,255,255,0.02);
      }

      .ev-top {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 8px;
      }

      .ev-name {
        font-size: 16px;
        font-weight: 600;
        color: var(--text-primary);
      }

      .prompt {
        color: var(--green-500);
        margin-right: 8px;
        font-weight: 400;
        opacity: 0.7;
      }

      .badge {
        display: inline-flex;
        align-items: center;
        gap: 5px;
        padding: 3px 12px;
        border-radius: 20px;
        font-size: 10px;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 1.5px;
      }

      .badge--ok {
        background: rgba(16,185,129,0.1);
        color: var(--green-400);
        border: 1px solid rgba(16,185,129,0.2);
      }

      .badge--draft {
        background: rgba(245,158,11,0.1);
        color: var(--amber-400);
        border: 1px solid rgba(245,158,11,0.2);
      }

      .badge-dot {
        width: 4px;
        height: 4px;
        border-radius: 50%;
        background: currentColor;
      }

      .ev-desc {
        color: var(--text-secondary);
        font-size: 13px;
        margin: 0 0 16px;
        padding-left: 20px;
        line-height: 1.5;
      }

      .ev-grid {
        display: grid;
        grid-template-columns: repeat(4, 1fr);
        gap: 8px;
        padding-left: 20px;
        font-size: 12px;
      }

      .ev-m-label {
        font-size: 9px;
        color: var(--text-muted);
        text-transform: uppercase;
        letter-spacing: 1px;
        margin-bottom: 2px;
        opacity: 0.7;
      }

      .ev-m-val {
        color: var(--text-secondary);
        font-weight: 500;
      }

      .ev-hash {
        font-size: 10px;
        background: rgba(255,255,255,0.04);
        padding: 2px 7px;
        border-radius: 4px;
        color: var(--text-muted);
        font-family: var(--font);
      }

      .ev-foot {
        margin-top: 16px;
        padding-left: 20px;
        display: flex;
        justify-content: space-between;
        align-items: center;
      }

      .ev-time {
        font-size: 11px;
        color: var(--text-muted);
      }

      .pr-link {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        font-size: 11px;
        color: var(--green-400);
        background: rgba(16,185,129,0.06);
        padding: 6px 16px;
        border-radius: 8px;
        border: 1px solid rgba(16,185,129,0.12);
        transition: all 0.25s;
        text-decoration: none;
      }

      .pr-link:hover {
        background: rgba(16,185,129,0.15);
        border-color: rgba(16,185,129,0.3);
        box-shadow: 0 0 12px rgba(16,185,129,0.1);
        text-decoration: none;
      }

      .pr-arrow { transition: transform 0.2s; display: inline-block; }
      .pr-link:hover .pr-arrow { transform: translateX(3px); }

      /* ═══ Expandable Card ═══ */
      .ev-clickable {
        cursor: pointer;
        user-select: none;
      }

      .ev-chevron {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        width: 24px;
        height: 24px;
        border-radius: 6px;
        background: rgba(255,255,255,0.03);
        border: 1px solid rgba(255,255,255,0.06);
        transition: all 0.3s ease;
        flex-shrink: 0;
        margin-left: 10px;
      }

      .ev-chevron svg {
        width: 12px;
        height: 12px;
        transition: transform 0.3s ease;
        color: var(--text-muted);
      }

      .ev-chevron--open svg {
        transform: rotate(180deg);
        color: var(--green-400);
      }

      .ev-clickable:hover .ev-chevron {
        background: rgba(16,185,129,0.08);
        border-color: rgba(16,185,129,0.15);
      }

      .ev-detail {
        max-height: 0;
        overflow: hidden;
        transition: max-height 0.35s ease, opacity 0.25s ease;
        opacity: 0;
      }

      .ev-detail--open {
        max-height: 500px;
        opacity: 1;
      }

      .ev-detail-inner {
        padding: 16px 20px 4px;
        border-top: 1px solid rgba(255,255,255,0.04);
        margin-top: 16px;
      }

      .ev-detail-grid {
        display: grid;
        grid-template-columns: repeat(3, 1fr);
        gap: 12px;
        margin-bottom: 14px;
      }

      .ev-detail-section {
        margin-bottom: 14px;
      }

      .ev-detail-label {
        font-size: 9px;
        color: var(--text-muted);
        text-transform: uppercase;
        letter-spacing: 1.5px;
        margin-bottom: 4px;
        opacity: 0.7;
      }

      .ev-detail-val {
        color: var(--text-secondary);
        font-size: 12px;
        font-weight: 500;
      }

      .ev-reasoning {
        color: var(--text-secondary);
        font-size: 12px;
        line-height: 1.6;
        background: rgba(255,255,255,0.02);
        border: 1px solid rgba(255,255,255,0.04);
        border-radius: 8px;
        padding: 12px 14px;
        white-space: pre-wrap;
        word-break: break-word;
      }

      .ev-full-hash {
        font-size: 10px;
        background: rgba(255,255,255,0.04);
        padding: 4px 10px;
        border-radius: 4px;
        color: var(--text-muted);
        font-family: var(--font);
        word-break: break-all;
      }

      .delta-pos { color: var(--green-400); }
      .delta-neg { color: #f87171; }
      .delta-zero { color: var(--text-muted); }

      /* ═══ Empty State ═══ */
      .empty-page {
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        min-height: 100vh;
        padding: 24px;
        text-align: center;
      }

      .empty-title {
        font-size: 42px;
        font-weight: 700;
        letter-spacing: 18px;
        text-indent: 18px;
        text-transform: uppercase;
        background: linear-gradient(135deg, #6ee7b7, #34d399 30%, #10b981 70%, #059669);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
        filter: drop-shadow(0 0 30px rgba(16,185,129,0.2));
        margin: 28px 0 6px;
      }

      .empty-sub {
        color: var(--text-muted);
        font-size: 11px;
        letter-spacing: 4px;
        text-transform: uppercase;
        margin: 0 0 32px;
      }

      .empty-msg {
        color: var(--text-secondary);
        font-size: 15px;
        font-weight: 300;
        letter-spacing: 5px;
        text-transform: uppercase;
        margin: 0 0 12px;
        animation: pulse-text 4s ease-in-out infinite;
      }

      @keyframes pulse-text {
        0%, 100% { opacity: 0.6; }
        50% { opacity: 1; }
      }

      .empty-hint {
        color: var(--text-muted);
        font-size: 12px;
        margin: 0 0 20px;
      }

      .cmd {
        display: inline-block;
        padding: 8px 20px;
        background: rgba(17, 19, 32, 0.6);
        backdrop-filter: blur(8px);
        -webkit-backdrop-filter: blur(8px);
        border: 1px solid var(--border);
        border-radius: 8px;
        font-size: 12px;
        color: var(--green-400);
        font-family: var(--font);
      }

      /* ═══ Ouroboros ═══ */
      .ouroboros-wrap {
        display: inline-block;
        animation: breathe 8s ease-in-out infinite;
      }

      @keyframes breathe {
        0%, 100% {
          transform: scale(1);
          filter: drop-shadow(0 0 20px rgba(16,185,129,0.1));
        }
        50% {
          transform: scale(1.02);
          filter: drop-shadow(0 0 32px rgba(16,185,129,0.2));
        }
      }

      .ouroboros { display: block; }

      .ring-glow { animation: gpulse 5s ease-in-out infinite; }

      @keyframes gpulse {
        0%, 100% { opacity: 0.06; }
        50% { opacity: 0.2; }
      }

      .scales-1 { animation: slither 26s linear infinite; }
      .scales-2 { animation: slither 20s linear infinite reverse; }

      @keyframes slither {
        from { stroke-dashoffset: 0; }
        to { stroke-dashoffset: -440; }
      }

      .eye-glow { animation: eshine 3s ease-in-out infinite; }

      @keyframes eshine {
        0%, 100% { opacity: 0.12; }
        50% { opacity: 0.55; }
      }

      .tongue { animation: flick 4.5s ease-in-out infinite; }

      @keyframes flick {
        0%, 78%, 100% { opacity: 0; }
        82%, 96% { opacity: 1; }
      }

      /* ═══ Evolve Trigger ═══ */
      .evolve-trigger-section {
        background: rgba(17, 19, 32, 0.55);
        backdrop-filter: blur(10px);
        -webkit-backdrop-filter: blur(10px);
        border: 1px solid var(--border);
        border-radius: 12px;
        padding: 24px;
        margin-bottom: 32px;
        position: relative;
        overflow: hidden;
      }

      .evolve-trigger-section::before {
        content: '';
        position: absolute;
        left: 0;
        top: 0;
        bottom: 0;
        width: 3px;
        background: linear-gradient(to bottom, var(--green-400), var(--green-600));
        border-radius: 0 2px 2px 0;
      }

      .evolve-title {
        font-size: 11px;
        color: var(--text-muted);
        text-transform: uppercase;
        letter-spacing: 3px;
        margin: 0 0 16px;
      }

      .evolve-form {
        display: flex;
        flex-direction: column;
        gap: 12px;
      }

      .evolve-input, .evolve-textarea {
        background: rgba(7, 8, 13, 0.6);
        border: 1px solid rgba(26, 30, 48, 0.8);
        border-radius: 8px;
        padding: 10px 14px;
        color: var(--text-primary);
        font-family: var(--font);
        font-size: 13px;
        transition: border-color 0.2s;
      }

      .evolve-input:focus, .evolve-textarea:focus {
        outline: none;
        border-color: rgba(16, 185, 129, 0.4);
      }

      .evolve-input::placeholder, .evolve-textarea::placeholder {
        color: var(--text-muted);
        opacity: 0.5;
      }

      .evolve-textarea {
        resize: vertical;
        min-height: 60px;
      }

      .evolve-row {
        display: flex;
        gap: 12px;
        align-items: flex-end;
      }

      .evolve-row .evolve-input {
        flex: 1;
      }

      .evolve-btn {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        padding: 10px 24px;
        border-radius: 8px;
        border: 1px solid rgba(16, 185, 129, 0.3);
        background: rgba(16, 185, 129, 0.1);
        color: var(--green-400);
        font-size: 12px;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 1.5px;
        cursor: pointer;
        transition: all 0.25s;
        font-family: var(--font);
        white-space: nowrap;
      }

      .evolve-btn:hover:not(:disabled) {
        background: rgba(16, 185, 129, 0.2);
        border-color: rgba(16, 185, 129, 0.5);
        box-shadow: 0 0 16px rgba(16, 185, 129, 0.1);
      }

      .evolve-btn:disabled {
        opacity: 0.4;
        cursor: not-allowed;
      }

      .evolve-msg {
        font-size: 12px;
        padding: 10px 14px;
        border-radius: 6px;
        margin-top: 12px;
      }

      .evolve-msg--error {
        background: rgba(239, 68, 68, 0.1);
        border: 1px solid rgba(239, 68, 68, 0.2);
        color: #f87171;
      }

      .evolve-msg--success {
        background: rgba(16, 185, 129, 0.1);
        border: 1px solid rgba(16, 185, 129, 0.2);
        color: var(--green-400);
      }

      .evolve-msg--info {
        background: rgba(245, 158, 11, 0.1);
        border: 1px solid rgba(245, 158, 11, 0.2);
        color: var(--amber-400);
      }

      .kill-switch-banner {
        background: rgba(239, 68, 68, 0.08);
        border: 1px solid rgba(239, 68, 68, 0.2);
        border-radius: 8px;
        padding: 10px 14px;
        font-size: 12px;
        color: #f87171;
        display: flex;
        align-items: center;
        gap: 8px;
        margin-bottom: 12px;
      }

      /* ═══ Responsive ═══ */
      @media (max-width: 640px) {
        .stats-row { grid-template-columns: repeat(2, 1fr); }
        .ev-grid { grid-template-columns: repeat(2, 1fr); }
        .ev-detail-grid { grid-template-columns: repeat(2, 1fr); }
        .krait-title, .empty-title {
          font-size: 28px;
          letter-spacing: 10px;
          text-indent: 10px;
        }
        .timeline { padding-left: 24px; }
      }
    </style>

    <div class="krait-dash">
      <!-- Background layers -->
      <div class="bg-grid"></div>
      <div class="bg-orb bg-orb--1"></div>
      <div class="bg-orb bg-orb--2"></div>
      <div class="scanline"></div>

      <%= if @events != [] do %>
        <!-- ═══ Hero ═══ -->
        <header class="krait-hero">
          <div class="ouroboros-wrap">
            <.ouroboros size={150} />
          </div>
          <h1 class="krait-title">Krait</h1>
          <p class="subtitle">Evolution Feed</p>
          <p class="tagline">immutable core, mutable periphery</p>
        </header>

        <main class="krait-main">
          <!-- ═══ Stats ═══ -->
          <div class="stats-row">
            <div class="stat">
              <div class="stat-val"><%= @stats.total %></div>
              <div class="stat-lbl">Events</div>
              <span class="stat-accent"></span>
            </div>
            <div class="stat">
              <div class="stat-val"><%= @stats.skills %></div>
              <div class="stat-lbl">Skills</div>
              <span class="stat-accent"></span>
            </div>
            <div class="stat">
              <div class="stat-val"><%= @stats.merged %></div>
              <div class="stat-lbl">Merged</div>
              <span class="stat-accent"></span>
            </div>
            <div class="stat">
              <div class={"stat-val#{if @stats.drafts > 0, do: " stat-val--amber", else: ""}"}>
                <%= @stats.drafts %>
              </div>
              <div class="stat-lbl">Drafts</div>
              <span class="stat-accent"></span>
            </div>
          </div>

          <!-- ═══ Trigger Evolution ═══ -->
          <div class="evolve-trigger-section">
            <h3 class="evolve-title">Trigger Evolution</h3>

            <%= if @kill_switch_active do %>
              <div class="kill-switch-banner">
                <span>&#9888;</span> Kill switch is active — evolution is halted system-wide
              </div>
            <% end %>

            <form phx-submit="trigger_evolution" class="evolve-form">
              <div class="evolve-row">
                <input
                  type="text"
                  name="skill_name"
                  placeholder="skill_name (e.g. greeting)"
                  class="evolve-input"
                  maxlength="64"
                  pattern="[a-z][a-z0-9_]*"
                  required
                  disabled={@evolving || @kill_switch_active}
                />
                <button type="submit" class="evolve-btn" disabled={@evolving || @kill_switch_active}>
                  <%= if @evolving do %>
                    Evolving...
                  <% else %>
                    Evolve
                  <% end %>
                </button>
              </div>
              <textarea
                name="description"
                placeholder="Describe what this skill should do..."
                class="evolve-textarea"
                maxlength="2000"
                rows="3"
                required
                disabled={@evolving || @kill_switch_active}
              ></textarea>
            </form>

            <%= if @evolution_error do %>
              <div class="evolve-msg evolve-msg--error"><%= @evolution_error %></div>
            <% end %>
            <%= if @evolution_success do %>
              <div class="evolve-msg evolve-msg--success"><%= @evolution_success %></div>
            <% end %>
            <%= if @evolving do %>
              <div class="evolve-msg evolve-msg--info">Evolution in progress — this may take a few minutes...</div>
            <% end %>
          </div>

          <!-- ═══ Feed ═══ -->
          <div class="feed-hdr">
            <span class="feed-dot"></span>
            Live Feed
          </div>

          <div class="timeline">
            <div class="tl-line"></div>
            <%= for event <- @events do %>
              <% eid = to_string(event.id) %>
              <% open? = MapSet.member?(@expanded, eid) %>
              <div class="ev-wrap">
                <div class={"tl-dot#{if event.draft, do: " tl-dot--amber", else: ""}"}></div>
                <div class={if event.draft, do: "ev ev--draft", else: "ev"}>
                  <div class="ev-top ev-clickable" phx-click="toggle_event" phx-value-id={eid}>
                    <span class="ev-name">
                      <span class="prompt">&gt;</span><%= event.skill_name || "unknown" %>
                    </span>
                    <span style="display:flex;align-items:center;gap:8px;">
                      <span class={
                        if event.draft, do: "badge badge--draft", else: "badge badge--ok"
                      }>
                        <span class="badge-dot"></span>
                        <%= if event.draft, do: "Draft", else: "Merged" %>
                      </span>
                      <span class={"ev-chevron#{if open?, do: " ev-chevron--open", else: ""}"}>
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                          <polyline points="6 9 12 15 18 9"></polyline>
                        </svg>
                      </span>
                    </span>
                  </div>

                  <p class="ev-desc"><%= event.description || "No description" %></p>

                  <div class="ev-grid">
                    <div>
                      <div class="ev-m-label">Complexity</div>
                      <div class="ev-m-val"><%= event.complexity || "\u2014" %></div>
                    </div>
                    <div>
                      <div class="ev-m-label">Findings</div>
                      <div class="ev-m-val"><%= event.security_findings || 0 %></div>
                    </div>
                    <div>
                      <div class="ev-m-label">Attempts</div>
                      <div class="ev-m-val"><%= event.attempts || 1 %></div>
                    </div>
                    <div>
                      <div class="ev-m-label">Hash</div>
                      <code class="ev-hash"><%= short_hash(event.ast_hash) %></code>
                    </div>
                  </div>

                  <!-- Expandable detail section -->
                  <div class={"ev-detail#{if open?, do: " ev-detail--open", else: ""}"}>
                    <div class="ev-detail-inner">
                      <div class="ev-detail-grid">
                        <div>
                          <div class="ev-detail-label">Taint Flows</div>
                          <div class="ev-detail-val"><%= event.taint_flows || 0 %></div>
                        </div>
                        <div>
                          <div class="ev-detail-label">Test Count</div>
                          <div class="ev-detail-val"><%= event.test_count || 0 %></div>
                        </div>
                        <div>
                          <div class="ev-detail-label">Complexity Delta</div>
                          <div class={"ev-detail-val #{delta_class(event.complexity_delta)}"}>
                            <%= format_delta(event.complexity_delta) %>
                          </div>
                        </div>
                      </div>

                      <%= if event.ast_hash do %>
                        <div class="ev-detail-section">
                          <div class="ev-detail-label">Full AST Hash</div>
                          <code class="ev-full-hash"><%= event.ast_hash %></code>
                        </div>
                      <% end %>

                      <%= if event.pr_number do %>
                        <div class="ev-detail-section">
                          <div class="ev-detail-label">PR Number</div>
                          <div class="ev-detail-val">#<%= event.pr_number %></div>
                        </div>
                      <% end %>

                      <%= if event.reasoning do %>
                        <div class="ev-detail-section">
                          <div class="ev-detail-label">Reasoning</div>
                          <div class="ev-reasoning"><%= event.reasoning %></div>
                        </div>
                      <% end %>
                    </div>
                  </div>

                  <%= if event.pr_url || Map.get(event, :inserted_at) || Map.get(event, :timestamp) do %>
                    <div class="ev-foot">
                      <span class="ev-time"><%= format_time(Map.get(event, :inserted_at) || Map.get(event, :timestamp)) %></span>
                      <%= if safe_pr_url(event.pr_url) do %>
                        <a href={safe_pr_url(event.pr_url)} target="_blank" rel="noopener" class="pr-link">
                          View PR <span class="pr-arrow">&rarr;</span>
                        </a>
                      <% end %>
                    </div>
                  <% end %>
                </div>
              </div>
            <% end %>
          </div>
        </main>
      <% else %>
        <!-- ═══ Empty State ═══ -->
        <div class="empty-page">
          <div class="ouroboros-wrap">
            <.ouroboros size={220} />
          </div>
          <h1 class="empty-title">Krait</h1>
          <p class="empty-sub">Evolution Feed</p>
          <p class="empty-msg">Awaiting Evolution</p>
          <p class="empty-hint">No evolution events recorded yet.</p>
          <code class="cmd">&gt; trigger the &quot;evolve&quot; skill to begin</code>
        </div>
      <% end %>
    </div>
    """
  end

  # ── Ouroboros SVG Component ──

  attr :size, :integer, default: 150

  defp ouroboros(assigns) do
    ~H"""
    <svg
      viewBox="0 0 200 200"
      width={@size}
      height={@size}
      class="ouroboros"
      xmlns="http://www.w3.org/2000/svg"
    >
      <defs>
        <linearGradient id="sg" gradientTransform="rotate(90)">
          <stop offset="0%" stop-color="#34d399" />
          <stop offset="35%" stop-color="#10b981" />
          <stop offset="70%" stop-color="#059669" />
          <stop offset="100%" stop-color="#047857" />
        </linearGradient>
        <filter id="glow-h" x="-50%" y="-50%" width="200%" height="200%">
          <feGaussianBlur stdDeviation="8" />
        </filter>
        <filter id="glow" x="-40%" y="-40%" width="180%" height="180%">
          <feGaussianBlur stdDeviation="3" result="b" />
          <feMerge>
            <feMergeNode in="b" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
        <filter id="eye-f" x="-100%" y="-100%" width="300%" height="300%">
          <feGaussianBlur stdDeviation="2" />
        </filter>
      </defs>

      <!-- Ambient glow ring -->
      <circle
        cx="100" cy="100" r="76"
        fill="none" stroke="#10b981" stroke-width="22"
        filter="url(#glow-h)" class="ring-glow"
      />

      <!-- Body shadow -->
      <circle
        cx="101" cy="101" r="70"
        fill="none" stroke="#020305" stroke-width="14" opacity="0.5"
      />

      <!-- Main body -->
      <circle
        cx="100" cy="100" r="70"
        fill="none" stroke="url(#sg)" stroke-width="13"
      />

      <!-- Scale layer 1 — primary -->
      <circle
        cx="100" cy="100" r="70"
        fill="none" stroke="#047857" stroke-width="13"
        stroke-dasharray="8 4.5" stroke-linecap="round" opacity="0.45"
        class="scales-1"
      />

      <!-- Scale layer 2 — highlights -->
      <circle
        cx="100" cy="100" r="70"
        fill="none" stroke="#34d399" stroke-width="13"
        stroke-dasharray="2 10.5" stroke-linecap="round" opacity="0.12"
        class="scales-2"
      />

      <!-- Dorsal ridge (outer) -->
      <circle
        cx="100" cy="100" r="76"
        fill="none" stroke="#10b981" stroke-width="0.7"
        stroke-dasharray="5 7" opacity="0.25" class="scales-1"
      />

      <!-- Belly line (inner) -->
      <circle
        cx="100" cy="100" r="63.5"
        fill="none" stroke="#34d399" stroke-width="0.5"
        opacity="0.12"
      />

      <!-- Ventral scales (inner detail) -->
      <circle
        cx="100" cy="100" r="64.5"
        fill="none" stroke="#047857" stroke-width="0.7"
        stroke-dasharray="5 7" opacity="0.18" class="scales-2"
      />

      <!-- ═══ Cobra Head ═══ -->
      <g transform="translate(100, 30)">
        <!-- Hood shadow -->
        <ellipse cx="0" cy="4" rx="20" ry="18" fill="#020305" opacity="0.6" />

        <!-- Hood -->
        <path
          d="M0,-19 C-11,-20 -25,-4 -19,11 C-16,17 -6,17 0,13 C6,17 16,17 19,11 C25,-4 11,-20 0,-19Z"
          fill="#059669" stroke="#047857" stroke-width="0.5"
        />

        <!-- Hood underside -->
        <path d="M-13,7 Q0,18 13,7" fill="#047857" opacity="0.4" />

        <!-- Hood scale arcs -->
        <path d="M-14,-6 Q0,-13 14,-6" fill="none" stroke="#047857" stroke-width="0.5" opacity="0.5" />
        <path d="M-16,0 Q0,-6 16,0" fill="none" stroke="#047857" stroke-width="0.5" opacity="0.4" />
        <path d="M-14,5 Q0,0 14,5" fill="none" stroke="#047857" stroke-width="0.5" opacity="0.3" />
        <path d="M-11,9 Q0,5 11,9" fill="none" stroke="#047857" stroke-width="0.5" opacity="0.2" />

        <!-- Hood rib lines (vertical structure) -->
        <path
          d="M-9,-16 C-10,-6 -10,4 -9,12"
          fill="none" stroke="#047857" stroke-width="0.3" opacity="0.25"
        />
        <path
          d="M9,-16 C10,-6 10,4 9,12"
          fill="none" stroke="#047857" stroke-width="0.3" opacity="0.25"
        />
        <path
          d="M-5,-18 C-5,-8 -4,3 -3,13"
          fill="none" stroke="#047857" stroke-width="0.3" opacity="0.15"
        />
        <path
          d="M5,-18 C5,-8 4,3 3,13"
          fill="none" stroke="#047857" stroke-width="0.3" opacity="0.15"
        />

        <!-- Spectacle marking (king cobra signature) -->
        <path
          d="M-7,-7 L-3,-11 L0,-9 L3,-11 L7,-7"
          fill="none" stroke="#fbbf24" stroke-width="1.5" stroke-linecap="round" opacity="0.4"
        />

        <!-- Eyes -->
        <ellipse cx="-6" cy="-3" rx="3.2" ry="3.5" fill="#fbbf24" />
        <ellipse cx="6" cy="-3" rx="3.2" ry="3.5" fill="#fbbf24" />
        <!-- Slit pupils -->
        <ellipse cx="-6" cy="-3" rx="1" ry="2.8" fill="#0f0f0f" />
        <ellipse cx="6" cy="-3" rx="1" ry="2.8" fill="#0f0f0f" />
        <!-- Eye highlights -->
        <circle cx="-7.2" cy="-4.2" r="0.9" fill="white" opacity="0.5" />
        <circle cx="4.8" cy="-4.2" r="0.9" fill="white" opacity="0.5" />
        <!-- Eye glow rings -->
        <circle
          cx="-6" cy="-3" r="5"
          fill="none" stroke="#fbbf24" stroke-width="0.7" class="eye-glow"
        />
        <circle
          cx="6" cy="-3" r="5"
          fill="none" stroke="#fbbf24" stroke-width="0.7" class="eye-glow"
        />
        <!-- Eye ambient glow -->
        <circle
          cx="-6" cy="-3" r="6"
          fill="#fbbf24" filter="url(#eye-f)" opacity="0.12" class="eye-glow"
        />
        <circle
          cx="6" cy="-3" r="6"
          fill="#fbbf24" filter="url(#eye-f)" opacity="0.12" class="eye-glow"
        />

        <!-- Nostrils -->
        <ellipse cx="-2.5" cy="3" rx="0.8" ry="0.6" fill="#047857" />
        <ellipse cx="2.5" cy="3" rx="0.8" ry="0.6" fill="#047857" />

        <!-- Snout ridge -->
        <path d="M0,-7 L0,5" fill="none" stroke="#047857" stroke-width="0.3" opacity="0.25" />

        <!-- Mouth -->
        <path
          d="M-9,9 Q-4,10 0,9 Q4,8 9,9"
          fill="none" stroke="#047857" stroke-width="0.8"
        />

        <!-- Lower jaw -->
        <path d="M-6,10 Q0,14 6,10" fill="#047857" opacity="0.4" />

        <!-- Tail entering mouth -->
        <path
          d="M6,9 C10,10 12,13 10,16 C9,18 7,16 6,14 C5,12 6,10 6,9 Z"
          fill="#059669" stroke="#047857" stroke-width="0.3" opacity="0.7"
        />
        <path
          d="M8,11 Q10,13 9,15"
          fill="none" stroke="#047857" stroke-width="0.4" opacity="0.4"
        />

        <!-- Fangs -->
        <line
          x1="-3" y1="10" x2="-2.5" y2="14"
          stroke="#e2e8f0" stroke-width="0.7" stroke-linecap="round" opacity="0.45"
        />
        <line
          x1="3" y1="10" x2="2.5" y2="14"
          stroke="#e2e8f0" stroke-width="0.7" stroke-linecap="round" opacity="0.45"
        />

        <!-- Forked tongue -->
        <g class="tongue">
          <line
            x1="0" y1="11" x2="0" y2="22"
            stroke="#ef4444" stroke-width="0.9" stroke-linecap="round"
          />
          <line
            x1="0" y1="22" x2="-4" y2="27"
            stroke="#ef4444" stroke-width="0.6" stroke-linecap="round"
          />
          <line
            x1="0" y1="22" x2="4" y2="27"
            stroke="#ef4444" stroke-width="0.6" stroke-linecap="round"
          />
        </g>
      </g>
    </svg>
    """
  end

  # ── Helpers ──

  defp fetch_events do
    Krait.Evolution.Feed.list(limit: 50)
  rescue
    e in [Ecto.QueryError, DBConnection.ConnectionError] ->
      Logger.warning("Feed query failed: #{Exception.message(e)}")
      []

    e in [RuntimeError, ArgumentError] ->
      Logger.warning("Unexpected error fetching events: #{Exception.message(e)}")
      []
  catch
    :exit, reason ->
      Logger.debug("Feed process exit: #{inspect(reason)}")
      []
  end

  defp compute_stats(events) do
    %{
      total: length(events),
      skills: events |> Enum.map(& &1.skill_name) |> Enum.uniq() |> length(),
      merged: Enum.count(events, fn e -> !e.draft end),
      drafts: Enum.count(events, fn e -> e.draft == true end)
    }
  end

  defp short_hash(nil), do: "\u2014"
  defp short_hash(hash), do: String.slice(to_string(hash), 0..7)

  # v14: L-7 — PR URL scheme validation (prevent javascript:/data: URI injection)
  defp safe_pr_url(nil), do: nil

  defp safe_pr_url(url) when is_binary(url) do
    if String.starts_with?(url, "https://github.com/"), do: url, else: nil
  end

  defp safe_pr_url(_), do: nil

  defp format_time(nil), do: ""

  defp format_time(%DateTime{} = dt) do
    Calendar.strftime(dt, "%Y-%m-%d %H:%M:%S")
  end

  defp format_time(_), do: ""

  defp format_delta(nil), do: "\u2014"
  defp format_delta(0), do: "0"
  defp format_delta(d) when d > 0, do: "+#{d}"
  defp format_delta(d), do: "#{d}"

  defp delta_class(nil), do: "delta-zero"
  defp delta_class(0), do: "delta-zero"
  defp delta_class(d) when d > 0, do: "delta-pos"
  defp delta_class(_), do: "delta-neg"

  # ── Evolution Trigger Helpers ──

  @max_description_length 2000

  @doc false
  def validate_trigger_params(skill_name, description) do
    cond do
      skill_name == "" ->
        {:error, "Skill name is required"}

      match?({:error, _}, Krait.Evolution.Naming.validate_skill_name(skill_name)) ->
        {:error,
         "Invalid skill name (lowercase letters, numbers, underscores; start with letter; max 64 chars)"}

      description == "" ->
        {:error, "Description is required"}

      String.length(description) > @max_description_length ->
        {:error, "Description too long (max #{@max_description_length} characters)"}

      String.contains?(description, <<0>>) ->
        {:error, "Description contains invalid characters"}

      true ->
        :ok
    end
  end

  defp start_evolution(skill_name, description) do
    max_slots = Application.get_env(:krait, :max_active_evolutions, 3)

    case Krait.EvolveCooldownServer.try_acquire_slot(:active_evolutions, max_slots) do
      :ok ->
        sanitized = Krait.Security.PromptSanitizer.sanitize(description)
        lv_pid = self()

        Logger.info("[Evolution] Starting evolution for skill: #{skill_name}")

        Task.Supervisor.start_child(Krait.TaskSupervisor, fn ->
          try do
            Logger.info("[Evolution] Task started for: #{skill_name}")
            result = run_evolution(skill_name, sanitized)

            Logger.info(
              "[Evolution] Task completed for: #{skill_name}, success: #{match?({:ok, _}, result)}"
            )

            send(lv_pid, {:evolution_complete, skill_name, result})
          rescue
            e in [RuntimeError, ArgumentError] ->
              Logger.error("[Evolution] Task crashed for: #{skill_name}: #{Exception.message(e)}")
              send(lv_pid, {:evolution_complete, skill_name, {:error, Exception.message(e)}})
          after
            Krait.EvolveCooldownServer.release_slot(:active_evolutions)
          end
        end)

        :ok

      {:error, :at_capacity} ->
        Logger.warning("[Evolution] At capacity — rejected: #{skill_name}")
        {:error, "Too many concurrent evolutions — please wait"}
    end
  rescue
    e in [RuntimeError, ArgumentError] ->
      Logger.error("[Evolution] start_evolution crashed: #{Exception.message(e)}")
      {:error, Exception.message(e)}
  end

  defp run_evolution(skill_name, description) do
    # Call the Evolve skill directly (not via Registry GenServer.call,
    # which would block the Registry for the entire evolution duration)
    Krait.Skills.Core.Evolve.execute(%{
      "skill_name" => skill_name,
      "description" => description
    })
  end

  defp kill_switch_halted? do
    Krait.KillSwitch.halted?()
  rescue
    ArgumentError -> false
  end
end
