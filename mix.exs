defmodule Krait.MixProject do
  use Mix.Project

  def project do
    [
      app: :krait,
      version: "0.1.0",
      elixir: "~> 1.15",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      aliases: aliases(),
      deps: deps(),
      releases: releases(),
      dialyzer: [
        plt_local_path: "priv/plts",
        plt_core_path: "priv/plts",
        plt_add_apps: [:mix, :ex_unit]
      ],
      listeners: [Phoenix.CodeReloader]
    ]
  end

  # Configuration for the OTP application.
  #
  # Type `mix help compile.app` for more information.
  def application do
    [
      mod: {Krait.Application, []},
      extra_applications: [:logger, :runtime_tools]
    ]
  end

  def cli do
    [
      preferred_envs: [precommit: :test]
    ]
  end

  # Specifies which paths to compile per environment.
  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  # Specifies your project dependencies.
  #
  # Type `mix help deps` for examples and options.
  defp deps do
    [
      # Web
      {:phoenix, "~> 1.8"},
      {:phoenix_pubsub, "~> 2.1"},
      {:phoenix_live_view, "~> 1.0"},
      {:bandit, "~> 1.5"},
      {:jason, "~> 1.4"},
      {:gettext, "~> 1.0"},
      {:dns_cluster, "~> 0.2.0"},

      # Rust FFI
      {:rustler, "~> 0.37"},

      # LLM
      {:langchain, "~> 0.3"},
      {:req, "~> 0.5"},

      # Database / Memory
      {:ecto_sql, "~> 3.12"},
      {:postgrex, "~> 0.19"},
      {:pgvector, "~> 0.3"},

      # Infrastructure
      {:flame, "~> 0.5"},

      # Security
      {:joken, "~> 2.6"},
      {:cloak, "~> 1.1"},
      {:cloak_ecto, "~> 1.3"},

      # Observability
      {:telemetry, "~> 1.0"},
      {:telemetry_metrics, "~> 1.0"},
      {:telemetry_poller, "~> 1.0"},

      # v20 L-5: Dependency vulnerability scanning
      {:mix_audit, "~> 2.1", only: [:dev, :test], runtime: false},

      # Static Analysis
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false},

      # Structured Logging (prod only, referenced in runtime.exs)
      {:logger_json, "~> 6.0", only: :prod, runtime: false},

      # Testing
      {:mox, "~> 1.0", only: :test},
      {:bypass, "~> 2.1", only: :test},
      {:ex_machina, "~> 2.8", only: :test},
      {:stream_data, "~> 1.0", only: [:test, :dev]}
    ]
  end

  defp releases do
    [
      krait: [
        include_executables_for: [:unix],
        applications: [runtime_tools: :permanent]
      ]
    ]
  end

  # Aliases are shortcuts or tasks specific to the current project.
  # For example, to install project dependencies and perform other setup tasks, run:
  #
  #     $ mix setup
  #
  # See the documentation for `Mix` for more info on aliases.
  defp aliases do
    [
      setup: ["deps.get"],
      precommit: [
        "compile --warnings-as-errors",
        "deps.unlock --unused",
        "format",
        "credo --strict",
        "test"
      ]
    ]
  end
end
