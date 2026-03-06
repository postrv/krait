defmodule Krait.Skills.Registry do
  @moduledoc "Dynamic skill registry managing skill modules"

  use GenServer

  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts)
  end

  @spec list_manifests(GenServer.server()) :: [map()]
  def list_manifests(pid) do
    GenServer.call(pid, :list_manifests)
  end

  @spec get_skill(GenServer.server(), String.t()) :: {:ok, module()} | {:error, :not_found}
  def get_skill(pid, name) do
    GenServer.call(pid, {:get_skill, name})
  end

  @spec execute_skill(GenServer.server(), String.t(), map()) :: {:ok, term()} | {:error, term()}
  def execute_skill(pid, name, params) do
    GenServer.call(pid, {:execute_skill, name, params}, 30_000)
  end

  @impl true
  def init(opts) do
    skills = Keyword.get(opts, :skills, [])
    registry = Map.new(skills, fn mod -> {mod.name(), mod} end)
    {:ok, %{registry: registry}}
  end

  @impl true
  def handle_call(:list_manifests, _from, state) do
    manifests =
      state.registry
      |> Enum.map(fn {_name, mod} ->
        %{
          name: mod.name(),
          description: mod.description()
        }
      end)

    {:reply, manifests, state}
  end

  def handle_call({:get_skill, name}, _from, state) do
    case Map.get(state.registry, name) do
      nil -> {:reply, {:error, :not_found}, state}
      mod -> {:reply, {:ok, mod}, state}
    end
  end

  def handle_call({:execute_skill, name, params}, _from, state) do
    case Map.get(state.registry, name) do
      nil ->
        {:reply, {:error, :not_found}, state}

      mod ->
        result =
          if function_exported?(mod, :required_capabilities, 0) do
            Krait.Skills.CapabilityInjector.execute_with_capabilities(mod, params)
          else
            mod.execute(params)
          end

        {:reply, result, state}
    end
  end
end
