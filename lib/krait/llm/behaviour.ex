defmodule Krait.LLM.Behaviour do
  @moduledoc "Contract for LLM client implementations"

  @callback complete(messages :: [map()], opts :: keyword()) ::
              {:ok, String.t()} | {:error, term()}

  @callback complete_with_tools(messages :: [map()], tools :: [map()], opts :: keyword()) ::
              {:ok, map()} | {:error, term()}

  @callback stream(messages :: [map()], opts :: keyword()) ::
              {:ok, Enumerable.t()} | {:error, term()}
end
