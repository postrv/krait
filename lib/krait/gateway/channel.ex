defmodule Krait.Gateway.Channel do
  @moduledoc "Contract for messaging channel implementations"

  @callback start_link(opts :: keyword()) :: GenServer.on_start()
  @callback send_message(pid :: pid(), recipient :: String.t(), message :: String.t()) ::
              :ok | {:error, term()}
  @callback channel_type() :: atom()
end
