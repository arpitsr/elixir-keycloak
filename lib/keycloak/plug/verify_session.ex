defmodule Keycloak.Plug.VerifySession do

  use Joken.Config

  import Plug.Conn

  alias JOSE.JWK

  @regex ~r/^Bearer:?\s+(.+)/i

  @doc false
  def init(opts), do: opts

  @spec call(Plug.Conn.t(), keyword()) :: Plug.Conn.t()
  def call(conn, _) do
    token =
      conn
      |> fetch_session
      |> get_session(:token)
    case verify_token(token.access_token) do
      {:ok, claims} ->
        conn
        |> assign(:claims, claims)

      {:error, message} ->
        conn
        |> put_resp_content_type("application/vnd.api+json")
        |> send_resp(401, Poison.encode!(%{error: message}))
        |> halt()
    end
  end

  def token_config(), do: default_claims(default_exp: 60 * 60)

  def verify_token(nil), do: {:error, :not_authenticated}

  def verify_token(token) do
    token
    |> Joken.Signer.verify(Joken.Signer.parse_config(:public_key))
  end

end
