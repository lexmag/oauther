defmodule OAuther do
  defmodule Credentials do
    defstruct [
      :consumer_key, :consumer_secret,
      :token, :token_secret, method: :hmac_sha1
    ]
  end

  def credentials(args) do
    Enum.reduce(args, %Credentials{}, fn({key, val}, acc) ->
      :maps.update(key, val, acc)
    end)
  end

  def sign(verb, url, params, %Credentials{} = creds) do
    params = protocol_params(params, creds)
    signature = signature(verb, url, params, creds)

    [{"oauth_signature", signature} | params]
  end

  def header(params) do
    {oauth_params, req_params} = Enum.partition(params, &protocol_param?/1)

    {{"Authorization", "OAuth " <> compose_header(oauth_params)}, req_params}
  end

  def protocol_params(params, %Credentials{} = creds) do
    [{"oauth_consumer_key",     creds.consumer_key},
     {"oauth_nonce",            nonce()},
     {"oauth_signature_method", sign_method(creds.method)},
     {"oauth_timestamp",        timestamp()},
     {"oauth_version",          "1.0"}
     | cons_token(params, creds.token)]
  end

  def signature(_, _, _, %{method: :plaintext} = creds) do
    compose_key(creds)
  end

  def signature(verb, url, params, %{method: :hmac_sha1} = creds) do
    :crypto.hmac(:sha, compose_key(creds), base_string(verb, url, params))
    |> Base.encode64
  end

  def signature(verb, url, params, %{method: :rsa_sha1} = creds) do
    base_string(verb, url, params)
    |> :public_key.sign(:sha, read_private_key(creds.consumer_secret))
    |> Base.encode64
  end

  defp protocol_param?({key, _v}) do
    String.starts_with?(key, "oauth_")
  end

  defp compose_header([_ | _] = params) do
    Stream.map(params, &percent_encode/1)
    |> Enum.map_join(", ", &compose_header/1)
  end

  defp compose_header({key, value}) do
    key <> "=\"" <> value <> "\""
  end

  defp compose_key(creds) do
    [creds.consumer_secret, creds.token_secret]
    |> Enum.map_join("&", &percent_encode/1)
  end

  defp read_private_key(path) do
    File.read!(path)
    |> :public_key.pem_decode
    |> hd() |> :public_key.pem_entry_decode
  end

  defp base_string(verb, url, params) do
    {uri, query_params} = parse_url(url)
    [verb, uri, params ++ query_params]
    |> Stream.map(&normalize/1)
    |> Enum.map_join("&", &percent_encode/1)
  end

  defp normalize(verb) when is_binary(verb),
    do: String.upcase(verb)

  defp normalize(%URI{host: host} = uri),
    do: %{uri | host: String.downcase(host)}

  defp normalize([_ | _] = params) do
    Enum.map(params, &percent_encode/1)
    |> Enum.sort
    |> Enum.map_join("&", &normalize_pair/1)
  end

  defp normalize_pair({key, value}) do
    key <> "=" <> value
  end

  defp parse_url(url) do
    uri = URI.parse(url)
    {%{uri | query: nil}, parse_query_params(uri.query)}
  end

  def parse_query_params(nil), do: []

  def parse_query_params(params) do
    URI.query_decoder(params)
    |> Enum.into([])
  end

  defp nonce() do
    :crypto.strong_rand_bytes(24)
    |> Base.encode64
  end

  defp timestamp() do
    {mgsec, sec, _mcs} = :os.timestamp

    mgsec * 1_000_000 + sec
  end

  defp cons_token(params, nil), do: params
  defp cons_token(params, value),
    do: [{"oauth_token", value} | params]

  defp sign_method(:plaintext), do: "PLAINTEXT"
  defp sign_method(:hmac_sha1), do: "HMAC-SHA1"
  defp sign_method(:rsa_sha1),  do: "RSA-SHA1"

  defp percent_encode({key, value}) do
    {percent_encode(key), percent_encode(value)}
  end

  defp percent_encode(term) do
    to_string(term)
    |> URI.encode(&URI.char_unreserved?/1)
  end
end
