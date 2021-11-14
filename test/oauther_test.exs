defmodule OAutherTest do
  use ExUnit.Case

  describe "credentials/1" do
    test "returns Credentials struct" do
      assert %OAuther.Credentials{
               consumer_key: "dpf43f3p2l4k3l03",
               consumer_secret: "kd94hf93k423kf44",
               method: :hmac_sha1,
               token: "nnch734d00sl2jdk",
               token_secret: "pfkkdhi9sl3r4s00",
               realm: "Photos"
             } ==
               OAuther.credentials(
                 consumer_key: "dpf43f3p2l4k3l03",
                 consumer_secret: "kd94hf93k423kf44",
                 token: "nnch734d00sl2jdk",
                 token_secret: "pfkkdhi9sl3r4s00",
                 realm: "Photos"
               )
    end

    test "by default realm is set to nil" do
      assert %OAuther.Credentials{
               consumer_key: "dpf43f3p2l4k3l03",
               consumer_secret: "kd94hf93k423kf44",
               method: :hmac_sha1,
               token: "nnch734d00sl2jdk",
               token_secret: "pfkkdhi9sl3r4s00",
               realm: nil
             } ==
               OAuther.credentials(
                 consumer_key: "dpf43f3p2l4k3l03",
                 consumer_secret: "kd94hf93k423kf44",
                 token: "nnch734d00sl2jdk",
                 token_secret: "pfkkdhi9sl3r4s00"
               )
    end
  end

  describe "sign/4" do
    test "returns list of params with oauth_signature" do
      creds =
        OAuther.credentials(
          consumer_secret: "kd94hf93k423kf44",
          token_secret: "pfkkdhi9sl3r4s00",
          consumer_key: "dpf43f3p2l4k3l03",
          token: "nnch734d00sl2jdk",
          realm: "Photos"
        )

      assert [
               {"oauth_signature", _},
               {"realm", "Photos"},
               {"oauth_token", "nnch734d00sl2jdk"},
               {"oauth_consumer_key", "dpf43f3p2l4k3l03"},
               {"oauth_nonce", _},
               {"oauth_signature_method", "HMAC-SHA1"},
               {"oauth_timestamp", _},
               {"oauth_version", "1.0"},
               {"custom_param", "123"}
             ] = OAuther.sign("get", "http://test.com", [{"custom_param", "123"}], creds)
    end
  end

  describe "header/1" do
    test "Authorization header" do
      {header, req_params} =
        OAuther.header([
          {"oauth_consumer_key", "dpf43f3p2l4k3l03"},
          {"oauth_signature_method", "PLAINTEXT"},
          {"oauth_signature", "kd94hf93k423kf44&"},
          {"realm", "Photos"},
          {"build", "Luna Park"}
        ])

      assert header ==
               {"Authorization",
                ~S(OAuth oauth_consumer_key="dpf43f3p2l4k3l03", oauth_signature_method="PLAINTEXT", oauth_signature="kd94hf93k423kf44%26", realm="Photos")}

      assert req_params == [{"build", "Luna Park"}]
    end
  end

  describe "protocol_params/2" do
    test "returns params list with protocol params" do
      creds =
        OAuther.credentials(
          consumer_secret: "kd94hf93k423kf44",
          token_secret: "pfkkdhi9sl3r4s00",
          consumer_key: "dpf43f3p2l4k3l03",
          token: "nnch734d00sl2jdk",
          realm: "Photos"
        )

      assert [
               {"realm", "Photos"},
               {"oauth_token", "nnch734d00sl2jdk"},
               {"oauth_consumer_key", "dpf43f3p2l4k3l03"},
               {"oauth_nonce", _},
               {"oauth_signature_method", "HMAC-SHA1"},
               {"oauth_timestamp", _},
               {"oauth_version", "1.0"},
               {"custom_param", "123"}
             ] = OAuther.protocol_params([{"custom_param", "123"}], creds)
    end

    test "when realm is not present it's not included in the list of protocol params" do
      creds =
        OAuther.credentials(
          consumer_secret: "kd94hf93k423kf44",
          token_secret: "pfkkdhi9sl3r4s00",
          consumer_key: "dpf43f3p2l4k3l03",
          token: "nnch734d00sl2jdk",
          realm: nil
        )

      assert [
               {"oauth_token", "nnch734d00sl2jdk"},
               {"oauth_consumer_key", "dpf43f3p2l4k3l03"},
               {"oauth_nonce", _},
               {"oauth_signature_method", "HMAC-SHA1"},
               {"oauth_timestamp", _},
               {"oauth_version", "1.0"},
               {"custom_param", "123"}
             ] = OAuther.protocol_params([{"custom_param", "123"}], creds)
    end
  end

  describe "signature/4" do
    test "HMAC-SHA1 signature" do
      creds =
        OAuther.credentials(
          consumer_secret: "kd94hf93k423kf44",
          token_secret: "pfkkdhi9sl3r4s00",
          consumer_key: "dpf43f3p2l4k3l03",
          token: "nnch734d00sl2jdk"
        )

      params = protocol_params(creds)
      assert signature(params, creds, "/photos") == "tR3+Ty81lMeYAr/Fid0kMTYa/WM="
    end

    test "HMAC-SHA256 signature" do
      creds =
        OAuther.credentials(
          method: :hmac_sha256,
          consumer_secret: "kd94hf93k423kf44",
          token_secret: "pfkkdhi9sl3r4s00",
          consumer_key: "dpf43f3p2l4k3l03",
          token: "nnch734d00sl2jdk"
        )

      params = protocol_params(creds)
      assert signature(params, creds, "/photos") == "WVPzl1j6ZsnkIjWr7e3OZ3jkenL57KwaLFhYsroX1hg="
    end

    test "RSA-SHA1 signature" do
      creds =
        OAuther.credentials(
          method: :rsa_sha1,
          consumer_secret: fixture_path("private_key.pem"),
          consumer_key: "dpf43f3p2l4k3l03"
        )

      params = protocol_params(creds)

      assert signature(params, creds, "/photos") ==
               "cyZ9hTJnRfkOnF5+OzxXWKKG+hRY+/esxdQAluJem1RlHkZQRsFEevOS5x+A1ZoS+aYlTU3xdHkEKIb/+xuqaavAUFVaIF/5448XsXqSTJomvpoC1c7yw5ArNZnPRLYwK3XYHaIr5FHXbiCG/ze093i2MpsusQU6Shn8lGJNMWE="

      private_key = File.read!(fixture_path("private_key.pem"))

      creds =
        OAuther.credentials(
          method: :rsa_sha1,
          consumer_secret: private_key,
          consumer_key: "dpf43f3p2l4k3l03"
        )

      params = protocol_params(creds)

      assert signature(params, creds, "/photos") ==
               "cyZ9hTJnRfkOnF5+OzxXWKKG+hRY+/esxdQAluJem1RlHkZQRsFEevOS5x+A1ZoS+aYlTU3xdHkEKIb/+xuqaavAUFVaIF/5448XsXqSTJomvpoC1c7yw5ArNZnPRLYwK3XYHaIr5FHXbiCG/ze093i2MpsusQU6Shn8lGJNMWE="
    end

    test "PLAINTEXT signature" do
      creds =
        OAuther.credentials(
          method: :plaintext,
          consumer_secret: "kd94hf93k423kf44",
          consumer_key: "dpf43f3p2l4k3l03"
        )

      assert signature([], creds, "/photos") == "kd94hf93k423kf44&"
    end

    test "signature with query params" do
      creds =
        OAuther.credentials(
          consumer_secret: "kd94hf93k423kf44",
          token_secret: "pfkkdhi9sl3r4s00",
          consumer_key: "dpf43f3p2l4k3l03",
          token: "nnch734d00sl2jdk"
        )

      params = protocol_params(creds)
      assert signature(params, creds, "/photos?size=large") == "dzTFIxhRqhwfFqoXYgo4+hoPr2M="
    end

    test "signature with realm" do
      creds =
        OAuther.credentials(
          consumer_secret: "kd94hf93k423kf44",
          token_secret: "pfkkdhi9sl3r4s00",
          consumer_key: "dpf43f3p2l4k3l03",
          token: "nnch734d00sl2jdk",
          realm: "Photos"
        )

      params = protocol_params(creds)
      assert signature(params, creds, "/photos") == "9QG3oRtIpkf/+slqLB7SDlccBZU="
    end
  end

  defp fixture_path(file_path) do
    Path.expand("fixtures", __DIR__)
    |> Path.join(file_path)
  end

  defp protocol_params(creds) do
    OAuther.protocol_params([file: "vacation.jpg", size: "original"], creds)
    |> rewrite()
  end

  defp rewrite(params) do
    for param <- params do
      case param do
        {"oauth_nonce", _} ->
          put_elem(param, 1, "kllo9940pd9333jh")

        {"oauth_timestamp", _} ->
          put_elem(param, 1, 1_191_242_096)

        _otherwise ->
          param
      end
    end
  end

  defp signature(params, creds, path) do
    url = "http://photos.example.net" <> path
    OAuther.signature("get", url, params, creds)
  end
end
