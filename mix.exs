defmodule OAuther.Mixfile do
  use Mix.Project

  def project do
    [app: :oauther,
     version: "1.0.2",
     elixir: ">= 0.14.1",
     description: description,
     deps: deps,
     package: package]
  end

  def application do
    [applications: []]
  end

  defp description,
    do: "Library to authenticate with OAuth 1.0 protocol."

  defp deps do
    [{:dialyxir, "~> 0.3", only: [:dev]}]
  end

  defp package do
    [files: ["lib", "mix.exs", "README.md", "LICENSE"],
     contributors: ["Aleksei Magusev"],
     licenses: ["ISC"],
     links: %{"GitHub" => "https://github.com/lexmag/oauther"}]
  end
end
