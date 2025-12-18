{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/d7f52a7a640bc54c7bb414cca603835bf8dd4b10";
    utils.url = "github:numtide/flake-utils";
  };
  outputs = { nixpkgs, utils, ... }: utils.lib.eachDefaultSystem (system:
    let
      pkgs = nixpkgs.legacyPackages.${system};
    in
    {
      devShells.default = pkgs.mkShell {
        buildInputs = with pkgs; [
          cargo-deny
          protobuf
        ];

        shellHook = ''
          chmod +x .githooks/* && git config --local core.hooksPath .githooks/
        '';

        LD_LIBRARY_PATH = "${pkgs.openssl}/lib";
        PKG_CONFIG_PATH = "${pkgs.openssl.dev}/lib/pkgconfig";
      };

    }
  );
}
