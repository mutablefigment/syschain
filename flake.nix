{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };
  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem
      (system:
        with pkgs;
        {
          devShells.default = mkShell {
            buildInputs = [ 
                dub
                dmd
                openssl
                gdb
                gf 
            ];
          };
        }
      );
}